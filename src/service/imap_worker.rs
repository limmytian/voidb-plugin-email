//! IMAP protocol handler for the EmailService worker thread.
//!
//! Absorbed from `imap_client.rs` per D-05. All IMAP protocol logic lives here.
//! The worker thread in `mod.rs` delegates IMAP commands to `ImapClient` methods.

use anyhow::{Result, anyhow};
use imap::Session;
use native_tls::TlsStream;
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;

use crate::config::SecurityType;
use crate::mime_utils::{extract_attachments, extract_body_parts};
use crate::policy::EmailMessageIdentity;
use crate::types::{EmailBody, EmailEnvelope, EmailFlagAction, EmailFolder, EmailMailboxSnapshot};

/// A stream wrapper that prepends a fake IMAP greeting before delegating
/// to the real stream. This allows `imap::Client::read_greeting()` to succeed
/// on a stream where the real greeting was already consumed during raw ID handshake.
struct GreetingPrefixStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S: Read> Read for GreetingPrefixStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First drain the prefix, then read from inner
        let prefix_remaining = self.prefix.get_ref().len() as u64 - self.prefix.position();
        if prefix_remaining > 0 {
            return self.prefix.read(buf);
        }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for GreetingPrefixStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: imap::extensions::idle::SetReadTimeout> imap::extensions::idle::SetReadTimeout
    for GreetingPrefixStream<S>
{
    fn set_read_timeout(
        &mut self,
        timeout: Option<std::time::Duration>,
    ) -> imap::error::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
}

/// Perform raw IMAP handshake on a stream: read greeting, send ID command,
/// read ID response. This must happen before imap::Client gets the stream,
/// because imap-proto cannot parse `* ID (...)` responses (Netease/126/163
/// mail servers require ID before LOGIN).
fn raw_imap_id_handshake<S: Read + Write>(stream: &mut S) -> Result<()> {
    let mut buf = [0u8; 1];
    let mut line = Vec::new();

    // 1. Read server greeting ("* OK ...")
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(anyhow!("Connection closed during greeting"));
        }
        line.push(buf[0]);
        if buf[0] == b'\n' {
            break;
        }
    }
    let greeting = String::from_utf8_lossy(&line);
    if !greeting.starts_with("* ") {
        return Err(anyhow!("Unexpected IMAP greeting: {}", greeting.trim()));
    }

    // 2. Send ID command with tag "X0" (won't collide with imap crate's "a" prefix)
    let cmd = b"X0 ID (\"name\" \"voidb\" \"version\" \"1.0\")\r\n";
    stream.write_all(cmd)?;
    stream.flush()?;

    // 3. Read responses until we see tagged response "X0 "
    loop {
        line.clear();
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(anyhow!("Connection closed during ID response"));
            }
            line.push(buf[0]);
            if buf[0] == b'\n' {
                break;
            }
        }
        let resp = String::from_utf8_lossy(&line);
        if resp.starts_with("X0 ") {
            break;
        }
    }
    Ok(())
}

enum ImapSession {
    Tls(Session<GreetingPrefixStream<TlsStream<TcpStream>>>),
    StarttlsTls(Session<GreetingPrefixStream<TlsStream<TcpStream>>>),
    Plain(Session<GreetingPrefixStream<TcpStream>>),
}

pub struct ImapClient {
    session: ImapSession,
}

/// Send raw STARTTLS command and read tagged response.
/// Must be called after greeting + ID handshake on a plain TCP stream.
fn raw_starttls<S: Read + Write>(stream: &mut S) -> Result<()> {
    let cmd = b"X1 STARTTLS\r\n";
    stream.write_all(cmd)?;
    stream.flush()?;
    let mut buf = [0u8; 1];
    let mut line = Vec::new();
    loop {
        line.clear();
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(anyhow!("Connection closed during STARTTLS"));
            }
            line.push(buf[0]);
            if buf[0] == b'\n' {
                break;
            }
        }
        let resp = String::from_utf8_lossy(&line);
        if resp.starts_with("X1 ") {
            if !resp.contains("OK") {
                return Err(anyhow!("STARTTLS failed: {}", resp.trim()));
            }
            break;
        }
    }
    Ok(())
}

fn wrap_with_greeting<S>(stream: S) -> GreetingPrefixStream<S> {
    GreetingPrefixStream {
        prefix: Cursor::new(b"* OK ready\r\n".to_vec()),
        inner: stream,
    }
}

fn tls_connector(verify_tls: bool) -> Result<native_tls::TlsConnector> {
    let mut builder = native_tls::TlsConnector::builder();
    if !verify_tls {
        builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

impl ImapClient {
    pub fn connect_with_security(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        security: SecurityType,
    ) -> Result<Self> {
        Self::connect_with_security_and_tls_verification(host, port, user, password, security, true)
    }

    pub fn connect_with_security_and_tls_verification(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        security: SecurityType,
        verify_tls: bool,
    ) -> Result<Self> {
        match security {
            SecurityType::SslTls => {
                let tls_connector = tls_connector(verify_tls)?;
                let tcp = TcpStream::connect((host, port))?;
                let mut tls_stream = tls_connector.connect(host, tcp)?;

                // Raw handshake: greeting + ID (before imap crate, to avoid parser issues)
                raw_imap_id_handshake(&mut tls_stream)?;

                let mut client = imap::Client::new(wrap_with_greeting(tls_stream));
                client.read_greeting()?;
                let session = client
                    .login(user, password)
                    .map_err(|e| anyhow!("IMAP login failed: {}", e.0))?;
                Ok(Self {
                    session: ImapSession::Tls(session),
                })
            }
            SecurityType::STARTTLS => {
                let mut tcp = TcpStream::connect((host, port))?;

                // Raw handshake: greeting + ID on plain TCP
                raw_imap_id_handshake(&mut tcp)?;

                // Raw STARTTLS upgrade
                raw_starttls(&mut tcp)?;

                let tls_connector = tls_connector(verify_tls)?;
                let tls_stream = tls_connector.connect(host, tcp)?;

                // After TLS upgrade, server doesn't re-send greeting.
                // Wrap with fake greeting for imap::Client.
                let mut client = imap::Client::new(wrap_with_greeting(tls_stream));
                client.read_greeting()?;
                let session = client
                    .login(user, password)
                    .map_err(|e| anyhow!("IMAP login failed: {}", e.0))?;
                Ok(Self {
                    session: ImapSession::StarttlsTls(session),
                })
            }
            SecurityType::None => {
                let mut tcp = TcpStream::connect((host, port))?;

                // Raw handshake: greeting + ID on plain TCP
                raw_imap_id_handshake(&mut tcp)?;

                let mut client = imap::Client::new(wrap_with_greeting(tcp));
                client.read_greeting()?;
                let session = client
                    .login(user, password)
                    .map_err(|e| anyhow!("IMAP login failed: {}", e.0))?;
                Ok(Self {
                    session: ImapSession::Plain(session),
                })
            }
        }
    }

    pub fn list_folders(&mut self) -> Result<Vec<EmailFolder>> {
        macro_rules! impl_list_folders {
            ($session:expr) => {{
                let mailboxes = $session.list(Some(""), Some("*"))?;
                let mut folders = Vec::new();
                for mb in mailboxes.iter() {
                    let name = mb.name().to_string();
                    let delim = mb.delimiter().unwrap_or("/").to_string();

                    let (msg_count, unseen) = match $session.examine(&name) {
                        Ok(mailbox) => {
                            let total = mailbox.exists;
                            // SEARCH UNSEEN to get actual unread count
                            let unseen_count = $session
                                .uid_search("UNSEEN")
                                .map(|set| set.len() as u32)
                                .unwrap_or(0);
                            (total, unseen_count)
                        }
                        Err(_) => (0, 0),
                    };

                    let display_name = decode_imap_utf7(&name);
                    folders.push(EmailFolder {
                        name,
                        display_name,
                        delimiter: delim,
                        message_count: msg_count,
                        unread_count: unseen,
                    });
                }
                Ok(folders)
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_list_folders!(s),
            ImapSession::StarttlsTls(s) => impl_list_folders!(s),
            ImapSession::Plain(s) => impl_list_folders!(s),
        }
    }

    /// List messages with pagination. `page` is 0-based (0 = newest).
    /// Returns (envelopes, total_count) so caller knows if more pages exist.
    pub fn list_messages(
        &mut self,
        folder: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<EmailEnvelope>, u32)> {
        macro_rules! impl_list_messages {
            ($session:expr) => {{
                let mailbox = $session.select(folder)?;
                let total = mailbox.exists;
                let uid_validity = mailbox.uid_validity;
                if total == 0 {
                    return Ok((Vec::new(), 0));
                }

                let skip = page * page_size;
                if skip >= total {
                    return Ok((Vec::new(), total));
                }

                let end = total.saturating_sub(skip);
                let start = end.saturating_sub(page_size - 1).max(1);
                let range = format!("{}:{}", start, end);

                let messages = $session.fetch(&range, "(UID FLAGS ENVELOPE RFC822.SIZE)")?;
                let mut envelopes = Vec::new();

                for msg in messages.iter() {
                    let seq = msg.message;
                    let uid = msg.uid.unwrap_or(seq);
                    let size = msg.size.unwrap_or(0);
                    let seen = msg
                        .flags()
                        .iter()
                        .any(|f| matches!(f, imap::types::Flag::Seen));

                    let (from, subject, date) = if let Some(env) = msg.envelope() {
                        let from = env
                            .from
                            .as_ref()
                            .and_then(|addrs| addrs.first())
                            .map(|a| {
                                let name = a.name.as_ref().map(|n| decode_mime_words(n));
                                let mailbox_name = a
                                    .mailbox
                                    .as_ref()
                                    .map(|m| String::from_utf8_lossy(m).to_string())
                                    .unwrap_or_default();
                                let host = a
                                    .host
                                    .as_ref()
                                    .map(|h| String::from_utf8_lossy(h).to_string())
                                    .unwrap_or_default();
                                let email = format!("{}@{}", mailbox_name, host);
                                name.map(|n| format!("{} <{}>", n, email)).unwrap_or(email)
                            })
                            .unwrap_or_else(|| "(unknown)".into());

                        let subject = env
                            .subject
                            .as_ref()
                            .map(|s| decode_mime_words(s))
                            .unwrap_or_else(|| "(no subject)".into());

                        let date = env
                            .date
                            .as_ref()
                            .map(|d| String::from_utf8_lossy(d).to_string())
                            .unwrap_or_default();

                        (from, subject, date)
                    } else {
                        ("(unknown)".into(), "(no subject)".into(), String::new())
                    };

                    envelopes.push(EmailEnvelope {
                        uid,
                        uid_validity,
                        modseq: msg.mod_seq(),
                        from,
                        subject,
                        date,
                        seen,
                        size,
                    });
                }

                envelopes.reverse();
                Ok((envelopes, total))
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_list_messages!(s),
            ImapSession::StarttlsTls(s) => impl_list_messages!(s),
            ImapSession::Plain(s) => impl_list_messages!(s),
        }
    }

    /// List only unseen messages with pagination.
    /// Returns (envelopes, total_unseen_count).
    pub fn list_unseen_messages(
        &mut self,
        folder: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<EmailEnvelope>, u32)> {
        macro_rules! impl_list_unseen {
            ($session:expr) => {{
                let mailbox = $session.select(folder)?;
                let uid_validity = mailbox.uid_validity;

                let mut unseen_seqs: Vec<u32> = $session
                    .search("UNSEEN")
                    .map(|set| set.into_iter().collect())
                    .unwrap_or_default();

                let total_unseen = unseen_seqs.len() as u32;
                if total_unseen == 0 {
                    return Ok((Vec::new(), 0));
                }

                unseen_seqs.sort_unstable_by(|a, b| b.cmp(a));

                let skip = (page * page_size) as usize;
                let page_seqs: Vec<u32> = unseen_seqs
                    .into_iter()
                    .skip(skip)
                    .take(page_size as usize)
                    .collect();

                if page_seqs.is_empty() {
                    return Ok((Vec::new(), total_unseen));
                }

                let seq_set: String = page_seqs
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(",");

                let messages = $session.fetch(&seq_set, "(UID ENVELOPE RFC822.SIZE)")?;
                let mut envelopes = Vec::new();

                for msg in messages.iter() {
                    let seq = msg.message;
                    let uid = msg.uid.unwrap_or(seq);
                    let size = msg.size.unwrap_or(0);

                    let (from, subject, date) = if let Some(env) = msg.envelope() {
                        let from = env
                            .from
                            .as_ref()
                            .and_then(|addrs| addrs.first())
                            .map(|a| {
                                let name = a.name.as_ref().map(|n| decode_mime_words(n));
                                let mailbox_name = a
                                    .mailbox
                                    .as_ref()
                                    .map(|m| String::from_utf8_lossy(m).to_string())
                                    .unwrap_or_default();
                                let host = a
                                    .host
                                    .as_ref()
                                    .map(|h| String::from_utf8_lossy(h).to_string())
                                    .unwrap_or_default();
                                let email = format!("{}@{}", mailbox_name, host);
                                name.map(|n| format!("{} <{}>", n, email)).unwrap_or(email)
                            })
                            .unwrap_or_else(|| "(unknown)".into());

                        let subject = env
                            .subject
                            .as_ref()
                            .map(|s| decode_mime_words(s))
                            .unwrap_or_else(|| "(no subject)".into());

                        let date = env
                            .date
                            .as_ref()
                            .map(|d| String::from_utf8_lossy(d).to_string())
                            .unwrap_or_default();

                        (from, subject, date)
                    } else {
                        ("(unknown)".into(), "(no subject)".into(), String::new())
                    };

                    envelopes.push(EmailEnvelope {
                        uid,
                        uid_validity,
                        modseq: msg.mod_seq(),
                        from,
                        subject,
                        date,
                        seen: false,
                        size,
                    });
                }

                envelopes.sort_by(|a, b| b.uid.cmp(&a.uid));
                Ok((envelopes, total_unseen))
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_list_unseen!(s),
            ImapSession::StarttlsTls(s) => impl_list_unseen!(s),
            ImapSession::Plain(s) => impl_list_unseen!(s),
        }
    }

    pub fn fetch_body(&mut self, folder: &str, seq: u32) -> Result<EmailBody> {
        self.fetch_body_with_seen_flag(folder, seq, true)
    }

    pub fn fetch_body_read_only(&mut self, folder: &str, seq: u32) -> Result<EmailBody> {
        self.fetch_body_with_seen_flag(folder, seq, false)
    }

    fn fetch_body_with_seen_flag(
        &mut self,
        folder: &str,
        seq: u32,
        mark_seen: bool,
    ) -> Result<EmailBody> {
        macro_rules! impl_fetch_body {
            ($session:expr) => {{
                $session.select(folder)?;
                // Use BODY.PEEK[] instead of RFC822 to avoid implicit \Seen flag
                // change, which causes some servers to send unsolicited FETCH
                // responses that confuse the imap crate's tag parser.
                let messages = $session.fetch(seq.to_string(), "BODY.PEEK[]")?;
                let msg = messages
                    .iter()
                    .next()
                    .ok_or_else(|| anyhow!("Message not found"))?;

                let body_bytes = msg.body().ok_or_else(|| anyhow!("No body"))?;

                let parsed = mailparse::parse_mail(body_bytes)?;

                if mark_seen {
                    let _ = $session.store(seq.to_string(), "+FLAGS.SILENT (\\Seen)");
                }

                let from = parsed
                    .headers
                    .iter()
                    .find(|h| h.get_key_ref() == "From")
                    .map(|h| h.get_value())
                    .unwrap_or_else(|| "(unknown)".into());
                let to: Vec<String> = parsed
                    .headers
                    .iter()
                    .find(|h| h.get_key_ref() == "To")
                    .map(|h| {
                        h.get_value()
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let cc: Vec<String> = parsed
                    .headers
                    .iter()
                    .find(|h| h.get_key_ref() == "Cc")
                    .map(|h| {
                        h.get_value()
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let subject = parsed
                    .headers
                    .iter()
                    .find(|h| h.get_key_ref() == "Subject")
                    .map(|h| h.get_value())
                    .unwrap_or_else(|| "(no subject)".into());
                let date = parsed
                    .headers
                    .iter()
                    .find(|h| h.get_key_ref() == "Date")
                    .map(|h| h.get_value())
                    .unwrap_or_default();

                let (text, html) = extract_body_parts(&parsed);
                let attachments = extract_attachments(&parsed);

                Ok(EmailBody {
                    uid: msg.uid.unwrap_or(seq),
                    uid_validity: None,
                    modseq: msg.mod_seq(),
                    from,
                    to,
                    cc,
                    subject,
                    date,
                    text,
                    html,
                    attachments,
                })
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_fetch_body!(s),
            ImapSession::StarttlsTls(s) => impl_fetch_body!(s),
            ImapSession::Plain(s) => impl_fetch_body!(s),
        }
    }

    /// Delete a message by sequence number: set \Deleted flag and EXPUNGE.
    pub fn delete_message(&mut self, folder: &str, seq: u32) -> Result<()> {
        macro_rules! impl_delete {
            ($session:expr) => {{
                $session.select(folder)?;
                $session.store(seq.to_string(), "+FLAGS (\\Deleted)")?;
                $session.expunge()?;
                Ok(())
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_delete!(s),
            ImapSession::StarttlsTls(s) => impl_delete!(s),
            ImapSession::Plain(s) => impl_delete!(s),
        }
    }

    pub fn mailbox_snapshot(&mut self, folder: &str) -> Result<EmailMailboxSnapshot> {
        macro_rules! impl_snapshot {
            ($session:expr) => {{
                let mailbox = $session.select(folder)?;
                let uid_validity = mailbox
                    .uid_validity
                    .ok_or_else(|| anyhow!("Mailbox does not expose UIDVALIDITY"))?;
                let highest_uid = $session.uid_search("ALL")?.into_iter().max().unwrap_or(0);
                Ok(EmailMailboxSnapshot {
                    folder: folder.to_string(),
                    uid_validity,
                    highest_uid,
                    exists: mailbox.exists,
                    highest_modseq: mailbox.highest_mod_seq,
                })
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_snapshot!(s),
            ImapSession::StarttlsTls(s) => impl_snapshot!(s),
            ImapSession::Plain(s) => impl_snapshot!(s),
        }
    }

    /// Create a mailbox when it does not already exist.
    ///
    /// This is used by deterministic fixture journeys to prepare a move
    /// destination; it is intentionally not exposed as an Agent capability.
    #[doc(hidden)]
    pub fn ensure_mailbox(&mut self, folder: &str) -> Result<()> {
        validate_destination_mailbox(folder)?;
        macro_rules! impl_ensure_mailbox {
            ($session:expr) => {{
                match $session.create(folder) {
                    Ok(()) => Ok(()),
                    Err(error) if error.to_string().to_ascii_lowercase().contains("exist") => {
                        Ok(())
                    }
                    Err(error) => Err(error.into()),
                }
            }};
        }
        match &mut self.session {
            ImapSession::Tls(session) => impl_ensure_mailbox!(session),
            ImapSession::StarttlsTls(session) => impl_ensure_mailbox!(session),
            ImapSession::Plain(session) => impl_ensure_mailbox!(session),
        }
    }

    pub fn idle_snapshot(
        &mut self,
        folder: &str,
        timeout: std::time::Duration,
    ) -> Result<EmailMailboxSnapshot> {
        macro_rules! impl_idle {
            ($session:expr) => {{
                $session.select(folder)?;
                $session
                    .idle()
                    .timeout(timeout)
                    .keepalive(false)
                    .wait_while(imap::extensions::idle::stop_on_any)?;
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_idle!(s),
            ImapSession::StarttlsTls(s) => impl_idle!(s),
            ImapSession::Plain(s) => impl_idle!(s),
        }
        self.mailbox_snapshot(folder)
    }

    pub fn fetch_body_by_identity(&mut self, identity: &EmailMessageIdentity) -> Result<EmailBody> {
        identity
            .validate()
            .map_err(|error| anyhow!(error.message))?;
        macro_rules! impl_fetch_uid {
            ($session:expr) => {{
                let mailbox = $session.select(&identity.folder)?;
                ensure_uid_validity(mailbox.uid_validity, identity.uid_validity)?;
                let query = if identity.expected_modseq.is_some() {
                    "(UID MODSEQ BODY.PEEK[])"
                } else {
                    "(UID BODY.PEEK[])"
                };
                let messages = $session.uid_fetch(identity.uid.to_string(), query)?;
                let message = messages
                    .iter()
                    .find(|message| message.uid == Some(identity.uid))
                    .ok_or_else(|| anyhow!("Message UID is stale or missing"))?;
                ensure_modseq(message.mod_seq(), identity.expected_modseq)?;
                let body_bytes = message.body().ok_or_else(|| anyhow!("No message body"))?;
                let parsed = mailparse::parse_mail(body_bytes)?;
                email_body_from_parsed(
                    &parsed,
                    identity.uid,
                    identity.uid_validity,
                    message.mod_seq(),
                )
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_fetch_uid!(s),
            ImapSession::StarttlsTls(s) => impl_fetch_uid!(s),
            ImapSession::Plain(s) => impl_fetch_uid!(s),
        }
    }

    pub fn move_message(
        &mut self,
        identity: &EmailMessageIdentity,
        destination_folder: &str,
    ) -> Result<()> {
        validate_destination_mailbox(destination_folder)?;
        macro_rules! impl_move {
            ($session:expr) => {{
                validate_identity($session, identity)?;
                $session.uid_mv(identity.uid.to_string(), destination_folder)?;
                Ok(())
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_move!(s),
            ImapSession::StarttlsTls(s) => impl_move!(s),
            ImapSession::Plain(s) => impl_move!(s),
        }
    }

    pub fn delete_message_by_identity(
        &mut self,
        identity: &EmailMessageIdentity,
        expunge: bool,
        trash_folder: Option<&str>,
    ) -> Result<()> {
        if !expunge {
            return self.move_message(
                identity,
                trash_folder.ok_or_else(|| anyhow!("Trash folder is required"))?,
            );
        }
        macro_rules! impl_delete_uid {
            ($session:expr) => {{
                validate_identity($session, identity)?;
                $session.uid_store(identity.uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
                $session.uid_expunge(identity.uid.to_string())?;
                Ok(())
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_delete_uid!(s),
            ImapSession::StarttlsTls(s) => impl_delete_uid!(s),
            ImapSession::Plain(s) => impl_delete_uid!(s),
        }
    }

    pub fn set_message_flags(
        &mut self,
        identity: &EmailMessageIdentity,
        action: EmailFlagAction,
        flags: &[String],
    ) -> Result<()> {
        let flags = normalize_flags(flags)?;
        macro_rules! impl_flags {
            ($session:expr) => {{
                validate_identity($session, identity)?;
                let operation = match action {
                    EmailFlagAction::Add => "+FLAGS.SILENT",
                    EmailFlagAction::Remove => "-FLAGS.SILENT",
                    EmailFlagAction::Replace => "FLAGS.SILENT",
                };
                let query = format!("{operation} ({})", flags.join(" "));
                $session.uid_store(identity.uid.to_string(), query)?;
                Ok(())
            }};
        }
        match &mut self.session {
            ImapSession::Tls(s) => impl_flags!(s),
            ImapSession::StarttlsTls(s) => impl_flags!(s),
            ImapSession::Plain(s) => impl_flags!(s),
        }
    }

    pub fn logout(self) {
        match self.session {
            ImapSession::Tls(mut s) => {
                let _ = s.logout();
            }
            ImapSession::StarttlsTls(mut s) => {
                let _ = s.logout();
            }
            ImapSession::Plain(mut s) => {
                let _ = s.logout();
            }
        }
    }
}

fn ensure_uid_validity(actual: Option<u32>, expected: u32) -> Result<()> {
    if actual != Some(expected) {
        return Err(anyhow!("Mailbox UIDVALIDITY changed"));
    }
    Ok(())
}

fn ensure_modseq(actual: Option<u64>, expected: Option<u64>) -> Result<()> {
    if expected.is_some() && actual != expected {
        return Err(anyhow!("Message MODSEQ changed"));
    }
    Ok(())
}

fn validate_identity<T: Read + Write>(
    session: &mut Session<T>,
    identity: &EmailMessageIdentity,
) -> Result<()> {
    identity
        .validate()
        .map_err(|error| anyhow!(error.message))?;
    let mailbox = session.select(&identity.folder)?;
    ensure_uid_validity(mailbox.uid_validity, identity.uid_validity)?;
    let query = if identity.expected_modseq.is_some() {
        "(UID MODSEQ)"
    } else {
        "(UID)"
    };
    let messages = session.uid_fetch(identity.uid.to_string(), query)?;
    let message = messages
        .iter()
        .find(|message| message.uid == Some(identity.uid))
        .ok_or_else(|| anyhow!("Message UID is stale or missing"))?;
    ensure_modseq(message.mod_seq(), identity.expected_modseq)
}

fn validate_destination_mailbox(folder: &str) -> Result<()> {
    if folder.trim().is_empty()
        || folder.len() > 1024
        || folder.contains(['\r', '\n', '\0'])
        || folder.chars().any(char::is_control)
    {
        return Err(anyhow!("Destination mailbox is invalid"));
    }
    Ok(())
}

fn normalize_flags(flags: &[String]) -> Result<Vec<&'static str>> {
    if flags.is_empty() || flags.len() > 4 {
        return Err(anyhow!("Flag set is empty or too large"));
    }
    let mut normalized = Vec::new();
    for flag in flags {
        let value = match flag.trim().to_ascii_lowercase().as_str() {
            "seen" => "\\Seen",
            "flagged" => "\\Flagged",
            "answered" => "\\Answered",
            "draft" => "\\Draft",
            _ => return Err(anyhow!("Unsupported message flag")),
        };
        if !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn email_body_from_parsed(
    parsed: &mailparse::ParsedMail<'_>,
    uid: u32,
    uid_validity: u32,
    modseq: Option<u64>,
) -> Result<EmailBody> {
    let header = |key: &str| {
        parsed
            .headers
            .iter()
            .find(|header| header.get_key_ref().eq_ignore_ascii_case(key))
            .map(|header| header.get_value())
    };
    let recipients = |key: &str| {
        header(key)
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let (text, html) = extract_body_parts(parsed);
    Ok(EmailBody {
        uid,
        uid_validity: Some(uid_validity),
        modseq,
        from: header("From").unwrap_or_else(|| "(unknown)".into()),
        to: recipients("To"),
        cc: recipients("Cc"),
        subject: header("Subject").unwrap_or_else(|| "(no subject)".into()),
        date: header("Date").unwrap_or_default(),
        text,
        html,
        attachments: extract_attachments(parsed),
    })
}

/// Decode IMAP Modified UTF-7 folder names to UTF-8.
/// In Modified UTF-7: `&` starts a base64-encoded UTF-16BE sequence, `-` ends it.
/// `&-` is a literal `&`. ASCII printable chars outside `&` are literal.
fn decode_imap_utf7(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '&' {
            result.push(ch);
            continue;
        }
        // Collect until '-'
        let mut b64 = String::new();
        loop {
            match chars.next() {
                Some('-') | None => break,
                Some(c) => b64.push(c),
            }
        }
        if b64.is_empty() {
            result.push('&'); // &- = literal &
            continue;
        }
        // Modified UTF-7 uses ',' instead of '/' in base64
        let b64_std: String = b64
            .chars()
            .map(|c| if c == ',' { '/' } else { c })
            .collect();
        // Pad to multiple of 4
        let padded = match b64_std.len() % 4 {
            2 => format!("{}==", b64_std),
            3 => format!("{}=", b64_std),
            _ => b64_std,
        };
        if let Ok(bytes) = base64_decode(&padded) {
            // Decode UTF-16BE
            let utf16: Vec<u16> = bytes
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            if let Ok(s) = String::from_utf16(&utf16) {
                result.push_str(&s);
            } else {
                result.push_str(input); // fallback
                return result;
            }
        } else {
            result.push('&');
            result.push_str(&b64);
            result.push('-');
        }
    }
    result
}

/// Simple base64 decoder (standard alphabet, no external dependency needed)
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    const TABLE: [u8; 128] = {
        let mut t = [0xFFu8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            i += 1;
        }
        i = 0;
        while i < 26 {
            t[(b'a' + i) as usize] = 26 + i;
            i += 1;
        }
        i = 0;
        while i < 10 {
            t[(b'0' + i) as usize] = 52 + i;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut buf = [0u32; 4];
        for (i, &b) in chunk.iter().enumerate() {
            if b >= 128 || TABLE[b as usize] == 0xFF {
                return Err(());
            }
            buf[i] = TABLE[b as usize] as u32;
        }
        let combined = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
        out.push((combined >> 16) as u8);
        if chunk.len() > 2 {
            out.push((combined >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(combined as u8);
        }
    }
    Ok(out)
}

/// Decode RFC 2047 encoded words (e.g. =?UTF-8?B?...?=) in IMAP ENVELOPE fields.
/// Since mailparse::parse_header expects "Key: value" format, we prepend a fake key.
fn decode_mime_words(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    if !s.contains("=?") {
        return s.to_string();
    }
    let fake_header = format!("X: {}", s);
    match mailparse::parse_header(fake_header.as_bytes()) {
        Ok((h, _)) => h.get_value(),
        Err(_) => s.to_string(),
    }
}
