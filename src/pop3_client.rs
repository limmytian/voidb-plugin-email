//! POP3 client implementation
//! Author: Limmy
//!
//! POP3 protocol is simple text-based:
//!   +OK / -ERR response lines
//!   USER / PASS for auth
//!   STAT for mailbox status
//!   LIST for message sizes
//!   TOP n 0 for headers only
//!   RETR n for full message
//!   QUIT to disconnect

use anyhow::{Result, anyhow};
use native_tls::TlsStream;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use crate::config::SecurityType;
use crate::mime_utils::{extract_attachments, extract_body_parts};
use crate::types::{EmailBody, EmailEnvelope, EmailFolder};

enum Pop3Stream {
    Tls(BufReader<TlsStream<TcpStream>>),
    Plain(BufReader<TcpStream>),
}

pub struct Pop3Client {
    stream: Pop3Stream,
}

/// Read a single POP3 response line. Returns the line without CRLF.
fn read_line(stream: &mut Pop3Stream) -> Result<String> {
    let mut line = String::new();
    match stream {
        Pop3Stream::Tls(r) => {
            r.read_line(&mut line)?;
        }
        Pop3Stream::Plain(r) => {
            r.read_line(&mut line)?;
        }
    }
    Ok(line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string())
}

/// Read a multi-line POP3 response (terminated by ".\r\n").
/// Returns all lines between the +OK line and the terminator.
fn read_multiline(stream: &mut Pop3Stream) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        match stream {
            Pop3Stream::Tls(r) => {
                r.read_line(&mut line)?;
            }
            Pop3Stream::Plain(r) => {
                r.read_line(&mut line)?;
            }
        }
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed == "." {
            break;
        }
        // Byte-stuffing: lines starting with ".." have the first dot removed
        let content = if trimmed.starts_with("..") {
            &trimmed[1..]
        } else {
            trimmed
        };
        lines.push(content.to_string());
    }
    Ok(lines)
}

/// Send a POP3 command and return the response line.
fn send_command(stream: &mut Pop3Stream, cmd: &str) -> Result<String> {
    let data = format!("{}\r\n", cmd);
    match stream {
        Pop3Stream::Tls(r) => {
            r.get_mut().write_all(data.as_bytes())?;
            r.get_mut().flush()?;
        }
        Pop3Stream::Plain(r) => {
            r.get_mut().write_all(data.as_bytes())?;
            r.get_mut().flush()?;
        }
    }
    let resp = read_line(stream)?;
    Ok(resp)
}

/// Send a command and check +OK response.
fn send_command_ok(stream: &mut Pop3Stream, cmd: &str) -> Result<String> {
    let resp = send_command(stream, cmd)?;
    if !resp.starts_with("+OK") {
        return Err(anyhow!("POP3 error: {}", resp));
    }
    Ok(resp)
}

fn tls_connector(verify_tls: bool) -> Result<native_tls::TlsConnector> {
    let mut builder = native_tls::TlsConnector::builder();
    if !verify_tls {
        builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

impl Pop3Client {
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
        let mut stream = match security {
            SecurityType::SslTls => {
                let tls_connector = tls_connector(verify_tls)?;
                let tcp = TcpStream::connect((host, port))?;
                let tls = tls_connector.connect(host, tcp)?;
                Pop3Stream::Tls(BufReader::new(tls))
            }
            SecurityType::STARTTLS => {
                let tcp = TcpStream::connect((host, port))?;
                let mut stream = Pop3Stream::Plain(BufReader::new(tcp));

                // Read greeting
                let greeting = read_line(&mut stream)?;
                if !greeting.starts_with("+OK") {
                    return Err(anyhow!("POP3 greeting failed: {}", greeting));
                }

                // Send STLS command
                send_command_ok(&mut stream, "STLS")?;

                // Upgrade to TLS
                let tls_connector = tls_connector(verify_tls)?;
                let tcp = match stream {
                    Pop3Stream::Plain(r) => r.into_inner(),
                    _ => unreachable!(),
                };
                let tls = tls_connector.connect(host, tcp)?;
                let mut tls_stream = Pop3Stream::Tls(BufReader::new(tls));

                // Auth after TLS upgrade
                send_command_ok(&mut tls_stream, &format!("USER {}", user))?;
                send_command_ok(&mut tls_stream, &format!("PASS {}", password))?;

                return Ok(Self { stream: tls_stream });
            }
            SecurityType::None => {
                let tcp = TcpStream::connect((host, port))?;
                Pop3Stream::Plain(BufReader::new(tcp))
            }
        };

        // Read greeting (for SslTls and None; STARTTLS returns early)
        let greeting = read_line(&mut stream)?;
        if !greeting.starts_with("+OK") {
            return Err(anyhow!("POP3 greeting failed: {}", greeting));
        }

        // Authenticate
        send_command_ok(&mut stream, &format!("USER {}", user))?;
        send_command_ok(&mut stream, &format!("PASS {}", password))?;

        Ok(Self { stream })
    }

    /// POP3 only has INBOX. Return a single folder with message count.
    pub fn list_folders(&mut self) -> Result<Vec<EmailFolder>> {
        let resp = send_command_ok(&mut self.stream, "STAT")?;
        // +OK n size
        let total: u32 = resp
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(vec![EmailFolder {
            name: "INBOX".to_string(),
            display_name: "INBOX".to_string(),
            delimiter: "/".to_string(),
            message_count: total,
            unread_count: 0, // POP3 doesn't track read/unread
        }])
    }

    /// List messages with pagination. POP3 ignores folder name (always INBOX).
    /// `page` is 0-based (0 = newest). Returns (envelopes, total_count).
    pub fn list_messages(
        &mut self,
        _folder: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<EmailEnvelope>, u32)> {
        // Get total count
        let stat_resp = send_command_ok(&mut self.stream, "STAT")?;
        let total: u32 = stat_resp
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        if total == 0 {
            return Ok((Vec::new(), 0));
        }

        // Get message sizes via LIST
        send_command_ok(&mut self.stream, "LIST")?;
        let list_lines = read_multiline(&mut self.stream)?;
        let mut sizes: Vec<(u32, u32)> = Vec::new(); // (msg_num, size)
        for line in &list_lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2
                && let (Ok(num), Ok(size)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
            {
                sizes.push((num, size));
            }
        }

        // Paginate: skip newest `page * page_size`, then take `page_size`
        let skip = (page * page_size) as usize;
        let mut envelopes = Vec::new();
        for &(msg_num, size) in sizes.iter().rev().skip(skip).take(page_size as usize) {
            match self.fetch_headers(msg_num) {
                Ok((from, subject, date)) => {
                    envelopes.push(EmailEnvelope {
                        uid: msg_num,
                        uid_validity: None,
                        modseq: None,
                        from,
                        subject,
                        date,
                        seen: true, // POP3 doesn't track flags
                        size,
                    });
                }
                Err(_) => {
                    envelopes.push(EmailEnvelope {
                        uid: msg_num,
                        uid_validity: None,
                        modseq: None,
                        from: "(unknown)".into(),
                        subject: "(failed to fetch headers)".into(),
                        date: String::new(),
                        seen: true,
                        size,
                    });
                }
            }
        }

        Ok((envelopes, total))
    }

    /// Fetch headers of a message using TOP command.
    fn fetch_headers(&mut self, msg_num: u32) -> Result<(String, String, String)> {
        let resp = send_command(&mut self.stream, &format!("TOP {} 0", msg_num))?;
        if !resp.starts_with("+OK") {
            return Err(anyhow!("TOP failed: {}", resp));
        }
        let lines = read_multiline(&mut self.stream)?;
        let raw = lines.join("\r\n");

        match mailparse::parse_headers(raw.as_bytes()) {
            Ok((headers, _)) => {
                let from = headers
                    .iter()
                    .find(|h| h.get_key_ref().eq_ignore_ascii_case("From"))
                    .map(|h| h.get_value())
                    .unwrap_or_else(|| "(unknown)".into());
                let subject = headers
                    .iter()
                    .find(|h| h.get_key_ref().eq_ignore_ascii_case("Subject"))
                    .map(|h| h.get_value())
                    .unwrap_or_else(|| "(no subject)".into());
                let date = headers
                    .iter()
                    .find(|h| h.get_key_ref().eq_ignore_ascii_case("Date"))
                    .map(|h| h.get_value())
                    .unwrap_or_default();
                Ok((from, subject, date))
            }
            Err(_) => Ok(("(unknown)".into(), "(no subject)".into(), String::new())),
        }
    }

    /// POP3 does not support unseen filtering. Returns empty list.
    pub fn list_unseen_messages(
        &mut self,
        _folder: &str,
        _page: u32,
        _page_size: u32,
    ) -> Result<(Vec<EmailEnvelope>, u32)> {
        Ok((Vec::new(), 0))
    }

    /// Fetch full message body using RETR command.
    pub fn fetch_body(&mut self, _folder: &str, msg_num: u32) -> Result<EmailBody> {
        let resp = send_command(&mut self.stream, &format!("RETR {}", msg_num))?;
        if !resp.starts_with("+OK") {
            return Err(anyhow!("RETR failed: {}", resp));
        }
        let lines = read_multiline(&mut self.stream)?;
        let raw = lines.join("\r\n");

        let parsed = mailparse::parse_mail(raw.as_bytes())?;

        let from = parsed
            .headers
            .iter()
            .find(|h| h.get_key_ref().eq_ignore_ascii_case("From"))
            .map(|h| h.get_value())
            .unwrap_or_else(|| "(unknown)".into());
        let to: Vec<String> = parsed
            .headers
            .iter()
            .find(|h| h.get_key_ref().eq_ignore_ascii_case("To"))
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
            .find(|h| h.get_key_ref().eq_ignore_ascii_case("Cc"))
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
            .find(|h| h.get_key_ref().eq_ignore_ascii_case("Subject"))
            .map(|h| h.get_value())
            .unwrap_or_else(|| "(no subject)".into());
        let date = parsed
            .headers
            .iter()
            .find(|h| h.get_key_ref().eq_ignore_ascii_case("Date"))
            .map(|h| h.get_value())
            .unwrap_or_default();

        let (text, html) = extract_body_parts(&parsed);
        let attachments = extract_attachments(&parsed);

        Ok(EmailBody {
            uid: msg_num,
            uid_validity: None,
            modseq: None,
            from,
            to,
            cc,
            subject,
            date,
            text,
            html,
            attachments,
        })
    }

    /// Delete a message by number using DELE command.
    pub fn delete_message(&mut self, msg_num: u32) -> Result<()> {
        send_command_ok(&mut self.stream, &format!("DELE {}", msg_num))?;
        Ok(())
    }

    pub fn logout(mut self) {
        let _ = send_command(&mut self.stream, "QUIT");
    }
}
