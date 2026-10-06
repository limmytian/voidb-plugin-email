//! Email service layer.
//!
//! This module provides `EmailService`, the service facade for the email
//! plugin. It follows the service convention from `voidb-core`:
//!
//! - Dedicated worker thread owns a persistent IMAP/POP3 connection (per D-01)
//! - `send()` dispatches commands via std::sync::mpsc (non-blocking)
//! - `poll_event()` drains events via tokio::mpsc `try_recv()` (non-blocking)
//! - Render notifications fire after every event emission (per D-12)
//! - SMTP sends use `runtime.spawn_blocking` (per D-02), not the worker thread
//!
//! # Connection Lifecycle
//!
//! The service starts without an active connection. Send a `Connect` command
//! to establish the persistent session. The worker thread handles reconnection
//! internally (per D-03) with bounded retry (3 attempts, exponential backoff).
//!
//! # Direct Mode (CLI)
//!
//! `EmailService::new_direct()` creates the service without a real TabManager.
//! Use the direct async methods (`connect_direct`, `list_folders_direct`, etc.)
//! instead of the fire-and-forget `send()` + `poll_event()` pair.

pub mod commands;
pub mod events;
pub mod imap_worker;
pub mod pop3_worker;
pub mod smtp;

pub use commands::{EmailCommand, SendAttachment, StructuredEmail};
pub use events::EmailEvent;

use std::sync::Arc;
use std::sync::mpsc as std_mpsc;

use tokio::sync::mpsc as tokio_mpsc;

use voidb_core::TabManager;

/// No-op TabManager for direct mode (CLI usage).
/// `request_render()` is a no-op — there is no TUI to redraw.
struct NoOpTabManager;

impl TabManager for NoOpTabManager {
    fn open(
        &self,
        _title: String,
        _plugin_id: String,
        _context: serde_json::Value,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    fn close_current(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn close_tab(&self, _index: usize) -> anyhow::Result<()> {
        Ok(())
    }
    fn set_title(&self, _title: String) -> anyhow::Result<()> {
        Ok(())
    }
    fn request_render(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn list_tabs(&self) -> anyhow::Result<Vec<voidb_core::shell_capabilities::TabInfo>> {
        Ok(vec![])
    }
    fn switch_to(&self, _index: usize) -> anyhow::Result<()> {
        Ok(())
    }
    fn active_tab_index(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
    fn quit(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Email service facade.
///
/// Owns the command sender and event receiver channels. The background
/// worker thread runs on a dedicated OS thread (not tokio) because
/// IMAP/POP3 clients use blocking I/O with `!Send` types.
///
/// # Send + Sync
///
/// `EmailService` is `Send` but NOT `Sync` (because `UnboundedReceiver`
/// is `!Sync`). Plugin structs must wrap it in `std::sync::Mutex` to
/// satisfy `Plugin: Send + Sync`. Since `Plugin::update(&mut self)` has
/// exclusive access, the Mutex is never contended.
pub struct EmailService {
    cmd_tx: std_mpsc::Sender<EmailCommand>,
    event_rx: tokio_mpsc::UnboundedReceiver<EmailEvent>,
    _worker: Option<std::thread::JoinHandle<()>>,
}

impl EmailService {
    /// Create a new EmailService with a background worker thread.
    ///
    /// The service starts without an active connection. Send a `Connect`
    /// command to establish the persistent IMAP/POP3 session.
    ///
    /// `tabs` is used for `request_render()` notifications after events.
    /// `runtime` is used for `spawn_blocking` SMTP sends (per D-02).
    pub fn new(tabs: Arc<dyn TabManager>, runtime: tokio::runtime::Handle) -> Self {
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<EmailCommand>();
        let (event_tx, event_rx) = tokio_mpsc::unbounded_channel::<EmailEvent>();

        let worker = std::thread::spawn(move || {
            worker_loop(cmd_rx, event_tx, tabs, runtime);
        });

        Self {
            cmd_tx,
            event_rx,
            _worker: Some(worker),
        }
    }

    /// Create an EmailService in direct mode for CLI usage.
    ///
    /// Uses a `NoOpTabManager` so no TUI render notifications are fired.
    /// After creation, call `connect_direct()` to establish the IMAP/POP3
    /// session, then use the other `*_direct()` methods.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the tokio runtime handle cannot be obtained (i.e.,
    /// called outside a tokio runtime context).
    pub fn new_direct() -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            anyhow::anyhow!("EmailService::new_direct must be called inside a tokio runtime")
        })?;

        let tabs: Arc<dyn TabManager> = Arc::new(NoOpTabManager);
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<EmailCommand>();
        let (event_tx, event_rx) = tokio_mpsc::unbounded_channel::<EmailEvent>();

        let worker = std::thread::spawn(move || {
            worker_loop(cmd_rx, event_tx, tabs, runtime);
        });

        Ok(Self {
            cmd_tx,
            event_rx,
            _worker: Some(worker),
        })
    }

    /// Send a command to the email service worker thread.
    pub fn send(&self, cmd: EmailCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Poll for the next event from the service. Non-blocking.
    pub fn poll_event(&mut self) -> Option<EmailEvent> {
        self.event_rx.try_recv().ok()
    }

    // === Direct mode async methods (CLI) ===

    /// Connect to the email server and wait for the result.
    ///
    /// Returns `Ok(())` on successful connection, `Err` with the error
    /// message on failure.
    pub async fn connect_direct(
        &mut self,
        config: crate::config::EmailConfig,
    ) -> anyhow::Result<()> {
        self.send(EmailCommand::Connect { config });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::Connected) => return Ok(()),
                Some(EmailEvent::ConnectError(e)) => {
                    return Err(anyhow::anyhow!("Connection failed: {}", e));
                }
                Some(_) => continue, // discard unrelated events
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// List all folders on the server (direct mode).
    ///
    /// Requires a prior successful `connect_direct()` call.
    pub async fn list_folders_direct(&mut self) -> anyhow::Result<Vec<crate::types::EmailFolder>> {
        self.send(EmailCommand::ListFolders);
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::FoldersLoaded(folders)) => return Ok(folders),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// List messages in a folder with pagination (direct mode).
    ///
    /// Returns `(envelopes, total_count)`. `page` is 0-based (0 = newest).
    pub async fn list_messages_direct(
        &mut self,
        folder: String,
        page: u32,
        page_size: u32,
    ) -> anyhow::Result<(Vec<crate::types::EmailEnvelope>, u32)> {
        self.send(EmailCommand::ListMessages {
            folder: folder.clone(),
            page,
            page_size,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::MessagesLoaded {
                    messages, total, ..
                }) => return Ok((messages, total)),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// List unseen messages in a folder with pagination (direct mode).
    ///
    /// Returns `(envelopes, total_unseen_count)`. `page` is 0-based.
    pub async fn list_unseen_messages_direct(
        &mut self,
        folder: String,
        page: u32,
        page_size: u32,
    ) -> anyhow::Result<(Vec<crate::types::EmailEnvelope>, u32)> {
        self.send(EmailCommand::ListUnseenMessages {
            folder: folder.clone(),
            page,
            page_size,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::UnseenMessagesLoaded {
                    messages,
                    total_unseen,
                    ..
                }) => return Ok((messages, total_unseen)),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// Fetch the full body of a message by sequence number (direct mode).
    pub async fn fetch_body_direct(
        &mut self,
        folder: String,
        seq: u32,
    ) -> anyhow::Result<crate::types::EmailBody> {
        self.send(EmailCommand::FetchBody { folder, seq });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::BodyLoaded(body)) => return Ok(body),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// Fetch a message body without marking it read (direct mode).
    pub async fn fetch_body_read_only_direct(
        &mut self,
        folder: String,
        seq: u32,
    ) -> anyhow::Result<crate::types::EmailBody> {
        self.send(EmailCommand::FetchBodyReadOnly { folder, seq });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::BodyLoaded(body)) => return Ok(body),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    pub async fn fetch_body_by_identity_direct(
        &mut self,
        identity: crate::policy::EmailMessageIdentity,
    ) -> anyhow::Result<crate::types::EmailBody> {
        self.send(EmailCommand::FetchBodyByIdentity { identity });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::BodyLoaded(body)) => return Ok(body),
                Some(EmailEvent::Error(error)) => return Err(anyhow::anyhow!(error)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    pub async fn mailbox_snapshot_direct(
        &mut self,
        folder: String,
    ) -> anyhow::Result<crate::types::EmailMailboxSnapshot> {
        self.send(EmailCommand::MailboxSnapshot { folder });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::MailboxSnapshotLoaded(snapshot)) => return Ok(snapshot),
                Some(EmailEvent::Error(error)) => return Err(anyhow::anyhow!(error)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    pub async fn move_message_direct(
        &mut self,
        identity: crate::policy::EmailMessageIdentity,
        destination_folder: String,
    ) -> anyhow::Result<()> {
        self.send(EmailCommand::MoveMessage {
            identity,
            destination_folder,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::MessageMoved { .. }) => return Ok(()),
                Some(EmailEvent::Error(error)) => return Err(anyhow::anyhow!(error)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    pub async fn delete_message_by_identity_direct(
        &mut self,
        identity: crate::policy::EmailMessageIdentity,
        expunge: bool,
        trash_folder: Option<String>,
    ) -> anyhow::Result<()> {
        self.send(EmailCommand::DeleteMessageByIdentity {
            identity,
            expunge,
            trash_folder,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::MessageDeleted { .. }) => return Ok(()),
                Some(EmailEvent::Error(error)) => return Err(anyhow::anyhow!(error)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    pub async fn set_message_flags_direct(
        &mut self,
        identity: crate::policy::EmailMessageIdentity,
        action: crate::types::EmailFlagAction,
        flags: Vec<String>,
    ) -> anyhow::Result<()> {
        self.send(EmailCommand::SetMessageFlags {
            identity,
            action,
            flags,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::MessageFlagsUpdated { .. }) => return Ok(()),
                Some(EmailEvent::Error(error)) => return Err(anyhow::anyhow!(error)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// Delete a message by sequence number (direct mode).
    pub async fn delete_message_direct(&mut self, folder: String, seq: u32) -> anyhow::Result<()> {
        self.send(EmailCommand::DeleteMessage {
            folder: folder.clone(),
            seq,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::MessageDeleted { .. }) => return Ok(()),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    /// Send an email via SMTP (direct mode).
    ///
    /// The SMTP send runs via `spawn_blocking` inside the worker loop.
    /// This method awaits the `EmailSent` confirmation event.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_email_direct(
        &mut self,
        smtp_host: String,
        smtp_port: u16,
        smtp_security: crate::config::SecurityType,
        from: String,
        auth_user: String,
        password: String,
        to: String,
        subject: String,
        body: String,
        attachments: Vec<SendAttachment>,
    ) -> anyhow::Result<()> {
        self.send(EmailCommand::SendEmail {
            smtp_host,
            smtp_port,
            smtp_security,
            from,
            auth_user,
            password,
            to,
            subject,
            body,
            attachments,
        });
        loop {
            match self.event_rx.recv().await {
                Some(EmailEvent::EmailSent) => return Ok(()),
                Some(EmailEvent::Error(e)) => return Err(anyhow::anyhow!(e)),
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Worker thread exited unexpectedly")),
            }
        }
    }

    pub async fn send_structured_email_direct(
        &mut self,
        config: crate::config::EmailConfig,
        message: StructuredEmail,
    ) -> anyhow::Result<String> {
        tokio::task::spawn_blocking(move || {
            smtp::send_structured_email_smtp(
                &config.smtp.host,
                config.smtp.port,
                &config.smtp_security,
                &config.email,
                &config.password,
                &message,
            )
        })
        .await
        .map_err(|_| anyhow::anyhow!("SMTP send worker failed"))?
    }
}

/// Protocol-agnostic client wrapper for the worker thread.
enum EmailClient {
    Imap(imap_worker::ImapClient),
    Pop3(pop3_worker::Pop3Client),
}

/// Main worker loop running on a dedicated OS thread.
///
/// Processes commands sequentially, dispatching to the appropriate
/// protocol handler. SMTP sends are offloaded via `runtime.spawn_blocking`
/// to keep this loop responsive (per D-02).
fn worker_loop(
    cmd_rx: std_mpsc::Receiver<EmailCommand>,
    event_tx: tokio_mpsc::UnboundedSender<EmailEvent>,
    tabs: Arc<dyn TabManager>,
    runtime: tokio::runtime::Handle,
) {
    use crate::config::EmailProtocol;

    let mut client: Option<EmailClient> = None;
    let mut config: Option<crate::config::EmailConfig> = None;

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            EmailCommand::Connect { config: cfg } => {
                let result = match cfg.protocol {
                    EmailProtocol::IMAP => {
                        imap_worker::ImapClient::connect_with_security_and_tls_verification(
                            &cfg.receive.host,
                            cfg.receive.port,
                            &cfg.email,
                            &cfg.password,
                            cfg.receive_security,
                            cfg.verify_tls,
                        )
                        .map(EmailClient::Imap)
                    }
                    EmailProtocol::POP3 => {
                        pop3_worker::Pop3Client::connect_with_security_and_tls_verification(
                            &cfg.receive.host,
                            cfg.receive.port,
                            &cfg.email,
                            &cfg.password,
                            cfg.receive_security,
                            cfg.verify_tls,
                        )
                        .map(EmailClient::Pop3)
                    }
                };
                match result {
                    Ok(c) => {
                        client = Some(c);
                        config = Some(cfg);
                        let _ = event_tx.send(EmailEvent::Connected);
                    }
                    Err(e) => {
                        let _ = event_tx.send(EmailEvent::ConnectError(e.to_string()));
                    }
                }
                let _ = tabs.request_render();
            }

            EmailCommand::Disconnect => {
                if let Some(c) = client.take() {
                    match c {
                        EmailClient::Imap(imap) => imap.logout(),
                        EmailClient::Pop3(pop3) => pop3.logout(),
                    }
                }
                drop(config);
                let _ = event_tx.send(EmailEvent::Disconnected);
                let _ = tabs.request_render();
                break;
            }

            EmailCommand::ListFolders => {
                let evt = match client.as_mut() {
                    Some(c) => match list_folders(c) {
                        Ok(folders) => EmailEvent::FoldersLoaded(folders),
                        Err(e) => try_reconnect_or_error(
                            &mut client,
                            &config,
                            &event_tx,
                            &tabs,
                            e,
                            "ListFolders",
                        ),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::ListMessages {
                folder,
                page,
                page_size,
            } => {
                let evt = match client.as_mut() {
                    Some(c) => match list_messages(c, &folder, page, page_size) {
                        Ok((messages, total)) => EmailEvent::MessagesLoaded {
                            folder,
                            messages,
                            total,
                        },
                        Err(e) => try_reconnect_or_error(
                            &mut client,
                            &config,
                            &event_tx,
                            &tabs,
                            e,
                            "ListMessages",
                        ),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::ListUnseenMessages {
                folder,
                page,
                page_size,
            } => {
                let evt = match client.as_mut() {
                    Some(c) => match list_unseen_messages(c, &folder, page, page_size) {
                        Ok((messages, total_unseen)) => EmailEvent::UnseenMessagesLoaded {
                            folder,
                            messages,
                            total_unseen,
                        },
                        Err(e) => try_reconnect_or_error(
                            &mut client,
                            &config,
                            &event_tx,
                            &tabs,
                            e,
                            "ListUnseenMessages",
                        ),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::FetchBody { folder, seq } => {
                let evt = match client.as_mut() {
                    Some(c) => match fetch_body(c, &folder, seq) {
                        Ok(body) => EmailEvent::BodyLoaded(body),
                        Err(e) => try_reconnect_or_error(
                            &mut client,
                            &config,
                            &event_tx,
                            &tabs,
                            e,
                            "FetchBody",
                        ),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::FetchBodyReadOnly { folder, seq } => {
                let evt = match client.as_mut() {
                    Some(c) => match fetch_body_read_only(c, &folder, seq) {
                        Ok(body) => EmailEvent::BodyLoaded(body),
                        Err(e) => try_reconnect_or_error(
                            &mut client,
                            &config,
                            &event_tx,
                            &tabs,
                            e,
                            "FetchBodyReadOnly",
                        ),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::FetchBodyByIdentity { identity } => {
                let evt = match client.as_mut() {
                    Some(EmailClient::Imap(client)) => client
                        .fetch_body_by_identity(&identity)
                        .map(EmailEvent::BodyLoaded)
                        .unwrap_or_else(|error| EmailEvent::Error(error.to_string())),
                    Some(EmailClient::Pop3(_)) => {
                        EmailEvent::Error("Stable UID fetch requires IMAP".into())
                    }
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::MailboxSnapshot { folder } => {
                let evt = match client.as_mut() {
                    Some(EmailClient::Imap(client)) => client
                        .mailbox_snapshot(&folder)
                        .map(EmailEvent::MailboxSnapshotLoaded)
                        .unwrap_or_else(|error| EmailEvent::Error(error.to_string())),
                    Some(EmailClient::Pop3(_)) => {
                        EmailEvent::Error("Mailbox snapshots require IMAP".into())
                    }
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::MoveMessage {
                identity,
                destination_folder,
            } => {
                let evt = match client.as_mut() {
                    Some(EmailClient::Imap(client)) => client
                        .move_message(&identity, &destination_folder)
                        .map(|()| EmailEvent::MessageMoved {
                            identity,
                            destination_folder,
                        })
                        .unwrap_or_else(|error| EmailEvent::Error(error.to_string())),
                    Some(EmailClient::Pop3(_)) => {
                        EmailEvent::Error("Message move requires IMAP".into())
                    }
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::DeleteMessageByIdentity {
                identity,
                expunge,
                trash_folder,
            } => {
                let folder = identity.folder.clone();
                let uid = identity.uid;
                let evt = match client.as_mut() {
                    Some(EmailClient::Imap(client)) => client
                        .delete_message_by_identity(&identity, expunge, trash_folder.as_deref())
                        .map(|()| EmailEvent::MessageDeleted { folder, seq: uid })
                        .unwrap_or_else(|error| EmailEvent::Error(error.to_string())),
                    Some(EmailClient::Pop3(_)) => {
                        EmailEvent::Error("Stable message deletion requires IMAP".into())
                    }
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::SetMessageFlags {
                identity,
                action,
                flags,
            } => {
                let evt = match client.as_mut() {
                    Some(EmailClient::Imap(client)) => client
                        .set_message_flags(&identity, action, &flags)
                        .map(|()| EmailEvent::MessageFlagsUpdated { identity })
                        .unwrap_or_else(|error| EmailEvent::Error(error.to_string())),
                    Some(EmailClient::Pop3(_)) => {
                        EmailEvent::Error("Message flags require IMAP".into())
                    }
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::DeleteMessage { folder, seq } => {
                let evt = match client.as_mut() {
                    Some(c) => match delete_message(c, &folder, seq) {
                        Ok(()) => EmailEvent::MessageDeleted { folder, seq },
                        Err(e) => try_reconnect_or_error(
                            &mut client,
                            &config,
                            &event_tx,
                            &tabs,
                            e,
                            "DeleteMessage",
                        ),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::PreloadFolderPreviews { folders, page_size } => {
                if let Some(c) = client.as_mut() {
                    for (idx, folder_name) in folders.iter().enumerate() {
                        match list_messages(c, folder_name, 0, page_size) {
                            Ok((messages, _total)) => {
                                let _ = event_tx.send(EmailEvent::FolderPreviewLoaded {
                                    folder_idx: idx,
                                    messages,
                                });
                            }
                            Err(e) => {
                                let _ = event_tx.send(EmailEvent::FolderPreviewLoaded {
                                    folder_idx: idx,
                                    messages: Vec::new(),
                                });
                                tracing::warn!(
                                    "Preview load failed for folder {}: {}",
                                    folder_name,
                                    e
                                );
                            }
                        }
                        let _ = tabs.request_render();
                    }
                    let _ = event_tx.send(EmailEvent::PreviewsComplete);
                } else {
                    let _ = event_tx.send(EmailEvent::Error("Not connected".into()));
                }
                let _ = tabs.request_render();
            }

            EmailCommand::RefreshFolder {
                folder_name,
                folder_idx,
                page_size,
            } => {
                let evt = match client.as_mut() {
                    Some(c) => match list_messages(c, &folder_name, 0, page_size) {
                        Ok((messages, _total)) => EmailEvent::FolderRefreshed {
                            folder_idx,
                            messages,
                        },
                        Err(e) => EmailEvent::Error(format!(
                            "Refresh folder {} failed: {}",
                            folder_name, e
                        )),
                    },
                    None => EmailEvent::Error("Not connected".into()),
                };
                let _ = event_tx.send(evt);
                let _ = tabs.request_render();
            }

            EmailCommand::SendEmail {
                smtp_host,
                smtp_port,
                smtp_security,
                from,
                auth_user,
                password,
                to,
                subject,
                body,
                attachments,
            } => {
                // Per D-02: SMTP runs on a SEPARATE thread via spawn_blocking,
                // NOT on the IMAP/POP3 worker thread.
                let send_event_tx = event_tx.clone();
                let send_tabs = tabs.clone();
                runtime.spawn_blocking(move || {
                    match smtp::send_email_smtp(
                        &smtp_host,
                        smtp_port,
                        &smtp_security,
                        &from,
                        &auth_user,
                        &password,
                        &to,
                        &subject,
                        &body,
                        &attachments,
                    ) {
                        Ok(()) => {
                            let _ = send_event_tx.send(EmailEvent::EmailSent);
                        }
                        Err(e) => {
                            let _ = send_event_tx
                                .send(EmailEvent::Error(format!("SMTP send failed: {}", e)));
                        }
                    }
                    let _ = send_tabs.request_render();
                });
                // Worker continues immediately — does not wait for SMTP to finish.
                continue;
            }
        }
    }
}

// === Protocol dispatch helpers ===

fn list_folders(client: &mut EmailClient) -> anyhow::Result<Vec<crate::types::EmailFolder>> {
    match client {
        EmailClient::Imap(c) => c.list_folders(),
        EmailClient::Pop3(c) => c.list_folders(),
    }
}

fn list_messages(
    client: &mut EmailClient,
    folder: &str,
    page: u32,
    page_size: u32,
) -> anyhow::Result<(Vec<crate::types::EmailEnvelope>, u32)> {
    match client {
        EmailClient::Imap(c) => c.list_messages(folder, page, page_size),
        EmailClient::Pop3(c) => c.list_messages(folder, page, page_size),
    }
}

fn list_unseen_messages(
    client: &mut EmailClient,
    folder: &str,
    page: u32,
    page_size: u32,
) -> anyhow::Result<(Vec<crate::types::EmailEnvelope>, u32)> {
    match client {
        EmailClient::Imap(c) => c.list_unseen_messages(folder, page, page_size),
        EmailClient::Pop3(c) => {
            // POP3 doesn't support UNSEEN filter natively — fall back to listing all
            c.list_messages(folder, page, page_size)
        }
    }
}

fn fetch_body(
    client: &mut EmailClient,
    folder: &str,
    seq: u32,
) -> anyhow::Result<crate::types::EmailBody> {
    match client {
        EmailClient::Imap(c) => c.fetch_body(folder, seq),
        EmailClient::Pop3(c) => c.fetch_body(folder, seq),
    }
}

fn fetch_body_read_only(
    client: &mut EmailClient,
    folder: &str,
    seq: u32,
) -> anyhow::Result<crate::types::EmailBody> {
    match client {
        EmailClient::Imap(c) => c.fetch_body_read_only(folder, seq),
        EmailClient::Pop3(c) => c.fetch_body_read_only(folder, seq),
    }
}

fn delete_message(client: &mut EmailClient, folder: &str, seq: u32) -> anyhow::Result<()> {
    match client {
        EmailClient::Imap(c) => c.delete_message(folder, seq),
        EmailClient::Pop3(c) => c.delete_message(seq),
    }
}

/// Attempt to reconnect after a connection error (per D-03).
///
/// Tries up to 3 times with exponential backoff (1s, 2s, 4s).
/// Emits `ConnectionLost` before attempts and `Reconnected`/`ReconnectFailed` after.
fn try_reconnect_or_error(
    client: &mut Option<EmailClient>,
    config: &Option<crate::config::EmailConfig>,
    event_tx: &tokio_mpsc::UnboundedSender<EmailEvent>,
    tabs: &Arc<dyn TabManager>,
    error: anyhow::Error,
    operation: &str,
) -> EmailEvent {
    use crate::config::EmailProtocol;

    let Some(cfg) = config else {
        return EmailEvent::Error(format!("{} failed: {}", operation, error));
    };

    // Check if this is a connection-level error worth reconnecting
    let err_str = error.to_string();
    let is_connection_error = err_str.contains("connection")
        || err_str.contains("Connection")
        || err_str.contains("broken pipe")
        || err_str.contains("reset by peer")
        || err_str.contains("timed out")
        || err_str.contains("EOF");

    if !is_connection_error {
        return EmailEvent::Error(format!("{} failed: {}", operation, error));
    }

    let _ = event_tx.send(EmailEvent::ConnectionLost(err_str.clone()));
    let _ = tabs.request_render();

    // Drop old client
    if let Some(old) = client.take() {
        match old {
            EmailClient::Imap(imap) => imap.logout(),
            EmailClient::Pop3(pop3) => pop3.logout(),
        }
    }

    // Reconnect with exponential backoff
    for attempt in 1..=3u32 {
        let backoff = std::time::Duration::from_secs(1 << (attempt - 1));
        std::thread::sleep(backoff);

        let result = match cfg.protocol {
            EmailProtocol::IMAP => {
                imap_worker::ImapClient::connect_with_security_and_tls_verification(
                    &cfg.receive.host,
                    cfg.receive.port,
                    &cfg.email,
                    &cfg.password,
                    cfg.receive_security,
                    cfg.verify_tls,
                )
                .map(EmailClient::Imap)
            }
            EmailProtocol::POP3 => {
                pop3_worker::Pop3Client::connect_with_security_and_tls_verification(
                    &cfg.receive.host,
                    cfg.receive.port,
                    &cfg.email,
                    &cfg.password,
                    cfg.receive_security,
                    cfg.verify_tls,
                )
                .map(EmailClient::Pop3)
            }
        };

        match result {
            Ok(c) => {
                *client = Some(c);
                let _ = event_tx.send(EmailEvent::Reconnected);
                let _ = tabs.request_render();
                return EmailEvent::Error(format!(
                    "{} failed (reconnected, please retry): {}",
                    operation, err_str
                ));
            }
            Err(_) if attempt < 3 => continue,
            Err(e) => {
                let _ = event_tx.send(EmailEvent::ReconnectFailed(e.to_string()));
                let _ = tabs.request_render();
                return EmailEvent::Error(format!(
                    "{} failed (reconnect failed after 3 attempts): {}",
                    operation, err_str
                ));
            }
        }
    }

    EmailEvent::Error(format!("{} failed: {}", operation, err_str))
}
