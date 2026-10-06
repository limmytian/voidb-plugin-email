//! EmailCommand enum — inbound commands from TUI to EmailService.

use crate::config::{EmailConfig, SecurityType};
use crate::policy::EmailMessageIdentity;
use crate::types::EmailFlagAction;

/// Commands sent from the TUI plugin to the EmailService worker thread.
///
/// All operations are fire-and-forget: the TUI sends a command and receives
/// results asynchronously via `EmailEvent`. Per D-04, a single flat enum
/// covers all email operations (IMAP, POP3, and SMTP).
#[derive(Debug)]
pub enum EmailCommand {
    /// Establish persistent IMAP/POP3 connection on worker thread.
    /// Per D-01, replaces per-operation connect/disconnect.
    Connect { config: EmailConfig },

    /// Disconnect and shut down the worker thread.
    Disconnect,

    /// List all folders on the server.
    ListFolders,

    /// List messages in a folder with pagination. `page` is 0-based.
    ListMessages {
        folder: String,
        page: u32,
        page_size: u32,
    },

    /// List only unseen messages in a folder with pagination.
    ListUnseenMessages {
        folder: String,
        page: u32,
        page_size: u32,
    },

    /// Fetch full message body by folder name and sequence number.
    FetchBody { folder: String, seq: u32 },

    /// Fetch full message body without changing read/unread state.
    FetchBodyReadOnly { folder: String, seq: u32 },

    /// Delete a message by folder name and sequence number.
    DeleteMessage { folder: String, seq: u32 },

    /// Fetch a message through its stable IMAP UID identity.
    FetchBodyByIdentity { identity: EmailMessageIdentity },

    /// Return UIDVALIDITY and high-water metadata for one IMAP mailbox.
    MailboxSnapshot { folder: String },

    /// Move one message after revalidating UIDVALIDITY and optional MODSEQ.
    MoveMessage {
        identity: EmailMessageIdentity,
        destination_folder: String,
    },

    /// Delete one message either by moving it to Trash or by UID EXPUNGE.
    DeleteMessageByIdentity {
        identity: EmailMessageIdentity,
        expunge: bool,
        trash_folder: Option<String>,
    },

    /// Apply a bounded allowlisted flag change to one stable message identity.
    SetMessageFlags {
        identity: EmailMessageIdentity,
        action: EmailFlagAction,
        flags: Vec<String>,
    },

    /// Per D-07: Preload first-page messages for all folders sequentially.
    /// Emits `FolderPreviewLoaded` for each folder as results arrive.
    PreloadFolderPreviews {
        folders: Vec<String>,
        page_size: u32,
    },

    /// Per D-08: Re-fetch a single folder's first-page messages.
    RefreshFolder {
        folder_name: String,
        folder_idx: usize,
        page_size: u32,
    },

    /// Per D-02: Send an email via SMTP. Uses spawn_blocking, not the worker thread.
    SendEmail {
        smtp_host: String,
        smtp_port: u16,
        smtp_security: SecurityType,
        from: String,
        auth_user: String,
        password: String,
        to: String,
        subject: String,
        body: String,
        attachments: Vec<SendAttachment>,
    },
}

/// Attachment data for SMTP sending.
///
/// Separate from `types::Attachment` to avoid `Serialize` bound issues
/// and keep the service command self-contained.
#[derive(Debug, Clone)]
pub struct SendAttachment {
    pub filename: String,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StructuredEmail {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub text_body: String,
    pub html_body: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<SendAttachment>,
}
