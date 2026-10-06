//! EmailEvent enum — outbound events from EmailService to TUI.

use crate::policy::EmailMessageIdentity;
use crate::types::{EmailBody, EmailEnvelope, EmailFolder, EmailMailboxSnapshot};

/// Events sent from the EmailService back to the TUI plugin.
///
/// The TUI polls these via `EmailService::poll_event()` in its
/// synchronous `Plugin::update()` method. Per D-13, errors are
/// a variant in this enum, not a `Result` wrapper.
#[derive(Debug)]
pub enum EmailEvent {
    /// Connection established successfully.
    Connected,

    /// Connection failed.
    ConnectError(String),

    /// Connection was lost and service is attempting reconnection.
    /// Per D-03, TUI does not manage reconnection.
    ConnectionLost(String),

    /// Reconnection succeeded after a drop.
    Reconnected,

    /// Reconnection failed after attempts exhausted.
    ReconnectFailed(String),

    /// Disconnected cleanly.
    Disconnected,

    /// Folder list loaded from server.
    FoldersLoaded(Vec<EmailFolder>),

    /// Messages loaded for a folder. `total` is total count for pagination.
    MessagesLoaded {
        folder: String,
        messages: Vec<EmailEnvelope>,
        total: u32,
    },

    /// Unseen messages loaded for a folder.
    UnseenMessagesLoaded {
        folder: String,
        messages: Vec<EmailEnvelope>,
        total_unseen: u32,
    },

    /// Full message body fetched.
    BodyLoaded(EmailBody),

    /// Message deleted successfully.
    MessageDeleted { folder: String, seq: u32 },

    /// Stable mailbox identity and high-water metadata loaded.
    MailboxSnapshotLoaded(EmailMailboxSnapshot),

    /// Message moved after stable identity validation.
    MessageMoved {
        identity: EmailMessageIdentity,
        destination_folder: String,
    },

    /// Message flags updated after stable identity validation.
    MessageFlagsUpdated { identity: EmailMessageIdentity },

    /// Per D-07: Preview loaded for one folder during batch preload.
    FolderPreviewLoaded {
        folder_idx: usize,
        messages: Vec<EmailEnvelope>,
    },

    /// All folder previews have been loaded.
    PreviewsComplete,

    /// Single folder refreshed after mutation (per D-08).
    FolderRefreshed {
        folder_idx: usize,
        messages: Vec<EmailEnvelope>,
    },

    /// Email sent successfully via SMTP.
    EmailSent,

    /// An error occurred during an operation (per D-13).
    Error(String),
}
