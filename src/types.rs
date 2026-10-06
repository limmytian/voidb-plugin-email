//! Email data types
//! Author: Limmy

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailFolder {
    /// Raw IMAP folder name (Modified UTF-7, used for SELECT/FETCH commands)
    pub name: String,
    /// Human-readable folder name (decoded from Modified UTF-7)
    pub display_name: String,
    pub delimiter: String,
    pub message_count: u32,
    pub unread_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailEnvelope {
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modseq: Option<u64>,
    pub from: String,
    pub subject: String,
    pub date: String,
    pub seen: bool,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub size: usize,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailBody {
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modseq: Option<u64>,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub date: String,
    pub text: String,
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMailboxSnapshot {
    pub folder: String,
    pub uid_validity: u32,
    pub highest_uid: u32,
    pub exists: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_modseq: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailFlagAction {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailDeleteMode {
    Trash,
    Expunge,
}
