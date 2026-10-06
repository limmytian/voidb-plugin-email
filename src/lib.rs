//! VoidB Email Plugin - IMAP/POP3 service and capability surface.
//! Author: Limmy

mod agent_session;
mod capabilities;
mod cli_plugin;
mod config;
// imap_client/pop3_client remain as internal modules used by service/imap_worker.rs
// and service/pop3_worker.rs. They are kept public for testing purposes only.
#[doc(hidden)]
pub mod imap_client;
pub(crate) mod mime_utils;
pub mod policy;
#[doc(hidden)]
pub mod pop3_client;
pub mod service;
mod tui;
mod types;

pub use agent_session::EmailAgentSessionFactory;
pub use capabilities::{email_capabilities, invoke_email_capability};
pub use cli_plugin::create_email_cli_plugin;
pub use config::{EmailConfig, EmailProtocol, SecurityType, ServerConfig};
pub use service::{EmailCommand, EmailEvent, EmailService};
pub use types::*;
// Re-exports for tests and external crate usage
pub use imap_client::ImapClient;
pub use pop3_client::Pop3Client;

/// Convenience function to create an IMAP connection (legacy, use EmailService for new code)
#[doc(hidden)]
pub fn imap_client_connect(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    security: SecurityType,
) -> anyhow::Result<ImapClient> {
    ImapClient::connect_with_security(host, port, user, password, security)
}

/// Convenience function to create a POP3 connection (legacy, use EmailService for new code)
#[doc(hidden)]
pub fn pop3_client_connect(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    security: SecurityType,
) -> anyhow::Result<Pop3Client> {
    Pop3Client::connect_with_security(host, port, user, password, security)
}
