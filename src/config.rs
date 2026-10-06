//! Email plugin configuration structures

use serde::{Deserialize, Serialize};

/// Email connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// Email address (username)
    pub email: String,
    /// Password for authentication
    pub password: String,
    /// Email protocol (IMAP or POP3)
    pub protocol: EmailProtocol,
    /// Receive server configuration
    pub receive: ServerConfig,
    /// SMTP server configuration
    pub smtp: ServerConfig,
    /// Security type for receive server
    #[serde(default = "SecurityType::default_value")]
    pub receive_security: SecurityType,
    /// Security type for SMTP server
    #[serde(default = "SecurityType::default_starttls")]
    pub smtp_security: SecurityType,
    /// Whether TLS certificates should be verified for receive connections.
    #[serde(default = "default_verify_tls")]
    pub verify_tls: bool,
}

fn default_verify_tls() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EmailProtocol {
    IMAP,
    POP3,
}

impl EmailProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            EmailProtocol::IMAP => "IMAP",
            EmailProtocol::POP3 => "POP3",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            EmailProtocol::IMAP => 993,
            EmailProtocol::POP3 => 995,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecurityType {
    #[serde(rename = "SSL/TLS")]
    SslTls,
    STARTTLS,
    None,
}

impl SecurityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityType::SslTls => "SSL/TLS",
            SecurityType::STARTTLS => "STARTTLS",
            SecurityType::None => "None",
        }
    }

    pub fn all() -> &'static [SecurityType] {
        &[
            SecurityType::SslTls,
            SecurityType::STARTTLS,
            SecurityType::None,
        ]
    }

    pub fn next(&self) -> SecurityType {
        match self {
            SecurityType::SslTls => SecurityType::STARTTLS,
            SecurityType::STARTTLS => SecurityType::None,
            SecurityType::None => SecurityType::SslTls,
        }
    }

    pub fn prev(&self) -> SecurityType {
        match self {
            SecurityType::SslTls => SecurityType::None,
            SecurityType::STARTTLS => SecurityType::SslTls,
            SecurityType::None => SecurityType::STARTTLS,
        }
    }

    pub fn default_receive_port(&self, protocol: EmailProtocol) -> u16 {
        match (protocol, self) {
            (EmailProtocol::IMAP, SecurityType::SslTls) => 993,
            (EmailProtocol::IMAP, _) => 143,
            (EmailProtocol::POP3, SecurityType::SslTls) => 995,
            (EmailProtocol::POP3, _) => 110,
        }
    }

    pub fn default_smtp_port(&self) -> u16 {
        match self {
            SecurityType::SslTls => 465,
            SecurityType::STARTTLS => 587,
            SecurityType::None => 25,
        }
    }

    fn default_value() -> SecurityType {
        SecurityType::SslTls
    }

    fn default_starttls() -> SecurityType {
        SecurityType::STARTTLS
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl EmailConfig {
    pub fn new_imap(email: String, password: String) -> Self {
        Self {
            email,
            password,
            protocol: EmailProtocol::IMAP,
            receive: ServerConfig {
                host: "imap.gmail.com".to_string(),
                port: 993,
            },
            smtp: ServerConfig {
                host: "smtp.gmail.com".to_string(),
                port: 587,
            },
            receive_security: SecurityType::SslTls,
            smtp_security: SecurityType::STARTTLS,
            verify_tls: true,
        }
    }

    pub fn new_pop3(email: String, password: String) -> Self {
        Self {
            email,
            password,
            protocol: EmailProtocol::POP3,
            receive: ServerConfig {
                host: "pop3.gmail.com".to_string(),
                port: 995,
            },
            smtp: ServerConfig {
                host: "smtp.gmail.com".to_string(),
                port: 587,
            },
            receive_security: SecurityType::SslTls,
            smtp_security: SecurityType::STARTTLS,
            verify_tls: true,
        }
    }
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self::new_imap(String::new(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_verify_tls_defaults_to_true() {
        let json = serde_json::json!({
            "email": "user@example.com",
            "password": "secret",
            "protocol": "IMAP",
            "receive": { "host": "imap.example.com", "port": 993 },
            "smtp": { "host": "smtp.example.com", "port": 587 },
            "receive_security": "SSL/TLS",
            "smtp_security": "STARTTLS"
        });

        let config: EmailConfig = serde_json::from_value(json).expect("deserialize email config");

        assert!(config.verify_tls);
    }

    #[test]
    fn explicit_verify_tls_false_is_preserved() {
        let mut config = EmailConfig::new_imap("user@example.com".into(), "secret".into());
        config.verify_tls = false;

        let value = serde_json::to_value(&config).expect("serialize email config");
        let roundtrip: EmailConfig =
            serde_json::from_value(value).expect("deserialize email config");

        assert!(!roundtrip.verify_tls);
    }
}
