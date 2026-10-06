//! SMTP send operations for the EmailService.
//!
//! Per D-02, SMTP sends run via `runtime.spawn_blocking`, not on the
//! IMAP/POP3 worker thread. This module provides the blocking send function.

use anyhow::{Result, anyhow};

use super::commands::{SendAttachment, StructuredEmail};
use crate::config::SecurityType;

/// Send an email via SMTP. This is a blocking function intended to be
/// called from `runtime.spawn_blocking`.
#[allow(clippy::too_many_arguments)]
pub fn send_email_smtp(
    smtp_host: &str,
    smtp_port: u16,
    smtp_security: &SecurityType,
    from: &str,
    auth_user: &str,
    password: &str,
    to: &str,
    subject: &str,
    body: &str,
    attachments: &[SendAttachment],
) -> Result<()> {
    use lettre::address::Address;
    use lettre::message::{Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    fn parse_address(addr: &str) -> Result<Mailbox> {
        let addr = addr.trim();
        if let Ok(m) = addr.parse::<Mailbox>() {
            return Ok(m);
        }
        let at = addr
            .rfind('@')
            .ok_or_else(|| anyhow!("Invalid email address (no @): {}", addr))?;
        let (local, domain) = (&addr[..at], &addr[at + 1..]);
        let address = Address::new(local, domain)
            .map_err(|e| anyhow!("Invalid email address '{}': {}", addr, e))?;
        Ok(Mailbox::new(None, address))
    }

    let from_mailbox = parse_address(from)?;
    let to_mailbox = parse_address(to)?;

    let builder = Message::builder()
        .from(from_mailbox)
        .to(to_mailbox)
        .subject(subject);

    let email = if attachments.is_empty() {
        builder
            .body(body.to_string())
            .map_err(|e| anyhow!("Failed to build email: {}", e))?
    } else {
        let mut multipart = MultiPart::mixed().singlepart(SinglePart::plain(body.to_string()));

        for att in attachments {
            let content_type = guess_content_type(&att.filename);
            let attachment = attachment_part(&att.filename, att.data.clone(), content_type);
            multipart = multipart.singlepart(attachment);
        }

        builder
            .multipart(multipart)
            .map_err(|e| anyhow!("Failed to build email: {}", e))?
    };

    let creds = Credentials::new(auth_user.to_string(), password.to_string());
    let mailer = match smtp_security {
        SecurityType::SslTls => SmtpTransport::relay(smtp_host)?
            .port(smtp_port)
            .credentials(creds)
            .build(),
        SecurityType::STARTTLS => SmtpTransport::starttls_relay(smtp_host)?
            .port(smtp_port)
            .credentials(creds)
            .build(),
        SecurityType::None => SmtpTransport::builder_dangerous(smtp_host)
            .port(smtp_port)
            .credentials(creds)
            .build(),
    };

    mailer.send(&email)?;
    Ok(())
}

pub fn send_structured_email_smtp(
    smtp_host: &str,
    smtp_port: u16,
    smtp_security: &SecurityType,
    auth_user: &str,
    password: &str,
    message: &StructuredEmail,
) -> Result<String> {
    use lettre::message::{MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let mut builder = Message::builder()
        .from(parse_mailbox(&message.from)?)
        .subject(&message.subject);
    for recipient in &message.to {
        builder = builder.to(parse_mailbox(recipient)?);
    }
    for recipient in &message.cc {
        builder = builder.cc(parse_mailbox(recipient)?);
    }
    for recipient in &message.bcc {
        builder = builder.bcc(parse_mailbox(recipient)?);
    }
    if let Some(reply_to) = &message.reply_to {
        builder = builder.reply_to(parse_mailbox(reply_to)?);
    }
    if let Some(in_reply_to) = &message.in_reply_to {
        builder = builder.in_reply_to(in_reply_to.clone());
    }
    if !message.references.is_empty() {
        builder = builder.references(message.references.join(" "));
    }

    let body = match &message.html_body {
        Some(html) => MultiPart::alternative()
            .singlepart(SinglePart::plain(message.text_body.clone()))
            .singlepart(SinglePart::html(html.clone())),
        None => MultiPart::alternative().singlepart(SinglePart::plain(message.text_body.clone())),
    };
    let content = if message.attachments.is_empty() {
        body
    } else {
        let mut mixed = MultiPart::mixed().multipart(body);
        for attachment in &message.attachments {
            let content_type = attachment
                .content_type
                .as_deref()
                .and_then(|value| lettre::message::header::ContentType::parse(value).ok())
                .unwrap_or_else(|| guess_content_type(&attachment.filename));
            mixed = mixed.singlepart(attachment_part(
                &attachment.filename,
                attachment.data.clone(),
                content_type,
            ));
        }
        mixed
    };
    let email = builder
        .multipart(content)
        .map_err(|error| anyhow!("Failed to build email: {error}"))?;
    let message_id = email
        .headers()
        .get_raw("Message-ID")
        .map(str::to_string)
        .unwrap_or_else(|| "generated".into());

    let credentials = Credentials::new(auth_user.to_string(), password.to_string());
    let mailer = match smtp_security {
        SecurityType::SslTls => SmtpTransport::relay(smtp_host)?
            .port(smtp_port)
            .credentials(credentials)
            .build(),
        SecurityType::STARTTLS => SmtpTransport::starttls_relay(smtp_host)?
            .port(smtp_port)
            .credentials(credentials)
            .build(),
        SecurityType::None => SmtpTransport::builder_dangerous(smtp_host)
            .port(smtp_port)
            .credentials(credentials)
            .build(),
    };
    mailer.send(&email)?;
    Ok(message_id)
}

fn parse_mailbox(address: &str) -> Result<lettre::message::Mailbox> {
    address
        .trim()
        .parse::<lettre::message::Mailbox>()
        .map_err(|_| anyhow!("Invalid structured email address"))
}

fn attachment_part(
    filename: &str,
    data: Vec<u8>,
    content_type: lettre::message::header::ContentType,
) -> lettre::message::SinglePart {
    use lettre::message::{SinglePart, header};

    SinglePart::builder()
        .header(header::ContentDisposition::attachment(filename))
        .header(content_type)
        .header(header::ContentTransferEncoding::Base64)
        .body(data)
}

fn guess_content_type(filename: &str) -> lettre::message::header::ContentType {
    use lettre::message::header::ContentType;
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "pdf" => ContentType::parse("application/pdf").unwrap(),
        "zip" => ContentType::parse("application/zip").unwrap(),
        "gz" | "gzip" => ContentType::parse("application/gzip").unwrap(),
        "tar" => ContentType::parse("application/x-tar").unwrap(),
        "jpg" | "jpeg" => ContentType::parse("image/jpeg").unwrap(),
        "png" => ContentType::parse("image/png").unwrap(),
        "gif" => ContentType::parse("image/gif").unwrap(),
        "webp" => ContentType::parse("image/webp").unwrap(),
        "svg" => ContentType::parse("image/svg+xml").unwrap(),
        "txt" => ContentType::parse("text/plain").unwrap(),
        "html" | "htm" => ContentType::parse("text/html").unwrap(),
        "css" => ContentType::parse("text/css").unwrap(),
        "js" => ContentType::parse("application/javascript").unwrap(),
        "json" => ContentType::parse("application/json").unwrap(),
        "xml" => ContentType::parse("application/xml").unwrap(),
        "csv" => ContentType::parse("text/csv").unwrap(),
        "doc" => ContentType::parse("application/msword").unwrap(),
        "docx" => ContentType::parse(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        .unwrap(),
        "xls" => ContentType::parse("application/vnd.ms-excel").unwrap(),
        "xlsx" => {
            ContentType::parse("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                .unwrap()
        }
        "ppt" => ContentType::parse("application/vnd.ms-powerpoint").unwrap(),
        "pptx" => ContentType::parse(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
        .unwrap(),
        "mp3" => ContentType::parse("audio/mpeg").unwrap(),
        "mp4" => ContentType::parse("video/mp4").unwrap(),
        "avi" => ContentType::parse("video/x-msvideo").unwrap(),
        _ => ContentType::parse("application/octet-stream").unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailparse::MailHeaderMap;

    #[test]
    fn attachment_part_round_trips_exact_bytes_even_for_text_media_type() {
        let expected = b"text attachment without a trailing newline".to_vec();
        let part = attachment_part(
            "evidence.txt",
            expected.clone(),
            lettre::message::header::ContentType::TEXT_PLAIN,
        );
        let formatted = part.formatted();
        let parsed = mailparse::parse_mail(&formatted).expect("parse MIME part");

        assert_eq!(parsed.get_body_raw().expect("decode attachment"), expected);
        assert_eq!(
            parsed
                .headers
                .get_first_value("Content-Transfer-Encoding")
                .as_deref(),
            Some("base64")
        );
    }
}
