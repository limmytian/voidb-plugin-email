//! Shared MIME parsing utilities for IMAP and POP3 clients.
//! Author: Limmy

use crate::types::Attachment;
use mailparse::DispositionType;

/// Extract text and HTML body parts from a parsed MIME message.
pub fn extract_body_parts(parsed: &mailparse::ParsedMail) -> (String, Option<String>) {
    let mut text = String::new();
    let mut html = None;

    if parsed.subparts.is_empty() {
        let ct = parsed.ctype.mimetype.to_lowercase();
        if let Ok(body) = parsed.get_body() {
            if ct.contains("html") {
                html = Some(body);
            } else {
                text = body;
            }
        }
    } else {
        for part in &parsed.subparts {
            let (t, h) = extract_body_parts(part);
            if !t.is_empty() && text.is_empty() {
                text = t;
            }
            if h.is_some() && html.is_none() {
                html = h;
            }
        }
    }
    (text, html)
}

/// Extract attachments from a parsed MIME message.
pub fn extract_attachments(parsed: &mailparse::ParsedMail) -> Vec<Attachment> {
    let mut attachments = Vec::new();
    collect_attachments(parsed, &mut attachments);
    attachments
}

fn collect_attachments(parsed: &mailparse::ParsedMail, out: &mut Vec<Attachment>) {
    if parsed.subparts.is_empty() {
        let disposition = parsed.get_content_disposition();
        let mime = parsed.ctype.mimetype.to_lowercase();

        let is_attachment = disposition.disposition == DispositionType::Attachment
            || (mime != "text/plain"
                && mime != "text/html"
                && !mime.starts_with("multipart/")
                && (disposition.params.contains_key("filename")
                    || parsed.ctype.params.contains_key("name")));

        if is_attachment {
            let filename = disposition
                .params
                .get("filename")
                .or_else(|| parsed.ctype.params.get("name"))
                .cloned()
                .unwrap_or_else(|| "unnamed_attachment".into());
            let data = parsed.get_body_raw().unwrap_or_default();
            let size = data.len();
            out.push(Attachment {
                filename,
                content_type: mime,
                size,
                data,
            });
        }
    } else {
        for part in &parsed.subparts {
            collect_attachments(part, out);
        }
    }
}
