//! Debug tool: fetch a specific email via IMAP and dump MIME structure + HTML previews.
//! Reads IMAP credentials from voidb encrypted config automatically.
//! Usage: cargo run --package voidb-plugin-email --example debug_email -- <subject_keyword>

use anyhow::{anyhow, Result};
use std::io::{Cursor, Read, Write};
use voidb_core::config::AppConfig;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <subject_keyword>", args[0]);
        std::process::exit(1);
    }
    let keyword = &args[1];

    // Load credentials from voidb encrypted config
    let config = AppConfig::load_with_password(None)
        .map_err(|e| anyhow!("Failed to load config: {}", e))?;

    let conn = config.connections.iter()
        .find(|c| c.plugin_id.as_deref() == Some("email"))
        .ok_or_else(|| anyhow!("No email connection found in config"))?;

    let plugin_config = conn.plugin_config.as_ref()
        .ok_or_else(|| anyhow!("No plugin_config in email connection"))?;

    let email_config: serde_json::Value = plugin_config.clone();
    let host = email_config["receive"]["host"].as_str()
        .ok_or_else(|| anyhow!("No receive.host in config"))?;
    let port = email_config["receive"]["port"].as_u64()
        .ok_or_else(|| anyhow!("No receive.port in config"))? as u16;
    let user = email_config["email"].as_str()
        .ok_or_else(|| anyhow!("No email in config"))?;
    let pass = email_config["password"].as_str()
        .ok_or_else(|| anyhow!("No password in config"))?;

    println!("Connecting to {}:{} as {}...", host, port, user);

    // Connect with TLS
    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tcp = std::net::TcpStream::connect((host, port))?;
    let mut tls_stream = tls_connector.connect(host, tcp)?;

    // Raw ID handshake (for 126/163 servers)
    raw_id_handshake(&mut tls_stream)?;

    // Wrap with fake greeting for imap crate
    let wrapped = GreetingPrefixStream {
        prefix: Cursor::new(b"* OK ready\r\n".to_vec()),
        inner: tls_stream,
    };
    let mut client = imap::Client::new(wrapped);
    client.read_greeting()?;
    let mut session = client.login(user, pass)
        .map_err(|e| anyhow!("Login failed: {}", e.0))?;

    session.select("INBOX")?;

    // Search for the email by subject
    let search_query = format!("SUBJECT \"{}\"", keyword);
    let uids = session.uid_search(&search_query)?;
    println!("Found {} message(s) matching '{}'", uids.len(), keyword);

    if uids.is_empty() {
        println!("No messages found.");
        session.logout()?;
        return Ok(());
    }

    // Fetch the first match
    let uid = *uids.iter().next().unwrap();
    println!("Fetching UID {}...\n", uid);

    let fetches = session.uid_fetch(uid.to_string(), "BODY[]")?;
    let fetch = fetches.iter().next().ok_or_else(|| anyhow!("No fetch result"))?;
    let body_raw = fetch.body().ok_or_else(|| anyhow!("No body"))?;

    println!("=== RAW SIZE: {} bytes ===\n", body_raw.len());

    // Parse with mailparse
    let parsed = mailparse::parse_mail(body_raw)?;

    // Dump MIME structure
    println!("=== MIME STRUCTURE ===");
    dump_mime(&parsed, 0);

    // Extract body parts
    let (text, html) = extract_body_parts(&parsed);
    println!("\n=== PLAIN TEXT ({} chars) ===", text.len());
    if text.len() > 500 {
        println!("{}...(truncated)", &text[..500]);
    } else if text.is_empty() {
        println!("(empty)");
    } else {
        println!("{}", text);
    }

    println!("\n=== HTML ({} chars) ===", html.as_ref().map(|h| h.len()).unwrap_or(0));
    if let Some(ref h) = html {
        // Show first 2000 chars of HTML
        if h.len() > 2000 {
            println!("{}...(truncated)", &h[..2000]);
        } else {
            println!("{}", h);
        }
    } else {
        println!("(none)");
    }

    // Count <img> tags in HTML
    if let Some(ref h) = html {
        let img_count = h.to_lowercase().matches("<img").count();
        println!("\n=== IMG TAGS: {} ===", img_count);

        // Show each <img> tag's src
        let lower = h.to_lowercase();
        let mut pos = 0;
        let mut idx = 0;
        while let Some(start) = lower[pos..].find("<img") {
            let abs_start = pos + start;
            let tag_end = h[abs_start..].find('>').map(|i| abs_start + i + 1).unwrap_or(h.len());
            let tag = &h[abs_start..tag_end];
            idx += 1;
            let src = extract_attr(tag, "src").unwrap_or_else(|| "(no src)".into());
            let src_short = if src.len() > 120 { format!("{}...", &src[..120]) } else { src };
            println!("  img#{}: src={}", idx, src_short);
            pos = tag_end;
        }
    }

    // Run img_to_link preprocessing
    if let Some(ref h) = html {
        let processed = img_to_link(h);
        println!("\n=== AFTER img_to_link ({} chars) ===", processed.len());
        println!("  Original HTML: {} chars", h.len());
        println!("  Processed:     {} chars", processed.len());

        // Also show a snippet of the processed HTML around any <a href> we injected
        let mut search_pos = 0;
        let mut link_idx = 0;
        while let Some(found) = processed[search_pos..].find("<a href=") {
            let abs = search_pos + found;
            let snippet_end = processed[abs..].find("</a>").map(|i| abs + i + 4).unwrap_or((abs + 200).min(processed.len()));
            link_idx += 1;
            println!("  injected_link#{}: {}", link_idx, &processed[abs..snippet_end]);
            search_pos = snippet_end;
            if link_idx >= 20 { break; }
        }

        // Plaintext preview without pulling UI-only conversion dependencies into
        // the service crate.
        let text_out = html_preview_text(&processed, 120);
        println!("\n=== HTML TEXT PREVIEW ({} chars, width=120) ===", text_out.len());

        // Show the full output but limit to 5000 chars
        if text_out.len() > 5000 {
            println!("{}...(truncated)", &text_out[..5000]);
        } else {
            println!("{}", text_out);
        }

        // Count blank lines
        let blank_lines = text_out.lines().filter(|l| l.trim().is_empty()).count();
        let total_lines = text_out.lines().count();
        println!("\n=== STATS: {} total lines, {} blank lines ({:.0}% blank) ===",
            total_lines, blank_lines, blank_lines as f64 / total_lines.max(1) as f64 * 100.0);

        // Check for extremely long lines (could cause ratatui rendering issues)
        let max_line_len = text_out.lines().map(|l| l.len()).max().unwrap_or(0);
        let lines_over_200 = text_out.lines().filter(|l| l.len() > 200).count();
        println!("  Max line length: {} chars", max_line_len);
        println!("  Lines over 200 chars: {}", lines_over_200);

        // Check for unusual characters that might break terminal rendering
        let control_chars = text_out.chars().filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t').count();
        println!("  Control characters (non-newline/tab): {}", control_chars);

        // Also test with raw HTML (no img_to_link) to compare
        println!("\n=== RAW HTML TEXT PREVIEW (no preprocessing, width=120) ===");
        let raw_out = html_preview_text(h, 120);
        let raw_lines = raw_out.lines().count();
        let raw_blank = raw_out.lines().filter(|l| l.trim().is_empty()).count();
        let raw_max_line = raw_out.lines().map(|l| l.len()).max().unwrap_or(0);
        println!("  {} total lines, {} blank ({:.0}%), max line {} chars",
            raw_lines, raw_blank, raw_blank as f64 / raw_lines.max(1) as f64 * 100.0, raw_max_line);
        if raw_out.len() > 5000 {
            println!("{}...(truncated)", &raw_out[..5000]);
        } else {
            println!("{}", raw_out);
        }
    }

    session.logout()?;
    Ok(())
}

fn dump_mime(parsed: &mailparse::ParsedMail, depth: usize) {
    let indent = "  ".repeat(depth);
    let mime = &parsed.ctype.mimetype;
    let disposition = parsed.get_content_disposition();
    let filename = disposition.params.get("filename")
        .or_else(|| parsed.ctype.params.get("name"))
        .map(|s| s.as_str())
        .unwrap_or("");
    let cid = parsed.headers.iter()
        .find(|h| h.get_key_ref().eq_ignore_ascii_case("Content-ID"))
        .map(|h| h.get_value())
        .unwrap_or_default();

    let body_len = parsed.get_body_raw().map(|b| b.len()).unwrap_or(0);
    println!("{}[{}] disp={:?} filename='{}' cid='{}' body={}B",
        indent, mime, disposition.disposition, filename, cid, body_len);

    for sub in &parsed.subparts {
        dump_mime(sub, depth + 1);
    }
}

fn extract_body_parts(parsed: &mailparse::ParsedMail) -> (String, Option<String>) {
    let mut text = String::new();
    let mut html = None;
    if parsed.subparts.is_empty() {
        let ct = parsed.ctype.mimetype.to_lowercase();
        if let Ok(body) = parsed.get_body() {
            if ct.contains("html") { html = Some(body); } else { text = body; }
        }
    } else {
        for part in &parsed.subparts {
            let (t, h) = extract_body_parts(part);
            if !t.is_empty() && text.is_empty() { text = t; }
            if h.is_some() && html.is_none() { html = h; }
        }
    }
    (text, html)
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let patterns = [format!("{}=\"", attr), format!("{}='", attr)];
    for pat in &patterns {
        if let Some(pos) = tag.to_lowercase().find(&pat.to_lowercase()) {
            let value_start = pos + pat.len();
            let quote = tag.as_bytes()[value_start - 1] as char;
            if let Some(end) = tag[value_start..].find(quote) {
                return Some(tag[value_start..value_start + end].to_string());
            }
        }
    }
    None
}

fn img_to_link(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut remaining = html;
    let mut in_anchor = false;

    while !remaining.is_empty() {
        if let Some(pos) = remaining.find('<') {
            result.push_str(&remaining[..pos]);
            remaining = &remaining[pos..];

            let lower = remaining.to_ascii_lowercase();
            if lower.starts_with("<a ") || lower.starts_with("<a>") {
                in_anchor = true;
                if let Some(end) = remaining.find('>') {
                    result.push_str(&remaining[..end + 1]);
                    remaining = &remaining[end + 1..];
                } else {
                    result.push_str(remaining);
                    break;
                }
            } else if lower.starts_with("</a") {
                in_anchor = false;
                if let Some(end) = remaining.find('>') {
                    result.push_str(&remaining[..end + 1]);
                    remaining = &remaining[end + 1..];
                } else {
                    result.push_str(remaining);
                    break;
                }
            } else if lower.starts_with("<img") {
                let end = remaining.find('>')
                    .map(|i| i + 1)
                    .unwrap_or(remaining.len());
                let tag = &remaining[..end];

                let label = extract_attr(tag, "alt")
                    .filter(|a| !a.is_empty())
                    .unwrap_or_else(|| "Image".to_string());

                if let Some(src) = extract_attr(tag, "src") {
                    if src.starts_with("cid:") || src.starts_with("data:") {
                        // cid/data: silently dropped
                    } else if in_anchor {
                        result.push_str(&format!("[{}]", label));
                    } else {
                        result.push_str(&format!("<a href=\"{}\">[{}]</a>", src, label));
                    }
                }

                remaining = &remaining[end..];
            } else {
                if let Some(end) = remaining.find('>') {
                    result.push_str(&remaining[..end + 1]);
                    remaining = &remaining[end + 1..];
                } else {
                    result.push_str(remaining);
                    break;
                }
            }
        } else {
            result.push_str(remaining);
            break;
        }
    }
    result
}

fn html_preview_text(html: &str, width: usize) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut last_was_space = false;

    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                push_preview_space(&mut text, &mut last_was_space);
            }
            '>' => in_tag = false,
            _ if in_tag => {}
            _ if ch.is_whitespace() => push_preview_space(&mut text, &mut last_was_space),
            _ => {
                text.push(ch);
                last_was_space = false;
            }
        }
    }

    wrap_preview_text(&decode_basic_html_entities(text.trim()), width)
}

fn push_preview_space(text: &mut String, last_was_space: &mut bool) {
    if !*last_was_space && !text.is_empty() {
        text.push(' ');
        *last_was_space = true;
    }
}

fn decode_basic_html_entities(input: &str) -> String {
    input
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn wrap_preview_text(text: &str, width: usize) -> String {
    let mut out = String::with_capacity(text.len());
    let mut line_len = 0usize;

    for word in text.split_whitespace() {
        let word_len = word.len();
        if line_len > 0 && line_len + 1 + word_len > width {
            out.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word_len;
    }

    out
}

struct GreetingPrefixStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S: Read> Read for GreetingPrefixStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.prefix.get_ref().len() as u64 - self.prefix.position();
        if remaining > 0 { return self.prefix.read(buf); }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for GreetingPrefixStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.inner.write(buf) }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush() }
}

fn raw_id_handshake<S: Read + Write>(stream: &mut S) -> Result<()> {
    let mut buf = [0u8; 1];
    let mut line = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 { return Err(anyhow!("Connection closed")); }
        line.push(buf[0]);
        if buf[0] == b'\n' { break; }
    }
    let cmd = b"X0 ID (\"name\" \"voidb\" \"version\" \"1.0\")\r\n";
    stream.write_all(cmd)?;
    stream.flush()?;
    loop {
        line.clear();
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 { return Err(anyhow!("Connection closed")); }
            line.push(buf[0]);
            if buf[0] == b'\n' { break; }
        }
        if String::from_utf8_lossy(&line).starts_with("X0 ") { break; }
    }
    Ok(())
}
