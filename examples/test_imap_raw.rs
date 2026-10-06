//! Raw IMAP diagnostic - check server-side message limits
//! Usage: cargo run -p voidb-plugin-email --example test_imap_raw

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> anyhow::Result<()> {
    let config = voidb_core::config::AppConfig::load()?;
    let conn = config.connections.iter().find(|c| c.name == "126").expect("No '126' connection");
    let email_config: voidb_plugin_email::EmailConfig = conn
        .plugin_config.as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .expect("Failed to parse email config");

    let host = &email_config.receive.host;
    let port = email_config.receive.port;
    let user = &email_config.email;
    let pass = &email_config.password;

    println!("Connecting to {}:{}...", host, port);

    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tcp = TcpStream::connect((host.as_str(), port))?;
    let mut stream = tls.connect(host, tcp)?;

    // Helper to read one line
    let read_line = |s: &mut native_tls::TlsStream<TcpStream>| -> String {
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            if s.read(&mut byte).unwrap_or(0) == 0 { break; }
            buf.push(byte[0]);
            if byte[0] == b'\n' { break; }
        }
        String::from_utf8_lossy(&buf).trim().to_string()
    };

    // Helper to read all lines until tagged response
    let read_until_tag = |s: &mut native_tls::TlsStream<TcpStream>, tag: &str| -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let mut buf = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                if s.read(&mut byte).unwrap_or(0) == 0 { break; }
                buf.push(byte[0]);
                if byte[0] == b'\n' { break; }
            }
            let line = String::from_utf8_lossy(&buf).trim().to_string();
            let done = line.starts_with(tag);
            lines.push(line);
            if done { break; }
        }
        lines
    };

    // Read greeting
    let greeting = read_line(&mut stream);
    println!("S: {}", greeting);

    // ID command
    let cmd = b"A0 ID (\"name\" \"voidb\" \"version\" \"1.0\")\r\n";
    stream.write_all(cmd)?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A0 ") {
        println!("S: {}", line);
    }

    // LOGIN
    let login = format!("A1 LOGIN {} {}\r\n", user, pass);
    stream.write_all(login.as_bytes())?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A1 ") {
        println!("S: {}", line);
    }

    // SELECT INBOX - see EXISTS, RECENT, UIDNEXT, UIDVALIDITY
    println!("\n=== SELECT INBOX ===");
    stream.write_all(b"A2 SELECT INBOX\r\n")?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A2 ") {
        println!("S: {}", line);
    }

    // SEARCH ALL - how many messages does the server actually expose?
    println!("\n=== SEARCH ALL ===");
    stream.write_all(b"A3 SEARCH ALL\r\n")?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A3 ") {
        if line.starts_with("* SEARCH") {
            let count = line.split_whitespace().count() - 2; // "* SEARCH" + seq nums
            println!("S: {} ({} results)", line.chars().take(80).collect::<String>(), count);
        } else {
            println!("S: {}", line);
        }
    }

    // SEARCH UNSEEN
    println!("\n=== SEARCH UNSEEN ===");
    stream.write_all(b"A4 SEARCH UNSEEN\r\n")?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A4 ") {
        println!("S: {}", line);
    }

    // FETCH first and last message FLAGS to verify
    println!("\n=== FETCH 1 FLAGS (oldest) ===");
    stream.write_all(b"A5 FETCH 1 FLAGS\r\n")?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A5 ") {
        println!("S: {}", line);
    }

    println!("\n=== FETCH 58 FLAGS (newest-ish) ===");
    stream.write_all(b"A6 FETCH 58 FLAGS\r\n")?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A6 ") {
        println!("S: {}", line);
    }

    // STATUS INBOX (MESSAGES UNSEEN) - alternative count
    println!("\n=== STATUS INBOX ===");
    stream.write_all(b"A7 STATUS INBOX (MESSAGES UNSEEN UIDNEXT)\r\n")?;
    stream.flush()?;
    for line in read_until_tag(&mut stream, "A7 ") {
        println!("S: {}", line);
    }

    // LOGOUT
    stream.write_all(b"A8 LOGOUT\r\n")?;
    stream.flush()?;

    println!("\n=== Done ===");
    Ok(())
}
