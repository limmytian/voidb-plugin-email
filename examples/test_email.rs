//! Simple test program for email service capabilities
//! Usage: cargo run -p voidb-plugin-email --example test_email

use voidb_core::config::AppConfig;
use voidb_plugin_email::EmailConfig;

fn main() -> anyhow::Result<()> {
    // Load config (auto-decrypts)
    let config = AppConfig::load().expect("Failed to load config");

    // Find the 126 email connection
    let conn = config
        .connections
        .iter()
        .find(|c| c.name == "126")
        .expect("No '126' connection found in config");

    let email_config: EmailConfig = conn
        .plugin_config
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .expect("Failed to parse email config");

    println!("=== Email Connection Config ===");
    println!("  Email:            {}", email_config.email);
    println!("  Protocol:         {}", email_config.protocol.as_str());
    println!("  Receive Server:   {}:{}", email_config.receive.host, email_config.receive.port);
    println!("  Receive Security: {}", email_config.receive_security.as_str());
    println!("  SMTP Server:      {}:{}", email_config.smtp.host, email_config.smtp.port);
    println!("  SMTP Security:    {}", email_config.smtp_security.as_str());
    println!();

    // --- Test 1: IMAP connection & list folders ---
    println!("=== Test 1: IMAP Connect & List Folders ===");
    let security = email_config.receive_security;
    match voidb_plugin_email::imap_client_connect(
        &email_config.receive.host,
        email_config.receive.port,
        &email_config.email,
        &email_config.password,
        security,
    ) {
        Ok(mut client) => {
            println!("  [OK] Connected to IMAP server");

            match client.list_folders() {
                Ok(folders) => {
                    println!("  [OK] {} folders found:", folders.len());
                    for f in &folders {
                        println!(
                            "        {} [{}] (total: {}, unread: {})",
                            f.display_name, f.name, f.message_count, f.unread_count
                        );
                    }
                    println!();

                    // --- Test 2: List messages in INBOX with pagination ---
                    println!("=== Test 2: List Messages in INBOX (paginated) ===");
                    let inbox = folders.iter().find(|f| f.name.eq_ignore_ascii_case("INBOX"));
                    if inbox.is_some() {
                        client.logout();
                        let mut client2 = voidb_plugin_email::imap_client_connect(
                            &email_config.receive.host,
                            email_config.receive.port,
                            &email_config.email,
                            &email_config.password,
                            security,
                        )?;

                        // Page 0 (newest 50)
                        match client2.list_messages("INBOX", 0, 50) {
                            Ok((msgs, total)) => {
                                let total_pages = total.div_ceil(50);
                                println!("  [OK] Total: {} messages, {} pages", total, total_pages);
                                println!("  Page 1: {} messages loaded", msgs.len());

                                let mut seen_count = 0;
                                let mut unseen_count = 0;
                                for msg in &msgs {
                                    if msg.seen { seen_count += 1; } else { unseen_count += 1; }
                                }
                                println!("  Page 1 seen/unseen: {}/{}", seen_count, unseen_count);
                                println!();

                                // Show first 5 messages
                                println!("  First 5 messages:");
                                for msg in msgs.iter().take(5) {
                                    let flag = if msg.seen { " " } else { "N" };
                                    println!(
                                        "    [{}] seq={} | {} | {} | {}",
                                        flag, msg.uid, msg.date, msg.from, msg.subject
                                    );
                                }

                                // If there are more pages, test page 2
                                if total_pages > 1 {
                                    println!();
                                    println!("  --- Loading page 2 ---");
                                    client2.logout();
                                    let mut client2b = voidb_plugin_email::imap_client_connect(
                                        &email_config.receive.host,
                                        email_config.receive.port,
                                        &email_config.email,
                                        &email_config.password,
                                        security,
                                    )?;
                                    match client2b.list_messages("INBOX", 1, 50) {
                                        Ok((msgs2, _)) => {
                                            println!("  Page 2: {} messages loaded", msgs2.len());
                                            for msg in msgs2.iter().take(3) {
                                                let flag = if msg.seen { " " } else { "N" };
                                                println!(
                                                    "    [{}] seq={} | {} | {} | {}",
                                                    flag, msg.uid, msg.date, msg.from, msg.subject
                                                );
                                            }
                                        }
                                        Err(e) => println!("  [FAIL] Page 2: {}", e),
                                    }
                                    client2b.logout();
                                } else {
                                    // --- Test 3: Fetch body ---
                                    if let Some(first) = msgs.first() {
                                        println!();
                                        println!("=== Test 3: Fetch Message Body (seq={}) ===", first.uid);
                                        client2.logout();
                                        let mut client3 = voidb_plugin_email::imap_client_connect(
                                            &email_config.receive.host,
                                            email_config.receive.port,
                                            &email_config.email,
                                            &email_config.password,
                                            security,
                                        )?;

                                        match client3.fetch_body("INBOX", first.uid) {
                                            Ok(body) => {
                                                println!("  [OK] From:    {}", body.from);
                                                println!("       To:      {}", body.to.join(", "));
                                                println!("       Subject: {}", body.subject);
                                                println!("       Date:    {}", body.date);
                                                let preview: String = body.text.chars().take(200).collect();
                                                println!("       Body:    {}...", preview.replace('\n', " "));
                                                println!("       Has HTML: {}", body.html.is_some());
                                            }
                                            Err(e) => println!("  [FAIL] Fetch body: {}", e),
                                        }
                                        client3.logout();
                                    } else {
                                        client2.logout();
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  [FAIL] List messages: {}", e);
                                client2.logout();
                            }
                        }
                    } else {
                        println!("  [SKIP] No INBOX folder found");
                        client.logout();
                    }
                }
                Err(e) => {
                    println!("  [FAIL] List folders: {}", e);
                    client.logout();
                }
            }
        }
        Err(e) => println!("  [FAIL] IMAP connection: {}", e),
    }

    println!();
    println!("=== All tests complete ===");
    Ok(())
}
