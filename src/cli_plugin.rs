use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};
use std::fs;
use voidb_core::VoidbError;
use voidb_core::plugin::cli::{CliContext, CliPlugin};

use crate::config::EmailConfig;
use crate::service::EmailService;
use crate::tui::{
    EmailTuiLaunch, EmailTuiSource, build_email_tui_evidence, run_email_tui,
    write_email_tui_preflight,
};

pub struct EmailCliPlugin;

pub fn create_email_cli_plugin() -> Box<dyn CliPlugin> {
    Box::new(EmailCliPlugin)
}

#[async_trait]
impl CliPlugin for EmailCliPlugin {
    fn plugin_id(&self) -> &str {
        "email"
    }

    fn name(&self) -> &str {
        "Email"
    }

    fn commands(&self) -> Vec<Command> {
        let conn_arg = Arg::new("connection")
            .short('c')
            .long("connection")
            .required(true)
            .help("Connection name");

        vec![
            Command::new("folders")
                .about("List email folders")
                .arg(conn_arg.clone()),
            Command::new("list")
                .about("List messages in a folder")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("folder")
                        .default_value("INBOX")
                        .help("Folder name"),
                )
                .arg(
                    Arg::new("page")
                        .short('p')
                        .long("page")
                        .default_value("0")
                        .help("Page number (0 = newest)"),
                )
                .arg(
                    Arg::new("limit")
                        .short('n')
                        .long("limit")
                        .default_value("20")
                        .help("Messages per page"),
                )
                .arg(
                    Arg::new("unread")
                        .short('u')
                        .long("unread")
                        .action(clap::ArgAction::SetTrue)
                        .help("Show only unread messages"),
                ),
            Command::new("read")
                .about("Read a message")
                .arg(conn_arg.clone())
                .arg(Arg::new("folder").required(true).help("Folder name"))
                .arg(
                    Arg::new("uid")
                        .required(true)
                        .value_parser(clap::value_parser!(u32))
                        .help("Message UID"),
                ),
            Command::new("delete")
                .about("Delete a message")
                .arg(conn_arg)
                .arg(Arg::new("folder").required(true).help("Folder name"))
                .arg(
                    Arg::new("uid")
                        .required(true)
                        .value_parser(clap::value_parser!(u32))
                        .help("Message UID"),
                ),
            Command::new("tui")
                .about("Launch the standalone Email TUI")
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .value_name("PROFILE")
                        .conflicts_with("connection")
                        .help("Profile name, id:<uuid>, or name:<name>"),
                )
                .arg(
                    Arg::new("connection")
                        .short('c')
                        .long("connection")
                        .value_name("CONNECTION")
                        .conflicts_with("profile")
                        .help("Legacy connection name"),
                )
                .arg(
                    Arg::new("fixture").long("fixture").value_name("PATH").help(
                        "Load deterministic mailbox fixture JSON instead of opening a target",
                    ),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["json"])
                        .help("Emit secret-free preflight JSON and exit"),
                )
                .arg(
                    Arg::new("evidence")
                        .long("evidence")
                        .value_name("PATH")
                        .help("Write fixture-backed standalone Email TUI evidence JSON and exit"),
                ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "folders" => self.handle_folders(matches, ctx).await,
            "list" => self.handle_list(matches, ctx).await,
            "read" => self.handle_read(matches, ctx).await,
            "delete" => self.handle_delete(matches, ctx).await,
            "tui" => self.handle_tui(matches, ctx).await,
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

impl EmailCliPlugin {
    fn parse_config(conn_name: &str, ctx: &CliContext) -> Result<EmailConfig, VoidbError> {
        let config = ctx
            .find_connection(conn_name)
            .ok_or_else(|| VoidbError::Plugin(format!("Connection '{}' not found", conn_name)))?;

        if config.effective_plugin_id() != "email" {
            return Err(VoidbError::Plugin(format!(
                "Connection '{}' is not an email connection (plugin: {})",
                conn_name,
                config.effective_plugin_id()
            )));
        }

        config
            .plugin_config
            .as_ref()
            .ok_or_else(|| VoidbError::Connection("Missing plugin_config".to_string()))
            .and_then(|pc| {
                serde_json::from_value(pc.clone())
                    .map_err(|e| VoidbError::Connection(format!("Invalid email config: {}", e)))
            })
    }

    fn parse_tui_launch(
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<EmailTuiLaunch, VoidbError> {
        let fixture_path = matches.get_one::<String>("fixture").cloned();

        if let Some(profile_ref) = matches.get_one::<String>("profile") {
            let (profile, connection) =
                ctx.resolve_profile_connection(profile_ref, Some("email"))?;
            let config = connection
                .plugin_config
                .as_ref()
                .ok_or_else(|| VoidbError::Connection("Missing plugin_config".to_string()))
                .and_then(|pc| {
                    serde_json::from_value(pc.clone())
                        .map_err(|e| VoidbError::Connection(format!("Invalid email config: {}", e)))
                })?;
            return Ok(EmailTuiLaunch {
                profile_label: profile.name,
                config: Some(config),
                source: EmailTuiSource::Profile,
                fixture_path,
            });
        }

        if let Some(conn_name) = matches.get_one::<String>("connection") {
            return Ok(EmailTuiLaunch {
                profile_label: conn_name.clone(),
                config: Some(Self::parse_config(conn_name, ctx)?),
                source: EmailTuiSource::Connection,
                fixture_path,
            });
        }

        if fixture_path.is_some() {
            return Ok(EmailTuiLaunch {
                profile_label: "fixture".to_string(),
                config: None,
                source: EmailTuiSource::Fixture,
                fixture_path,
            });
        }

        Err(VoidbError::Plugin(
            "email tui requires --profile, --connection, or --fixture".to_string(),
        ))
    }

    /// Create a connected EmailService for direct CLI use.
    ///
    /// Constructs the service, sends Connect, and waits for confirmation.
    async fn connect_service(email_config: EmailConfig) -> Result<EmailService, VoidbError> {
        let mut svc = EmailService::new_direct()
            .map_err(|e| VoidbError::Plugin(format!("Failed to create email service: {}", e)))?;

        svc.connect_direct(email_config)
            .await
            .map_err(|e| VoidbError::Connection(e.to_string()))?;

        Ok(svc)
    }

    async fn handle_folders(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap().clone();
        let email_config = Self::parse_config(&conn_name, ctx)?;

        let mut svc = Self::connect_service(email_config).await?;

        let folders = svc
            .list_folders_direct()
            .await
            .map_err(|e| VoidbError::Plugin(format!("{}", e)))?;

        println!("{:<40} {:>8} {:>8}", "FOLDER", "TOTAL", "UNREAD");
        println!("{}", "-".repeat(56));
        for folder in folders {
            println!(
                "{:<40} {:>8} {:>8}",
                folder.display_name, folder.message_count, folder.unread_count
            );
        }
        Ok(())
    }

    async fn handle_list(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap().clone();
        let folder = matches.get_one::<String>("folder").unwrap().clone();
        let page: u32 = matches
            .get_one::<String>("page")
            .unwrap()
            .parse()
            .map_err(|_| VoidbError::Plugin("Invalid page number".to_string()))?;
        let limit: u32 = matches
            .get_one::<String>("limit")
            .unwrap()
            .parse()
            .map_err(|_| VoidbError::Plugin("Invalid limit".to_string()))?;
        let unread = matches.get_flag("unread");

        let email_config = Self::parse_config(&conn_name, ctx)?;
        let mut svc = Self::connect_service(email_config).await?;

        let (messages, total) = if unread {
            svc.list_unseen_messages_direct(folder, page, limit)
                .await
                .map_err(|e| VoidbError::Plugin(format!("{}", e)))?
        } else {
            svc.list_messages_direct(folder, page, limit)
                .await
                .map_err(|e| VoidbError::Plugin(format!("{}", e)))?
        };

        println!(
            "{:>6} {:<1} {:<25} {:<50} DATE",
            "UID", "", "FROM", "SUBJECT"
        );
        println!("{}", "-".repeat(100));
        for msg in &messages {
            let flag = if msg.seen { " " } else { "*" };
            let subject = if msg.subject.len() > 48 {
                format!("{}...", &msg.subject[..45])
            } else {
                msg.subject.clone()
            };
            let from = if msg.from.len() > 23 {
                format!("{}...", &msg.from[..20])
            } else {
                msg.from.clone()
            };
            println!(
                "{:>6} {:<1} {:<25} {:<50} {}",
                msg.uid, flag, from, subject, msg.date
            );
        }
        eprintln!("({} messages, {} total)", messages.len(), total);
        Ok(())
    }

    async fn handle_read(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap().clone();
        let folder = matches.get_one::<String>("folder").unwrap().clone();
        let uid = *matches.get_one::<u32>("uid").unwrap();

        let email_config = Self::parse_config(&conn_name, ctx)?;
        let mut svc = Self::connect_service(email_config).await?;

        let body = svc
            .fetch_body_direct(folder, uid)
            .await
            .map_err(|e| VoidbError::Plugin(format!("{}", e)))?;

        println!("From:    {}", body.from);
        println!("To:      {}", body.to.join(", "));
        if !body.cc.is_empty() {
            println!("Cc:      {}", body.cc.join(", "));
        }
        println!("Subject: {}", body.subject);
        println!("Date:    {}", body.date);

        if !body.attachments.is_empty() {
            println!("Attachments:");
            for (i, att) in body.attachments.iter().enumerate() {
                println!(
                    "  [{}] {} ({}, {} bytes)",
                    i, att.filename, att.content_type, att.size
                );
            }
        }

        println!("\n{}", "-".repeat(60));
        println!("{}", body.text);
        Ok(())
    }

    async fn handle_delete(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap().clone();
        let folder = matches.get_one::<String>("folder").unwrap().clone();
        let uid = *matches.get_one::<u32>("uid").unwrap();

        let email_config = Self::parse_config(&conn_name, ctx)?;
        let mut svc = Self::connect_service(email_config).await?;

        svc.delete_message_direct(folder.clone(), uid)
            .await
            .map_err(|e| VoidbError::Plugin(format!("{}", e)))?;

        println!("Message {} deleted from {}", uid, folder);
        Ok(())
    }

    async fn handle_tui(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let launch = Self::parse_tui_launch(matches, ctx)?;
        if let Some(path) = matches.get_one::<String>("evidence") {
            let evidence = build_email_tui_evidence(&launch)
                .map_err(|e| VoidbError::Plugin(format!("Email TUI evidence failed: {}", e)))?;
            let rendered = serde_json::to_string_pretty(&evidence).map_err(|e| {
                VoidbError::Plugin(format!("Email TUI evidence serialization failed: {}", e))
            })?;
            if let Some(parent) = std::path::Path::new(path).parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|e| {
                    VoidbError::Plugin(format!(
                        "Failed to create Email TUI evidence directory '{}': {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            fs::write(path, rendered).map_err(|e| {
                VoidbError::Plugin(format!(
                    "Failed to write Email TUI evidence '{}': {}",
                    path, e
                ))
            })?;
            println!("Wrote Email TUI evidence to {path}");
            return Ok(());
        }

        if matches
            .get_one::<String>("format")
            .is_some_and(|format| format == "json")
        {
            write_email_tui_preflight(&launch)
                .map_err(|e| VoidbError::Plugin(format!("Email TUI preflight failed: {}", e)))?;
            return Ok(());
        }

        run_email_tui(launch)
            .await
            .map_err(|e| VoidbError::Plugin(format!("Email TUI failed: {}", e)))
    }
}
