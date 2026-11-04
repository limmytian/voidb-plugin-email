use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use voidb_core::retained_tui_quality_gate;

use crate::config::{EmailConfig, EmailProtocol, SecurityType};
use crate::service::EmailService;
use crate::types::{EmailBody, EmailEnvelope, EmailFolder};

const PAGE_SIZE: u32 = 25;
const PAGE_STEP: isize = 10;
/// The key-hint footer is persistent and sized to stay on one line at
/// ~120-column terminals.
const BROWSER_HINTS: &str = "email: j/k PgUp/PgDn | / filter | F folders | Enter read | a attach | c compose | r reply | ! diag | ? help | q quit";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailTuiSource {
    Profile,
    Connection,
    Fixture,
}

#[derive(Debug, Clone)]
pub struct EmailTuiLaunch {
    pub profile_label: String,
    pub config: Option<EmailConfig>,
    pub source: EmailTuiSource,
    pub fixture_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailTuiFixture {
    folders: Vec<EmailFolder>,
    messages: Vec<EmailEnvelope>,
    bodies: Vec<EmailBody>,
    diagnostics: Option<String>,
    #[serde(default)]
    redact_bodies: bool,
}

#[derive(Debug, Clone)]
struct MailboxData {
    folders: Vec<EmailFolder>,
    messages: Vec<EmailEnvelope>,
    bodies: Vec<EmailBody>,
    diagnostics: String,
    redact_transcript_text: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Browser,
    Filter,
    Compose,
    SendConfirm,
    DiscardConfirm,
}

/// Full-screen or popup surfaces stacked on top of the browser. Input is
/// routed to the active overlay first, so each surface owns its key space
/// instead of overloading browser keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlay {
    None,
    Help,
    Diagnostics,
    MessageViewer,
    FolderPicker,
    ConfirmQuit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DraftField {
    To,
    Cc,
    Subject,
    Body,
}

#[derive(Debug, Clone)]
struct ComposeDraft {
    to: String,
    cc: String,
    subject: String,
    body: String,
    field: DraftField,
    dirty: bool,
}

pub fn write_email_tui_preflight(launch: &EmailTuiLaunch) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&preflight_value(launch))?
    );
    Ok(())
}

pub fn build_email_tui_evidence(launch: &EmailTuiLaunch) -> Result<Value> {
    let data = if let Some(path) = &launch.fixture_path {
        load_fixture(path)?
    } else {
        let config = launch
            .config
            .as_ref()
            .context("email tui evidence requires a profile, connection, or fixture")?;
        MailboxData {
            folders: Vec::new(),
            messages: Vec::new(),
            bodies: Vec::new(),
            diagnostics: diagnostics_summary(config),
            redact_transcript_text: true,
        }
    };

    let folders = data
        .folders
        .iter()
        .map(|folder| {
            json!({
                "name": folder.name,
                "display_name": folder.display_name,
                "delimiter": folder.delimiter,
                "message_count": folder.message_count,
                "unread_count": folder.unread_count
            })
        })
        .collect::<Vec<_>>();
    let messages = data
        .messages
        .iter()
        .map(|message| {
            json!({
                "uid": message.uid,
                "from": message.from,
                "subject": message.subject,
                "date": message.date,
                "seen": message.seen,
                "size": message.size
            })
        })
        .collect::<Vec<_>>();
    let bodies = data
        .bodies
        .iter()
        .map(|body| {
            json!({
                "uid": body.uid,
                "from": body.from,
                "to": body.to,
                "cc": body.cc,
                "subject": body.subject,
                "date": body.date,
                "text": "[message body redacted for transcript evidence]",
                "html": null,
                "attachments": body.attachments
            })
        })
        .collect::<Vec<_>>();

    let mut evidence = json!({
        "schema_version": 1,
        "kind": "email_tui_fixture_evidence",
        "quality_gate": retained_tui_quality_gate(
            "email",
            &["fixture", "Quarterly report ready"],
            &["diagnostics", "verify_tls=true"],
            80,
            24,
            10_000
        ),
        "preflight": preflight_value(launch),
        "transcript": {
            "profile_label": launch.profile_label,
            "source": launch.source,
            "folders": folders,
            "messages": messages,
            "bodies": bodies,
            "diagnostics": data.diagnostics,
            "redact_transcript_text": data.redact_transcript_text
        },
        "plan_transcript": [
            {
                "action": "send_message",
                "risk": "side_effecting",
                "confirmation": "explicit_send_confirm",
                "body_capture": "redacted"
            },
            {
                "action": "discard_draft",
                "risk": "destructive",
                "confirmation": "explicit_discard_confirm"
            },
            {
                "action": "delete_message",
                "risk": "destructive",
                "status": "deferred_to_confirmed_side_effect_slice"
            }
        ],
        "coverage": [
            "startup",
            "mailbox_triage",
            "folder_navigation",
            "folder_picker",
            "per_folder_selection_memory",
            "message_reader",
            "message_viewer_scrollback",
            "search",
            "live_filter_match_count",
            "attachment_plan",
            "compose",
            "send_confirmation",
            "discard_confirmation",
            "diagnostics",
            "help_overlay",
            "page_navigation",
            "loading_marker",
            "non_modal_error_banner",
            "confirm_quit",
            "message_body_redaction",
            "resize",
            "quit_restore",
            "secret_leak_scan"
        ],
        "secret_leak_scan": null
    });

    let rendered = serde_json::to_string(&evidence)?;
    let markers = secret_leak_markers(&rendered);
    evidence["secret_leak_scan"] = json!({
        "passed": markers.is_empty(),
        "marker_count": markers.len(),
        "markers": markers
    });
    Ok(evidence)
}

fn preflight_value(launch: &EmailTuiLaunch) -> Value {
    json!({
        "ok": true,
        "command": "email tui",
        "profile_label": launch.profile_label,
        "source": launch.source,
        "fixture": launch.fixture_path.is_some(),
        "privacy": {
            "diagnostics_include_message_body": false,
            "diagnostics_include_attachment_bytes": false,
            "generic_invoke_side_effects": false,
            "attachments_auto_execute": false
        },
        "views": [
            "mailbox",
            "folders",
            "filter",
            "folder_picker",
            "message_viewer",
            "attachment_plan",
            "compose",
            "send_confirm",
            "discard_confirm",
            "diagnostics",
            "help",
            "confirm_quit"
        ],
        "side_effects": {
            "send": "explicit_confirmation_required",
            "delete": "deferred_to_confirmed_side_effect_slice"
        }
    })
}

pub async fn run_email_tui(launch: EmailTuiLaunch) -> Result<()> {
    let profile_label = launch.profile_label.clone();
    let config = launch.config.clone();
    let send_enabled = launch.fixture_path.is_none() && config.is_some();
    let data = load_mailbox_data(&launch).await?;
    let mut app = EmailTuiApp::new(profile_label, config, send_enabled, data);

    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

async fn load_mailbox_data(launch: &EmailTuiLaunch) -> Result<MailboxData> {
    if let Some(path) = &launch.fixture_path {
        return load_fixture(path);
    }

    let config = launch
        .config
        .clone()
        .context("email tui requires a profile or connection config")?;
    let diagnostics = diagnostics_summary(&config);
    let mut service = EmailService::new_direct().context("create EmailService")?;
    service
        .connect_direct(config)
        .await
        .context("connect to email target")?;
    let folders = service
        .list_folders_direct()
        .await
        .context("list email folders")?;
    let folder = folders
        .first()
        .map(|folder| folder.name.clone())
        .unwrap_or_else(|| "INBOX".to_string());
    let (messages, _) = service
        .list_messages_direct(folder.clone(), 0, PAGE_SIZE)
        .await
        .context("list email messages")?;
    let bodies = if let Some(message) = messages.first() {
        service
            .fetch_body_read_only_direct(folder, message.uid)
            .await
            .map(|body| vec![body])
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(MailboxData {
        folders,
        messages,
        bodies,
        diagnostics,
        redact_transcript_text: false,
    })
}

fn load_fixture(path: &str) -> Result<MailboxData> {
    let text = fs::read_to_string(path).with_context(|| format!("read fixture {path}"))?;
    let fixture: EmailTuiFixture =
        serde_json::from_str(&text).with_context(|| format!("parse fixture {path}"))?;
    let mut bodies = fixture.bodies;
    if fixture.redact_bodies {
        for body in &mut bodies {
            body.text = "[message body redacted for transcript evidence]".to_string();
            body.html = None;
        }
    }

    Ok(MailboxData {
        folders: fixture.folders,
        messages: fixture.messages,
        bodies,
        diagnostics: fixture
            .diagnostics
            .unwrap_or_else(|| "fixture mailbox loaded without target network".to_string()),
        redact_transcript_text: fixture.redact_bodies,
    })
}

fn secret_leak_markers(text: &str) -> Vec<String> {
    [
        "PRIVATE_BODY_SHOULD_NOT_APPEAR",
        "email_password_value",
        "smtp_password_value",
        "raw_email_config",
        "super-secret-password",
        "BEGIN OPENSSH PRIVATE KEY",
    ]
    .into_iter()
    .filter(|marker| text.contains(marker))
    .map(str::to_string)
    .collect()
}

fn diagnostics_summary(config: &EmailConfig) -> String {
    format!(
        "{} receive={} smtp={} verify_tls={}",
        protocol_label(config.protocol),
        security_label(config.receive_security),
        security_label(config.smtp_security),
        config.verify_tls
    )
}

fn protocol_label(protocol: EmailProtocol) -> &'static str {
    match protocol {
        EmailProtocol::IMAP => "imap",
        EmailProtocol::POP3 => "pop3",
    }
}

fn security_label(security: SecurityType) -> &'static str {
    match security {
        SecurityType::None => "none",
        SecurityType::STARTTLS => "starttls",
        SecurityType::SslTls => "ssl_tls",
    }
}

/// Run an async provider call on a background thread with its own runtime
/// and report the result through a channel. The plugin-owned TUI launch
/// contract forbids blocking the input loop on network calls, so key handlers
/// only stage the work here and the run loop drains the result non-blocking.
fn spawn_background<T, F>(work: F) -> mpsc::Receiver<Result<T>>
where
    T: Send + 'static,
    F: FnOnce() -> Pin<Box<dyn Future<Output = Result<T>> + Send>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| anyhow::anyhow!("start runtime: {error}"))
            .and_then(|runtime| runtime.block_on(work()));
        let _ = tx.send(result);
    });
    rx
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut EmailTuiApp) -> Result<()> {
    terminal.draw(|frame| app.draw(frame))?;
    loop {
        if app.should_quit {
            return Ok(());
        }
        let background_changed = app.drain_background();
        let event_handled = if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => {
                    app.handle_key(key);
                    true
                }
                Event::Resize(cols, rows) => {
                    app.status = format!("resized email view to {cols}x{rows}");
                    true
                }
                _ => false,
            }
        } else {
            false
        };
        if event_handled || background_changed {
            terminal.draw(|frame| app.draw(frame))?;
        }
    }
}

struct EmailTuiApp {
    profile_label: String,
    config: Option<EmailConfig>,
    send_enabled: bool,
    folders: Vec<EmailFolder>,
    messages: Vec<EmailEnvelope>,
    bodies: Vec<EmailBody>,
    diagnostics: String,
    redact_transcript_text: bool,
    mode: Mode,
    overlay: Overlay,
    /// Row held in the folder currently shown in the mailbox.
    selected_folder: usize,
    message_index: usize,
    /// Per-folder selection memory: the message row held in a folder is
    /// restored when the operator returns to it.
    selection_memory: HashMap<String, usize>,
    filter: String,
    folder_filter: String,
    folder_picker_selected: usize,
    viewer_scroll: usize,
    attachment_plan_visible: bool,
    /// Set while a folder listing is in flight; renders a loading marker.
    /// Background workers for provider calls; results drain non-blocking in
    /// the run loop so the input loop never blocks on network I/O.
    folder_rx: Option<mpsc::Receiver<Result<Vec<EmailEnvelope>>>>,
    body_rx: Option<mpsc::Receiver<Result<EmailBody>>>,
    send_rx: Option<mpsc::Receiver<Result<()>>>,
    messages_pending: bool,
    /// Set while a message body fetch is in flight; renders a loading marker.
    body_pending: bool,
    error_banner: Option<String>,
    status: String,
    should_quit: bool,
    draft: Option<ComposeDraft>,
}

impl EmailTuiApp {
    fn new(
        profile_label: String,
        config: Option<EmailConfig>,
        send_enabled: bool,
        data: MailboxData,
    ) -> Self {
        Self {
            profile_label,
            config,
            send_enabled,
            folders: data.folders,
            messages: data.messages,
            bodies: data.bodies,
            diagnostics: data.diagnostics,
            redact_transcript_text: data.redact_transcript_text,
            mode: Mode::Browser,
            overlay: Overlay::None,
            selected_folder: 0,
            message_index: 0,
            selection_memory: HashMap::new(),
            filter: String::new(),
            folder_filter: String::new(),
            folder_picker_selected: 0,
            viewer_scroll: 0,
            attachment_plan_visible: false,
            folder_rx: None,
            body_rx: None,
            send_rx: None,
            messages_pending: false,
            body_pending: false,
            error_banner: None,
            status: "mailbox loaded; j/k moves, / filters, Enter opens the message viewer"
                .to_string(),
            should_quit: false,
            draft: None,
        }
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        let area = frame.area();
        if area.width < 72 || area.height < 18 {
            let warning = Paragraph::new("Email TUI requires at least 72x18")
                .block(Block::default().title("Email").borders(Borders::ALL))
                .style(Style::default().fg(Color::Yellow));
            frame.render_widget(warning, area);
            return;
        }

        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                // Header and status each carry two content rows (title +
                // context, status + hints) on top of their borders, matching
                // the family-wide Length(4) panels.
                Constraint::Length(4),
                Constraint::Min(10),
                Constraint::Length(4),
            ])
            .split(area);

        frame.render_widget(self.header(), vertical[0]);
        self.draw_content(frame, vertical[1]);
        frame.render_widget(self.status_panel(), vertical[2]);

        if matches!(
            self.mode,
            Mode::Compose | Mode::SendConfirm | Mode::DiscardConfirm
        ) {
            self.draw_compose_overlay(frame, area);
        }
        match self.overlay {
            Overlay::None => {}
            Overlay::Help => self.draw_help(frame, area),
            Overlay::Diagnostics => self.draw_diagnostics(frame, area),
            Overlay::MessageViewer => self.draw_message_viewer(frame, area),
            Overlay::FolderPicker => self.draw_folder_picker(frame, area),
            Overlay::ConfirmQuit => self.draw_confirm_quit(frame, area),
        }
        if let Some(error) = &self.error_banner {
            self.draw_error_banner(frame, area, error);
        }
    }

    fn header(&self) -> Paragraph<'_> {
        let listing = if self.messages_pending || self.body_pending {
            " \u{27f3}"
        } else {
            ""
        };
        let send_label = if self.send_enabled {
            "confirmation-gated"
        } else {
            "fixture-local"
        };
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("Email TUI", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    " | profile {} | {}",
                    self.profile_label, self.diagnostics
                )),
            ]),
            Line::from(format!(
                "source {} | folders {} | messages {}/{} | filter {} | send {}{listing}",
                self.source_label(),
                self.folders.len(),
                self.filtered_messages().len(),
                self.messages.len(),
                self.filter_label(),
                send_label
            )),
        ])
        .block(Block::default().borders(Borders::ALL))
    }

    fn source_label(&self) -> &'static str {
        if self.config.is_some() {
            "profile"
        } else {
            "fixture"
        }
    }

    fn filter_label(&self) -> String {
        if self.filter.is_empty() {
            "-".to_string()
        } else {
            safe_inline(&self.filter, 24)
        }
    }

    fn draw_content(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(24),
                Constraint::Percentage(42),
                Constraint::Percentage(58),
            ])
            .split(area);
        self.draw_folders(frame, chunks[0]);
        self.draw_messages(frame, chunks[1]);
        self.draw_preview(frame, chunks[2]);
    }

    fn draw_folders(&self, frame: &mut Frame<'_>, area: Rect) {
        let visible = area.height.saturating_sub(2).max(1) as usize;
        let start = window_start(self.selected_folder, visible, self.folders.len());
        let lines = if self.folders.is_empty() {
            vec![Line::from("No folders")]
        } else {
            self.folders
                .iter()
                .enumerate()
                .skip(start)
                .take(visible)
                .map(|(idx, folder)| {
                    let marker = if idx == self.selected_folder {
                        "> "
                    } else {
                        "  "
                    };
                    let style = if idx == self.selected_folder {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(Span::styled(
                        format!(
                            "{marker}{} ({}/{})",
                            truncate(&folder.display_name, 15),
                            folder.unread_count,
                            folder.message_count
                        ),
                        style,
                    ))
                })
                .collect::<Vec<_>>()
        };
        let title = format!(
            " Folders ({}/{}) ",
            (self.selected_folder + 1).min(self.folders.len().max(1)),
            self.folders.len()
        );
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn draw_messages(&self, frame: &mut Frame<'_>, area: Rect) {
        let items = self.filtered_messages();
        let visible = area.height.saturating_sub(2).max(1) as usize;
        let start = window_start(self.message_index, visible, items.len());
        let lines = if !items.is_empty() {
            items
                .iter()
                .enumerate()
                .skip(start)
                .take(visible)
                .map(|(idx, message)| {
                    let marker = if idx == self.message_index {
                        "> "
                    } else {
                        "  "
                    };
                    let style = if idx == self.message_index {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let seen = if message.seen { " " } else { "*" };
                    Line::from(Span::styled(
                        format!(
                            "{marker}{seen} {} {}",
                            truncate(&message.from, 18),
                            truncate(&message.subject, 28)
                        ),
                        style,
                    ))
                })
                .collect::<Vec<_>>()
        } else if self.messages_pending {
            vec![Line::from("loading\u{2026}")]
        } else {
            vec![Line::from(
                "No messages. Press / to filter or F to pick a folder.",
            )]
        };
        let listing = if self.messages_pending {
            " \u{27f3}"
        } else {
            ""
        };
        let folder_label = self
            .folders
            .get(self.selected_folder)
            .map(|folder| truncate(&folder.display_name, 12))
            .unwrap_or_else(|| "mailbox".to_string());
        let title = if self.filter.is_empty() {
            format!(
                " Messages \u{b7} {} ({}/{}){listing} ",
                folder_label,
                (self.message_index + 1).min(items.len().max(1)),
                items.len()
            )
        } else {
            format!(
                " Messages \u{b7} {} \u{b7} '{}' {}/{}{listing} ",
                folder_label,
                safe_inline(&self.filter, 16),
                items.len(),
                self.messages.len()
            )
        };
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn draw_preview(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut lines = if let Some(message) = self.selected_message() {
            vec![
                Line::from(format!("From: {}", message.from)),
                Line::from(format!("Subject: {}", message.subject)),
                Line::from(format!("Date: {}", message.date)),
                Line::from(format!(
                    "Seen: {} \u{b7} Size: {} bytes",
                    message.seen, message.size
                )),
                Line::from(""),
                Line::from("Enter opens the full-screen message viewer."),
            ]
        } else {
            vec![
                Line::from("No message selected."),
                Line::from("Press / to filter or F to pick a folder."),
            ]
        };

        if self.attachment_plan_visible {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "attachment plan (metadata only)",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(
                "No file is opened or written; d/o only stage a plan description.",
            ));
            if let Some(body) = self.selected_body() {
                if body.attachments.is_empty() {
                    lines.push(Line::from("No attachments on selected message."));
                } else {
                    for attachment in &body.attachments {
                        lines.push(Line::from(format!(
                            "{} | {} | {} bytes",
                            attachment.filename, attachment.content_type, attachment.size
                        )));
                    }
                }
            } else {
                lines.push(Line::from(
                    "Attachment metadata requires a loaded message body.",
                ));
                lines.push(Line::from(
                    "Fixture mode can provide bodies without target access.",
                ));
            }
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().title(" Preview ").borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            area,
        );
    }

    fn status_panel(&self) -> Paragraph<'_> {
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", mode_label(self.mode)),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(&self.status),
            ]),
            Line::from(Span::styled(
                self.hint_footer(),
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" Status "))
    }

    fn hint_footer(&self) -> String {
        if let Some(hint) = match self.overlay {
            Overlay::Help => Some("help: any key closes".to_string()),
            Overlay::Diagnostics => Some("diagnostics: any key closes".to_string()),
            Overlay::MessageViewer => {
                Some("viewer: j/k PgUp/PgDn scroll | g/G home/end | Esc close".to_string())
            }
            Overlay::FolderPicker => {
                Some("picker: type to narrow | Enter switch | Esc close".to_string())
            }
            Overlay::ConfirmQuit => Some("quit: y/Enter quit | any other key stays".to_string()),
            Overlay::None => None,
        } {
            return hint;
        }
        match self.mode {
            Mode::Filter => format!(
                "filter: {}\u{258f} Enter apply \u{b7} Esc clear \u{b7} {} match(es)",
                safe_inline(&self.filter, 32),
                self.filtered_messages().len()
            ),
            Mode::Compose => "Tab field | F5 review send | Esc discard/back".to_string(),
            Mode::SendConfirm => "y send | n cancel | Esc compose".to_string(),
            Mode::DiscardConfirm => "y discard | n keep draft".to_string(),
            Mode::Browser => BROWSER_HINTS.to_string(),
        }
    }

    fn draw_help(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup = centered_rect(78, 84, area);
        frame.render_widget(Clear, popup);
        let help = vec![
            Line::from(Span::styled(
                "Email TUI help",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Navigation",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("j/k or arrows move \u{b7} PgUp/PgDn page \u{b7} g/G home/end"),
            Line::from("the message row is remembered per folder and restored on return"),
            Line::from("/ live filter over sender and subject (Enter applies, Esc clears)"),
            Line::from("F folder picker (type to narrow, Enter switches) \u{b7} f next folder"),
            Line::from(Span::styled(
                "Reading",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("Enter: full-screen scrollable message viewer (j/k PgUp/PgDn scroll)"),
            Line::from("a: attachment metadata plan \u{b7} bodies are fetched read-only"),
            Line::from("!: provider diagnostics (redacted, category-oriented)"),
            Line::from(Span::styled(
                "Compose (staged draft, F5 review)",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("c: new draft \u{b7} r: reply draft \u{b7} Tab cycles fields"),
            Line::from("F5 reviews the send; y confirms, n keeps the draft."),
            Line::from("Esc asks before discarding a non-empty draft."),
            Line::from(Span::styled(
                "Sessions",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("q: quit (asks for confirmation while a fetch is in flight)"),
            Line::from("Background failures surface as a non-modal banner; any key acknowledges."),
            Line::from(""),
            Line::from("Press any key to return."),
        ];
        frame.render_widget(
            Paragraph::new(help)
                .block(Block::default().title(" Help ").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }

    fn draw_diagnostics(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup = centered_rect(70, 62, area);
        frame.render_widget(Clear, popup);
        let lines = vec![
            Line::from("Provider diagnostics"),
            Line::from(""),
            Line::from(format!("Profile: {}", self.profile_label)),
            Line::from(format!("Transport: {}", self.diagnostics)),
            Line::from(""),
            Line::from("Auth failure: check username, password, app password, or OAuth policy."),
            Line::from("TLS failure: verify certificate trust and STARTTLS/SSL mode."),
            Line::from("Quota failure: reduce mailbox or provider send quota usage."),
            Line::from("Folder failure: refresh folders or verify server-side mailbox name."),
            Line::from("Transport failure: check network, host, port, proxy, and timeout."),
            Line::from(""),
            Line::from(
                "No message body, attachment bytes, password, or raw provider greeting is shown.",
            ),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .title(" Diagnostics ")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: true }),
            popup,
        );
    }

    fn message_viewer_lines(&self) -> Vec<Line<'static>> {
        if let Some(body) = self.selected_body() {
            let mut lines = vec![
                Line::from(format!("From: {}", body.from)),
                Line::from(format!("To: {}", body.to.join(", "))),
                if body.cc.is_empty() {
                    Line::from("Cc: -")
                } else {
                    Line::from(format!("Cc: {}", body.cc.join(", ")))
                },
                Line::from(format!("Subject: {}", body.subject)),
                Line::from(format!("Date: {}", body.date)),
                Line::from(""),
            ];
            for line in body.text.lines() {
                lines.push(Line::from(line.to_string()));
            }
            lines.push(Line::from(""));
            if body.attachments.is_empty() {
                lines.push(Line::from("No attachments."));
            } else {
                lines.push(Line::from(
                    "Attachments (metadata only; nothing opens or executes):",
                ));
                for attachment in &body.attachments {
                    lines.push(Line::from(format!(
                        "{} | {} | {} bytes",
                        attachment.filename, attachment.content_type, attachment.size
                    )));
                }
            }
            lines
        } else if let Some(message) = self.selected_message() {
            vec![
                Line::from(format!("From: {}", message.from)),
                Line::from(format!("Subject: {}", message.subject)),
                Line::from(""),
                Line::from("Body not loaded in the current cache."),
                Line::from("CLI fallback: voidb-cli email read --connection <name> <folder> <uid>"),
            ]
        } else {
            vec![Line::from("No message selected.")]
        }
    }

    fn draw_message_viewer(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup = centered_rect(88, 82, area);
        frame.render_widget(Clear, popup);
        let lines = self.message_viewer_lines();
        let visible = popup.height.saturating_sub(2).max(1) as usize;
        let total = lines.len();
        let start = self.viewer_scroll.min(total.saturating_sub(1));
        let body: Vec<Line> = if total == 0 {
            vec![Line::from("no message content")]
        } else {
            lines
                .into_iter()
                .skip(start)
                .take(visible)
                .collect::<Vec<_>>()
        };
        frame.render_widget(
            Paragraph::new(body)
                .block(Block::default()
                    .title(format!(
                        " Message \u{b7} line {}/{} \u{b7} j/k PgUp/PgDn scroll \u{b7} Esc close ",
                        (start + 1).min(total),
                        total
                    ))
                    .borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }

    fn draw_folder_picker(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup = centered_rect(60, 60, area);
        frame.render_widget(Clear, popup);
        let matches = self.filtered_folders();
        let visible = popup.height.saturating_sub(5).max(1) as usize;
        let start = window_start(self.folder_picker_selected, visible, matches.len());
        let mut lines = vec![
            Line::from(Span::styled(
                format!("filter: {}\u{258f}", self.folder_filter),
                Style::default().fg(Color::Cyan),
            )),
            Line::from(""),
        ];
        if matches.is_empty() {
            lines.push(Line::from("no folder matches the picker filter"));
        } else {
            lines.extend(matches.iter().enumerate().skip(start).take(visible).map(
                |(idx, folder)| {
                    let marker = if idx == self.selected_folder {
                        "*"
                    } else {
                        " "
                    };
                    let style = if idx == self.folder_picker_selected {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Green)
                            .add_modifier(Modifier::BOLD)
                    } else if idx == self.selected_folder {
                        Style::default().add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(Span::styled(
                        format!(
                            "{marker}{} ({}/{})",
                            truncate(&folder.display_name, 24),
                            folder.unread_count,
                            folder.message_count
                        ),
                        style,
                    ))
                },
            ));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default()
                    .title(format!(
                        " Folders {}/{} \u{b7} type to narrow \u{b7} Enter switch \u{b7} Esc close ",
                        (self.folder_picker_selected + 1).min(matches.len().max(1)),
                        matches.len()
                    ))
                    .borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }

    fn draw_compose_overlay(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup = centered_rect(64, 78, area);
        frame.render_widget(Clear, popup);
        let mut lines: Vec<Line<'static>> = match &self.draft {
            Some(draft) => {
                let mut lines = vec![
                    compose_line("To", &draft.to, draft.field == DraftField::To),
                    compose_line("Cc", &draft.cc, draft.field == DraftField::Cc),
                    compose_line(
                        "Subject",
                        &draft.subject,
                        draft.field == DraftField::Subject,
                    ),
                    Line::from(""),
                    compose_line("Body", "", draft.field == DraftField::Body),
                ];
                if self.redact_transcript_text && !draft.body.is_empty() {
                    lines.push(Line::from("[draft body redacted for transcript evidence]"));
                } else if draft.body.is_empty() {
                    lines.push(Line::from("(empty body)"));
                } else {
                    for line in draft.body.lines().take(14) {
                        lines.push(Line::from(line.to_string()));
                    }
                }
                lines
            }
            None => vec![Line::from("No active draft.")],
        };

        match self.mode {
            Mode::SendConfirm => {
                if let Some(draft) = &self.draft {
                    lines.push(Line::from(""));
                    lines.push(Line::from(format!(
                        "Confirm send to {} recipient(s), subject '{}'? y/n",
                        recipient_count(&draft.to, &draft.cc),
                        safe_subject(&draft.subject)
                    )));
                }
            }
            Mode::DiscardConfirm => {
                lines.push(Line::from(""));
                lines.push(Line::from("Discard non-empty draft? y/n"));
            }
            _ => {
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "F5 reviews send. Esc asks before discarding non-empty drafts.",
                ));
            }
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().title(" Compose ").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            popup,
        );
    }

    fn draw_confirm_quit(&self, frame: &mut Frame<'_>, area: Rect) {
        let popup = centered_rect(62, 22, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "Quit with active work?",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(self.active_work_summary()),
                Line::from("y/Enter: quit \u{b7} any other key: stay"),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Confirm Quit "),
            )
            .wrap(Wrap { trim: false }),
            popup,
        );
    }

    fn active_work_summary(&self) -> String {
        let mut parts = Vec::new();
        if self.messages_pending {
            parts.push("folder listing in flight".to_string());
        }
        if self.body_pending {
            parts.push("message body fetch in flight".to_string());
        }
        if parts.is_empty() {
            "no fetches in flight".to_string()
        } else {
            parts.join(", ")
        }
    }

    fn draw_error_banner(&self, frame: &mut Frame<'_>, area: Rect, error: &str) {
        let banner = Rect {
            x: area.x + 1,
            y: area.height.saturating_sub(6),
            width: area.width.saturating_sub(2),
            height: 3,
        };
        frame.render_widget(Clear, banner);
        frame.render_widget(
            Paragraph::new(vec![Line::from(Span::styled(
                safe_error_summary(error),
                Style::default().fg(Color::Red),
            ))])
            .block(
                Block::default()
                    .title(" Error (any key acknowledges) ")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::Red)),
            )
            .wrap(Wrap { trim: false }),
            banner,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) {
        // The error banner is informational: any key acknowledges it while
        // the key itself keeps its normal meaning, so background failures
        // never trap the operator in a modal.
        self.error_banner = None;
        // Overlay-first routing for stacked surfaces.
        match self.overlay {
            Overlay::None => {}
            Overlay::Help => {
                self.overlay = Overlay::None;
                self.status = "help closed".to_string();
                return;
            }
            Overlay::Diagnostics => {
                self.overlay = Overlay::None;
                self.status = "diagnostics closed".to_string();
                return;
            }
            Overlay::MessageViewer => {
                self.handle_message_viewer_key(key);
                return;
            }
            Overlay::FolderPicker => {
                self.handle_folder_picker_key(key);
                return;
            }
            Overlay::ConfirmQuit => {
                self.handle_confirm_quit_key(key);
                return;
            }
        }
        if matches!(
            self.mode,
            Mode::Compose | Mode::SendConfirm | Mode::DiscardConfirm
        ) {
            self.handle_compose_key(key);
            return;
        }
        if self.mode == Mode::Filter {
            self.handle_filter_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-PAGE_STEP),
            KeyCode::PageDown => self.move_selection(PAGE_STEP),
            KeyCode::Home | KeyCode::Char('g') => self.set_selected(0),
            KeyCode::End | KeyCode::Char('G') => {
                let len = self.filtered_messages().len();
                self.set_selected(len.saturating_sub(1));
            }
            KeyCode::Enter => self.open_message_viewer(),
            KeyCode::Char('/') => {
                self.mode = Mode::Filter;
                self.status = "filter: type to narrow live, Enter apply, Esc clear".to_string();
            }
            KeyCode::Char('f') => self.next_folder(),
            KeyCode::Char('F') => self.open_folder_picker(),
            KeyCode::Char('a') => self.toggle_attachment_plan(),
            KeyCode::Char('d') if self.attachment_plan_visible => {
                self.status =
                    "download plan requires a local path and confirmation; no file written"
                        .to_string();
            }
            KeyCode::Char('o') if self.attachment_plan_visible => {
                self.status =
                    "open plan requires confirmation; no external viewer launched".to_string();
            }
            KeyCode::Char('c') => self.start_compose(),
            KeyCode::Char('r') => self.start_reply(),
            KeyCode::Char('!') => {
                self.overlay = Overlay::Diagnostics;
                self.status = "diagnostics are redacted and category-oriented".to_string();
            }
            KeyCode::Char('?') => {
                self.overlay = Overlay::Help;
                self.status = "help open; any key closes".to_string();
            }
            KeyCode::Esc => {
                if !self.filter.is_empty() {
                    self.filter.clear();
                    self.set_selected(0);
                    self.status = "filter cleared".to_string();
                } else if self.attachment_plan_visible {
                    self.attachment_plan_visible = false;
                    self.status = "attachment plan hidden".to_string();
                } else {
                    self.status = format!("email: {BROWSER_HINTS}");
                }
            }
            _ => {
                self.status = format!("email: {BROWSER_HINTS}");
            }
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                self.mode = Mode::Browser;
                self.set_selected(0);
                self.status = format!(
                    "filter applied: {} ({} matches)",
                    self.filter_label(),
                    self.filtered_messages().len()
                );
            }
            KeyCode::Esc => {
                self.filter.clear();
                self.mode = Mode::Browser;
                self.set_selected(0);
                self.status = "filter cleared".to_string();
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.set_selected(0);
            }
            KeyCode::Char(ch) if !ch.is_control() => {
                self.filter.push(ch);
                self.set_selected(0);
            }
            _ => {}
        }
    }

    fn handle_message_viewer_key(&mut self, key: KeyEvent) {
        let max_scroll = self.message_viewer_lines().len().saturating_sub(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
                self.status = "message viewer closed".to_string();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.viewer_scroll = self.viewer_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.viewer_scroll = (self.viewer_scroll + 1).min(max_scroll);
            }
            KeyCode::PageUp => {
                self.viewer_scroll = self.viewer_scroll.saturating_sub(PAGE_STEP as usize)
            }
            KeyCode::PageDown => {
                self.viewer_scroll = (self.viewer_scroll + PAGE_STEP as usize).min(max_scroll)
            }
            KeyCode::Home | KeyCode::Char('g') => self.viewer_scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.viewer_scroll = max_scroll,
            _ => {}
        }
    }

    fn handle_folder_picker_key(&mut self, key: KeyEvent) {
        let matches = self.filtered_folders().len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
                self.status = "folder picker closed".to_string();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.folder_picker_selected = self.folder_picker_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if matches > 0 {
                    self.folder_picker_selected =
                        (self.folder_picker_selected + 1).min(matches - 1);
                }
            }
            KeyCode::Enter => self.apply_folder_selection(),
            KeyCode::Backspace => {
                self.folder_filter.pop();
                self.folder_picker_selected = 0;
            }
            KeyCode::Char(ch) if !ch.is_control() => {
                self.folder_filter.push(ch);
                self.folder_picker_selected = 0;
            }
            _ => {}
        }
    }

    fn handle_confirm_quit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                self.should_quit = true;
            }
            _ => {
                self.overlay = Overlay::None;
                self.status = "quit cancelled".to_string();
            }
        }
    }

    /// Quit immediately when no fetch is in flight; otherwise stage the
    /// non-modal confirmation overlay so a stray `q` cannot kill an in-flight
    /// folder listing or body fetch unnoticed. Compose owns `q` as draft text,
    /// so drafts are guarded by the discard confirmation instead.
    fn request_quit(&mut self) {
        if self.messages_pending || self.body_pending {
            self.overlay = Overlay::ConfirmQuit;
            self.status = "quit? a fetch is in flight: y quits, any other key stays".to_string();
            return;
        }
        self.should_quit = true;
    }

    fn open_folder_picker(&mut self) {
        if self.folders.is_empty() {
            self.status = "no folders loaded".to_string();
            return;
        }
        self.folder_filter.clear();
        self.folder_picker_selected = self.selected_folder;
        self.overlay = Overlay::FolderPicker;
        self.status = "folder picker: type to narrow, Enter switches, Esc closes".to_string();
    }

    fn filtered_folders(&self) -> Vec<&EmailFolder> {
        let needle = self.folder_filter.to_lowercase();
        self.folders
            .iter()
            .filter(|folder| {
                needle.is_empty()
                    || folder.display_name.to_lowercase().contains(&needle)
                    || folder.name.to_lowercase().contains(&needle)
            })
            .collect()
    }

    fn apply_folder_selection(&mut self) {
        let matches = self.filtered_folders();
        let Some(folder) = matches.get(self.folder_picker_selected).cloned() else {
            self.status = "no folder matches the picker filter".to_string();
            return;
        };
        let index = self
            .folders
            .iter()
            .position(|candidate| candidate.name == folder.name)
            .unwrap_or(self.selected_folder);
        self.overlay = Overlay::None;
        self.select_folder(index);
    }

    fn next_folder(&mut self) {
        if self.folders.is_empty() {
            return;
        }
        let next = (self.selected_folder + 1) % self.folders.len();
        self.select_folder(next);
    }

    /// Switch the active folder. The row held in the outgoing folder is
    /// remembered and the incoming folder's row is restored. Live profiles
    /// reload the message list through the same read-only listing used at
    /// startup; fixture mailboxes keep their single message list.
    fn select_folder(&mut self, index: usize) {
        if self.folders.is_empty() {
            return;
        }
        let index = index.min(self.folders.len() - 1);
        let outgoing = self.folders[self.selected_folder].name.clone();
        self.selection_memory.insert(outgoing, self.message_index);
        self.selected_folder = index;
        let folder_name = self.folders[index].name.clone();
        let folder_label = self.folders[index].display_name.clone();
        let restored = self
            .selection_memory
            .get(&folder_name)
            .copied()
            .unwrap_or(0);
        self.message_index = restored;

        match self.config.clone() {
            Some(config) => {
                self.messages_pending = true;
                self.status = format!("loading messages for {folder_label}\u{2026}");
                self.folder_rx = Some(spawn_background(move || {
                    Box::pin(async move { load_folder_messages(config, folder_name).await })
                }));
            }
            None => {
                self.status = format!(
                    "selected folder {folder_label} (fixture mailbox keeps one message list)"
                );
            }
        }
    }

    fn toggle_attachment_plan(&mut self) {
        if self.attachment_plan_visible {
            self.attachment_plan_visible = false;
            self.status = "attachment plan hidden".to_string();
        } else {
            self.attachment_plan_visible = true;
            self.status = "attachment plan is metadata-only; no auto-open".to_string();
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_messages().len();
        if len == 0 {
            self.set_selected(0);
            return;
        }
        let last = len as isize - 1;
        let next = (self.message_index as isize + delta).clamp(0, last) as usize;
        self.set_selected(next);
    }

    fn set_selected(&mut self, value: usize) {
        let len = self.filtered_messages().len();
        self.message_index = value.min(len.saturating_sub(1));
    }

    /// The live message list: the filter is applied on every access, so
    /// typing, clearing, and folder reloads are reflected immediately.
    fn filtered_messages(&self) -> Vec<EmailEnvelope> {
        let query = self.filter.to_ascii_lowercase();
        self.messages
            .iter()
            .filter(|message| {
                query.is_empty()
                    || message.from.to_ascii_lowercase().contains(&query)
                    || message.subject.to_ascii_lowercase().contains(&query)
            })
            .cloned()
            .collect()
    }

    fn selected_message(&self) -> Option<EmailEnvelope> {
        self.filtered_messages().get(self.message_index).cloned()
    }

    fn selected_body(&self) -> Option<&EmailBody> {
        let uid = self.selected_message()?.uid;
        self.bodies.iter().find(|body| body.uid == uid)
    }

    /// Open the full-screen message viewer. When the selected body is not in
    /// the local cache and a live profile is configured, fetch it through the
    /// same read-only call used at startup; the viewer opens regardless so a
    /// failed fetch never hijacks the flow.
    fn open_message_viewer(&mut self) {
        let Some(message) = self.selected_message() else {
            self.status = "no message selected; j/k moves the list".to_string();
            return;
        };
        if self.selected_body().is_none()
            && let Some(config) = self.config.clone()
        {
            let uid = message.uid;
            let folder = self
                .folders
                .get(self.selected_folder)
                .map(|folder| folder.name.clone())
                .unwrap_or_else(|| "INBOX".to_string());
            self.body_pending = true;
            self.status = format!("loading body for uid {uid}\u{2026}");
            self.body_rx = Some(spawn_background(move || {
                Box::pin(async move { fetch_body_read_only(config, folder, uid).await })
            }));
        }
        self.viewer_scroll = 0;
        self.overlay = Overlay::MessageViewer;
        self.status = "message viewer is local and scrollable; Esc returns".to_string();
    }

    fn note_error(&mut self, message: String) {
        // Background and request failures surface as a non-modal banner so a
        // failing fetch or send never hijacks the browser.
        self.error_banner = Some(message.clone());
        self.status = message;
    }

    fn start_compose(&mut self) {
        self.draft = Some(ComposeDraft {
            to: String::new(),
            cc: String::new(),
            subject: String::new(),
            body: String::new(),
            field: DraftField::To,
            dirty: false,
        });
        self.mode = Mode::Compose;
        self.status = "compose draft started".to_string();
    }

    fn start_reply(&mut self) {
        let (to, subject) = self
            .selected_message()
            .map(|message| {
                let subject = if message.subject.to_ascii_lowercase().starts_with("re:") {
                    message.subject.clone()
                } else {
                    format!("Re: {}", message.subject)
                };
                (message.from.clone(), subject)
            })
            .unwrap_or_else(|| (String::new(), String::new()));
        self.draft = Some(ComposeDraft {
            to,
            cc: String::new(),
            subject,
            body: String::new(),
            field: DraftField::Body,
            dirty: false,
        });
        self.mode = Mode::Compose;
        self.status = "reply draft started; original body is not quoted".to_string();
    }

    fn handle_compose_key(&mut self, key: KeyEvent) {
        match self.mode {
            Mode::SendConfirm => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.confirm_send(),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.mode = Mode::Compose;
                    self.status = "send canceled; draft preserved".to_string();
                }
                _ => {}
            },
            Mode::DiscardConfirm => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.draft = None;
                    self.mode = Mode::Browser;
                    self.status = "draft discarded".to_string();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.mode = Mode::Compose;
                    self.status = "draft preserved".to_string();
                }
                _ => {}
            },
            Mode::Compose => match key.code {
                KeyCode::Tab => self.next_draft_field(),
                KeyCode::Backspace => self.pop_draft_char(),
                KeyCode::Enter => self.enter_draft_newline_or_next_field(),
                KeyCode::F(5) => self.review_send(),
                KeyCode::Esc => self.request_discard_or_close(),
                KeyCode::Char(c) if !c.is_control() => self.push_draft_char(c),
                _ => {}
            },
            _ => {}
        }
    }

    fn next_draft_field(&mut self) {
        if let Some(draft) = &mut self.draft {
            draft.field = match draft.field {
                DraftField::To => DraftField::Cc,
                DraftField::Cc => DraftField::Subject,
                DraftField::Subject => DraftField::Body,
                DraftField::Body => DraftField::To,
            };
        }
    }

    fn push_draft_char(&mut self, c: char) {
        if let Some(draft) = &mut self.draft {
            match draft.field {
                DraftField::To => draft.to.push(c),
                DraftField::Cc => draft.cc.push(c),
                DraftField::Subject => draft.subject.push(c),
                DraftField::Body => draft.body.push(c),
            }
            draft.dirty = true;
        }
    }

    fn pop_draft_char(&mut self) {
        if let Some(draft) = &mut self.draft {
            match draft.field {
                DraftField::To => {
                    draft.to.pop();
                }
                DraftField::Cc => {
                    draft.cc.pop();
                }
                DraftField::Subject => {
                    draft.subject.pop();
                }
                DraftField::Body => {
                    draft.body.pop();
                }
            }
            draft.dirty = true;
        }
    }

    fn enter_draft_newline_or_next_field(&mut self) {
        if let Some(draft) = &mut self.draft {
            if draft.field == DraftField::Body {
                draft.body.push('\n');
                draft.dirty = true;
            } else {
                self.next_draft_field();
            }
        }
    }

    fn review_send(&mut self) {
        let Some(draft) = &self.draft else {
            return;
        };
        if recipient_count(&draft.to, &draft.cc) == 0 {
            self.status = "send blocked: add at least one recipient".to_string();
            return;
        }
        if draft.subject.trim().is_empty() {
            self.status = "send blocked: add a subject".to_string();
            return;
        }
        if draft.body.trim().is_empty() {
            self.status = "send blocked: body is empty".to_string();
            return;
        }
        self.mode = Mode::SendConfirm;
        self.status = "review recipient count and safe subject before y".to_string();
    }

    fn request_discard_or_close(&mut self) {
        if self.draft.as_ref().is_some_and(|draft| draft.dirty) {
            self.mode = Mode::DiscardConfirm;
            self.status = "non-empty draft requires discard confirmation".to_string();
        } else {
            self.draft = None;
            self.mode = Mode::Browser;
            self.status = "compose closed".to_string();
        }
    }

    fn confirm_send(&mut self) {
        let Some(draft) = self.draft.clone() else {
            self.mode = Mode::Browser;
            return;
        };
        if !self.send_enabled {
            self.draft = None;
            self.mode = Mode::Browser;
            self.status = format!(
                "fixture send confirmed for {} recipient(s); no SMTP target opened",
                recipient_count(&draft.to, &draft.cc)
            );
            return;
        }

        if self.send_rx.is_some() {
            self.status = "a send is already in progress".to_string();
            return;
        }

        let config = self.config.clone().expect("checked above");
        self.status = "sending email\u{2026}".to_string();
        self.send_rx = Some(spawn_background(move || {
            Box::pin(async move {
                let mut service = EmailService::new_direct().context("create EmailService")?;
                service
                    .send_email_direct(
                        config.smtp.host,
                        config.smtp.port,
                        config.smtp_security,
                        config.email.clone(),
                        config.email,
                        config.password,
                        recipient_list(&draft.to, &draft.cc),
                        draft.subject,
                        draft.body,
                        Vec::new(),
                    )
                    .await
                    .context("send email")
            })
        }));
    }

    /// Non-blocking drain of staged provider results. Returns whether any
    /// state changed and the UI should repaint.
    fn drain_background(&mut self) -> bool {
        let mut changed = false;
        if let Some(rx) = &self.folder_rx {
            match rx.try_recv() {
                Ok(Ok(messages)) => {
                    self.folder_rx = None;
                    self.messages_pending = false;
                    let count = messages.len();
                    self.messages = messages;
                    let label = self
                        .folders
                        .get(self.selected_folder)
                        .map(|folder| folder.display_name.clone())
                        .unwrap_or_default();
                    self.status = format!("folder {label}: {count} messages");
                    changed = true;
                }
                Ok(Err(error)) => {
                    self.folder_rx = None;
                    self.messages_pending = false;
                    self.note_error(safe_error_summary(&format!(
                        "folder load failed: {error:#}"
                    )));
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.folder_rx = None;
                    self.messages_pending = false;
                    self.note_error("folder loader stopped".to_string());
                    changed = true;
                }
            }
        }
        if let Some(rx) = &self.body_rx {
            match rx.try_recv() {
                Ok(Ok(body)) => {
                    self.body_rx = None;
                    self.body_pending = false;
                    self.bodies.push(body);
                    self.status = "message body loaded".to_string();
                    changed = true;
                }
                Ok(Err(error)) => {
                    self.body_rx = None;
                    self.body_pending = false;
                    self.note_error(safe_error_summary(&format!("body fetch failed: {error:#}")));
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.body_rx = None;
                    self.body_pending = false;
                    self.note_error("body fetcher stopped".to_string());
                    changed = true;
                }
            }
        }
        if let Some(rx) = &self.send_rx {
            match rx.try_recv() {
                Ok(Ok(())) => {
                    self.send_rx = None;
                    self.draft = None;
                    self.mode = Mode::Browser;
                    self.status = "email sent; draft cleared".to_string();
                    changed = true;
                }
                Ok(Err(error)) => {
                    self.send_rx = None;
                    self.record_send_failure(error.to_string());
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.send_rx = None;
                    self.record_send_failure("send worker stopped".to_string());
                    changed = true;
                }
            }
        }
        changed
    }

    /// A failed send keeps the draft and returns to the compose surface; the
    /// redacted classification also raises the non-modal error banner.
    fn record_send_failure(&mut self, error: String) {
        let classified = classify_provider_error(&error);
        self.mode = Mode::Compose;
        self.note_error(classified);
    }
}

async fn load_folder_messages(config: EmailConfig, folder: String) -> Result<Vec<EmailEnvelope>> {
    let mut service = EmailService::new_direct().context("create EmailService")?;
    service
        .connect_direct(config)
        .await
        .context("connect to email target")?;
    let (messages, _) = service
        .list_messages_direct(folder, 0, PAGE_SIZE)
        .await
        .context("list email messages")?;
    Ok(messages)
}

async fn fetch_body_read_only(config: EmailConfig, folder: String, uid: u32) -> Result<EmailBody> {
    let mut service = EmailService::new_direct().context("create EmailService")?;
    service
        .connect_direct(config)
        .await
        .context("connect to email target")?;
    service
        .fetch_body_read_only_direct(folder, uid)
        .await
        .context("fetch message body")
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut result = value
        .chars()
        .take(width.saturating_sub(3))
        .collect::<String>();
    result.push_str("...");
    result
}

fn safe_inline(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut result: String = value.chars().take(width.saturating_sub(1)).collect();
    result.push('\u{2026}');
    result
}

fn safe_error_summary(message: &str) -> String {
    let mut summary = message.replace('\n', " ");
    if summary.chars().count() > 180 {
        summary = summary.chars().take(177).collect();
        summary.push_str("...");
    }
    summary
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Browser => "browser",
        Mode::Filter => "filter",
        Mode::Compose => "compose",
        Mode::SendConfirm => "send_confirm",
        Mode::DiscardConfirm => "discard_confirm",
    }
}

fn window_start(selected: usize, visible: usize, len: usize) -> usize {
    if visible == 0 || len <= visible {
        0
    } else if selected >= visible {
        (selected + 1).saturating_sub(visible)
    } else {
        0
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn compose_line(label: &str, value: &str, active: bool) -> Line<'static> {
    let prefix = if active { "> " } else { "  " };
    Line::from(format!("{}{}: {}", prefix, label, value))
}

fn recipient_count(to: &str, cc: &str) -> usize {
    to.split(',')
        .chain(cc.split(','))
        .filter(|recipient| !recipient.trim().is_empty())
        .count()
}

fn recipient_list(to: &str, cc: &str) -> String {
    to.split(',')
        .chain(cc.split(','))
        .map(str::trim)
        .filter(|recipient| !recipient.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn safe_subject(subject: &str) -> String {
    truncate(subject.trim(), 48)
}

fn classify_provider_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("auth")
        || lower.contains("login")
        || lower.contains("password")
        || lower.contains("credential")
    {
        "send failed: auth error; check credentials or provider app-password policy".to_string()
    } else if lower.contains("tls")
        || lower.contains("certificate")
        || lower.contains("ssl")
        || lower.contains("starttls")
    {
        "send failed: TLS error; check provider security mode and certificate trust".to_string()
    } else if lower.contains("quota") || lower.contains("limit") {
        "send failed: quota error; check provider send or mailbox limits".to_string()
    } else if lower.contains("folder") || lower.contains("mailbox") {
        "provider error: folder or mailbox unavailable; refresh folders".to_string()
    } else if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection")
        || lower.contains("refused")
        || lower.contains("dns")
        || lower.contains("network")
    {
        "send failed: transport error; check host, port, network, and timeout".to_string()
    } else {
        "send failed: provider returned a redacted SMTP error; draft preserved".to_string()
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyModifiers;
    use serde_json::json;

    use super::{
        EmailTuiLaunch, EmailTuiSource, Overlay, build_email_tui_evidence, classify_provider_error,
    };
    use crate::tui::EmailTuiApp;

    fn fixture_launch() -> EmailTuiLaunch {
        EmailTuiLaunch {
            profile_label: "fixture".to_string(),
            config: None,
            source: EmailTuiSource::Fixture,
            fixture_path: Some(format!(
                "{}/fixtures/email_tui_smoke.json",
                env!("CARGO_MANIFEST_DIR")
            )),
        }
    }

    fn fixture_app() -> EmailTuiApp {
        let launch = fixture_launch();
        let data = super::load_fixture(launch.fixture_path.as_deref().unwrap()).unwrap();
        EmailTuiApp::new(launch.profile_label, None, false, data)
    }

    fn press(app: &mut EmailTuiApp, code: crossterm::event::KeyCode) {
        app.handle_key(crossterm::event::KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn type_text(app: &mut EmailTuiApp, text: &str) {
        for ch in text.chars() {
            press(app, crossterm::event::KeyCode::Char(ch));
        }
    }

    #[test]
    fn fixture_evidence_redacts_message_bodies_and_records_quality_gate() {
        let evidence = build_email_tui_evidence(&fixture_launch()).unwrap();
        let rendered = serde_json::to_string(&evidence).unwrap();

        assert!(rendered.contains("email_tui_fixture_evidence"));
        assert!(!rendered.contains("PRIVATE_BODY_SHOULD_NOT_APPEAR"));
        assert_eq!(evidence["secret_leak_scan"]["passed"], json!(true));
        assert_eq!(evidence["quality_gate"]["plugin_id"], json!("email"));
        assert_eq!(
            evidence["quality_gate"]["accessibility"]["keyboard_only"],
            json!(true)
        );
        let coverage = evidence["coverage"].as_array().unwrap().clone();
        for marker in [
            "message_body_redaction",
            "folder_picker",
            "message_viewer_scrollback",
            "live_filter_match_count",
            "non_modal_error_banner",
            "confirm_quit",
            "per_folder_selection_memory",
        ] {
            assert!(
                coverage.contains(&json!(marker)),
                "coverage must include {marker}"
            );
        }
    }

    #[test]
    fn live_filter_updates_match_count_and_clears() {
        let mut app = fixture_app();
        press(&mut app, crossterm::event::KeyCode::Char('/'));
        assert_eq!(app.mode, super::Mode::Filter);
        type_text(&mut app, "tls");
        // Typing narrows live with the cursor pinned to the first match.
        assert_eq!(app.message_index, 0);
        assert_eq!(app.filtered_messages().len(), 1);
        press(&mut app, crossterm::event::KeyCode::Enter);
        assert_eq!(app.mode, super::Mode::Browser);
        assert!(app.status.contains("filter applied: tls"));
        assert!(app.status.contains("(1 matches)"));

        press(&mut app, crossterm::event::KeyCode::Char('/'));
        press(&mut app, crossterm::event::KeyCode::Esc);
        assert_eq!(app.mode, super::Mode::Browser);
        assert!(app.filter.is_empty());
        assert_eq!(app.filtered_messages().len(), 2);
        assert!(app.status.contains("filter cleared"));
    }

    #[test]
    fn folder_picker_narrows_and_switches() {
        let mut app = fixture_app();
        press(&mut app, crossterm::event::KeyCode::Char('F'));
        assert_eq!(app.overlay, Overlay::FolderPicker);
        type_text(&mut app, "arch");
        press(&mut app, crossterm::event::KeyCode::Enter);
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(app.selected_folder, 1);
        assert!(app.status.contains("selected folder Archive"));

        // A filter with no matches keeps the picker open and stays put.
        press(&mut app, crossterm::event::KeyCode::Char('F'));
        type_text(&mut app, "no-such-folder");
        press(&mut app, crossterm::event::KeyCode::Enter);
        assert!(app.status.contains("no folder matches the picker filter"));
        assert_eq!(app.overlay, Overlay::FolderPicker);
        press(&mut app, crossterm::event::KeyCode::Esc);
        assert_eq!(app.overlay, Overlay::None);
    }

    #[test]
    fn folder_switch_restores_per_folder_selection() {
        let mut app = fixture_app();
        press(&mut app, crossterm::event::KeyCode::Down);
        assert_eq!(app.message_index, 1);
        press(&mut app, crossterm::event::KeyCode::Char('f'));
        assert_eq!(app.selected_folder, 1);
        // The INBOX row is restored when the operator returns to it.
        press(&mut app, crossterm::event::KeyCode::Char('f'));
        assert_eq!(app.selected_folder, 0);
        assert_eq!(
            app.message_index, 1,
            "selection must be restored per folder"
        );
    }

    #[test]
    fn message_viewer_scrolls_full_body_and_closes() {
        let mut app = fixture_app();
        let long_body = (1..=60)
            .map(|index| format!("body line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        app.bodies.push(crate::types::EmailBody {
            uid: 1002,
            uid_validity: None,
            modseq: None,
            from: "alerts@example.test".to_string(),
            to: vec!["operator@example.test".to_string()],
            cc: Vec::new(),
            subject: "TLS certificate rotation".to_string(),
            date: "2026-07-07T08:05:00Z".to_string(),
            text: long_body,
            html: None,
            attachments: Vec::new(),
        });
        press(&mut app, crossterm::event::KeyCode::Down);
        press(&mut app, crossterm::event::KeyCode::Enter);
        assert_eq!(app.overlay, Overlay::MessageViewer);
        assert_eq!(app.viewer_scroll, 0);

        let max_scroll = super::EmailTuiApp::message_viewer_lines(&app).len() - 1;
        press(&mut app, crossterm::event::KeyCode::PageDown);
        assert_eq!(app.viewer_scroll, 10);
        press(&mut app, crossterm::event::KeyCode::End);
        assert_eq!(app.viewer_scroll, max_scroll);
        press(&mut app, crossterm::event::KeyCode::PageDown);
        assert_eq!(
            app.viewer_scroll, max_scroll,
            "scrolling must clamp at the last body line"
        );
        press(&mut app, crossterm::event::KeyCode::Home);
        assert_eq!(app.viewer_scroll, 0);
        press(&mut app, crossterm::event::KeyCode::Esc);
        assert_eq!(app.overlay, Overlay::None);
    }

    #[test]
    fn quit_with_in_flight_fetch_requires_confirmation() {
        let mut app = fixture_app();
        // Compose owns `q` as draft text; quitting from there goes through the
        // discard confirmation, so a draft can never be lost by a stray `q`.
        press(&mut app, crossterm::event::KeyCode::Char('c'));
        type_text(&mut app, "hello");
        press(&mut app, crossterm::event::KeyCode::Char('q'));
        assert!(app.draft.is_some(), "compose mode types q into the draft");
        assert!(!app.should_quit);
        press(&mut app, crossterm::event::KeyCode::Esc);
        assert_eq!(app.mode, super::Mode::DiscardConfirm);
        press(&mut app, crossterm::event::KeyCode::Char('n'));
        assert!(app.draft.is_some(), "n keeps the draft");
        press(&mut app, crossterm::event::KeyCode::Esc);
        press(&mut app, crossterm::event::KeyCode::Char('y'));
        assert!(app.draft.is_none(), "y discards the draft");
        assert_eq!(app.mode, super::Mode::Browser);

        // With a body fetch in flight, `q` stages the confirmation instead of
        // quitting; staying keeps the marker, and only `y` leaves the app.
        app.body_pending = true;
        press(&mut app, crossterm::event::KeyCode::Char('q'));
        assert_eq!(app.overlay, Overlay::ConfirmQuit);
        assert!(!app.should_quit);
        press(&mut app, crossterm::event::KeyCode::Esc);
        assert_eq!(app.overlay, Overlay::None);
        assert!(!app.should_quit);
        assert!(app.body_pending, "staying keeps the fetch marker");
        press(&mut app, crossterm::event::KeyCode::Char('q'));
        press(&mut app, crossterm::event::KeyCode::Char('y'));
        assert!(app.should_quit);
    }

    #[test]
    fn background_error_becomes_banner_not_modal() {
        let mut app = fixture_app();
        app.note_error("folder load failed: connection refused".to_string());
        assert_eq!(
            app.mode,
            super::Mode::Browser,
            "errors must not hijack the mode"
        );
        assert!(app.error_banner.is_some());
        assert!(app.status.contains("connection refused"));
        // Any key acknowledges the banner while keeping its normal meaning.
        press(&mut app, crossterm::event::KeyCode::Char('j'));
        assert!(app.error_banner.is_none());
        assert_eq!(app.message_index, 1);
        assert_eq!(app.mode, super::Mode::Browser);
    }

    #[test]
    fn send_failure_keeps_draft_and_raises_banner() {
        let mut app = fixture_app();
        press(&mut app, crossterm::event::KeyCode::Char('c'));
        app.record_send_failure("535 authentication failed".to_string());
        assert_eq!(
            app.mode,
            super::Mode::Compose,
            "the draft must be preserved"
        );
        assert!(app.draft.is_some());
        assert!(app.error_banner.is_some());
        assert!(app.status.contains(
            "send failed: auth error; check credentials or provider app-password policy"
        ));
        assert_eq!(
            classify_provider_error("connection refused by peer"),
            "send failed: transport error; check host, port, network, and timeout"
        );
    }

    #[test]
    fn page_and_home_end_keys_move_selection() {
        let mut app = fixture_app();
        press(&mut app, crossterm::event::KeyCode::PageDown);
        assert_eq!(app.message_index, 1, "fixture holds two messages");
        press(&mut app, crossterm::event::KeyCode::PageUp);
        assert_eq!(app.message_index, 0);
        press(&mut app, crossterm::event::KeyCode::End);
        assert_eq!(app.message_index, 1);
        press(&mut app, crossterm::event::KeyCode::Home);
        assert_eq!(app.message_index, 0);
    }

    #[test]
    fn help_overlay_opens_and_closes() {
        let mut app = fixture_app();
        press(&mut app, crossterm::event::KeyCode::Char('?'));
        assert_eq!(app.overlay, Overlay::Help);
        // Any key closes the help overlay without applying that key's meaning.
        press(&mut app, crossterm::event::KeyCode::Char('c'));
        assert_eq!(app.overlay, Overlay::None);
        assert!(
            app.draft.is_none(),
            "help must not leak keystrokes into the app"
        );
    }

    #[test]
    fn hint_footer_variants_fit_120_columns() {
        let mut app = fixture_app();
        assert!(app.hint_footer().chars().count() <= 122);

        app.mode = super::Mode::Filter;
        app.filter = "x".repeat(64);
        assert!(app.hint_footer().chars().count() <= 122);

        app.filter.clear();
        for overlay in [
            Overlay::Help,
            Overlay::Diagnostics,
            Overlay::MessageViewer,
            Overlay::FolderPicker,
            Overlay::ConfirmQuit,
        ] {
            app.overlay = overlay;
            assert!(
                app.hint_footer().chars().count() <= 122,
                "hint for {overlay:?} must fit ~120 columns"
            );
        }

        app.overlay = Overlay::None;
        for mode in [
            super::Mode::Browser,
            super::Mode::Filter,
            super::Mode::Compose,
            super::Mode::SendConfirm,
            super::Mode::DiscardConfirm,
        ] {
            app.mode = mode;
            assert!(
                app.hint_footer().chars().count() <= 122,
                "hint for {mode:?} must fit ~120 columns"
            );
        }
    }
    #[test]
    fn send_result_drains_success_and_clears_the_draft() {
        let mut app = fixture_app();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ok(())).unwrap();
        app.send_rx = Some(rx);
        app.draft = Some(super::ComposeDraft {
            to: "peer@example.com".into(),
            cc: String::new(),
            subject: "subject".into(),
            body: "body".into(),
            field: super::DraftField::To,
            dirty: true,
        });
        assert!(app.drain_background());
        assert!(app.send_rx.is_none());
        assert!(app.draft.is_none());
        assert_eq!(app.mode, super::Mode::Browser);
        assert_eq!(app.status, "email sent; draft cleared");
        // Draining an empty channel is a no-op that does not repaint.
        assert!(!app.drain_background());
    }

    #[test]
    fn send_result_drains_failure_keeps_the_draft_and_classifies() {
        let mut app = fixture_app();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Err(anyhow::anyhow!("smtp connection refused")))
            .unwrap();
        app.send_rx = Some(rx);
        app.draft = Some(super::ComposeDraft {
            to: "peer@example.com".into(),
            cc: String::new(),
            subject: "subject".into(),
            body: "body".into(),
            field: super::DraftField::To,
            dirty: true,
        });
        assert!(app.drain_background());
        assert!(app.send_rx.is_none());
        assert!(app.draft.is_some(), "a failed send keeps the draft");
        assert_eq!(app.mode, super::Mode::Compose);
        assert!(app.error_banner.is_some());
    }

    #[test]
    fn folder_result_drains_into_the_message_list() {
        let mut app = fixture_app();
        let envelopes = vec![super::EmailEnvelope {
            uid: 1,
            uid_validity: None,
            modseq: None,
            from: "sender@example.com".into(),
            subject: "hello".into(),
            date: "2026-11-04".into(),
            seen: false,
            size: 128,
        }];
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ok(envelopes)).unwrap();
        app.folder_rx = Some(rx);
        app.messages_pending = true;
        assert!(app.drain_background());
        assert!(app.folder_rx.is_none());
        assert!(!app.messages_pending);
        assert_eq!(app.messages.len(), 1);
        assert!(app.status.contains("1 message"));
    }
}
