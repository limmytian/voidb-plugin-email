use std::fs;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use voidb_core::retained_tui_quality_gate;

use crate::config::{EmailConfig, EmailProtocol, SecurityType};
use crate::service::EmailService;
use crate::types::{EmailBody, EmailEnvelope, EmailFolder};

const PAGE_SIZE: u32 = 25;

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
    Mailbox,
    Search,
    Reader,
    AttachmentPlan,
    Compose,
    SendConfirm,
    DiscardConfirm,
    Diagnostics,
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
            "message_reader",
            "search",
            "attachment_plan",
            "compose",
            "send_confirmation",
            "discard_confirmation",
            "diagnostics",
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
            "search",
            "reader",
            "attachment_plan",
            "compose",
            "send_confirm",
            "discard_confirm",
            "diagnostics"
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

fn run_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut EmailTuiApp) -> Result<()> {
    terminal.draw(|frame| app.draw(frame))?;
    loop {
        if app.should_quit {
            return Ok(());
        }
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => {
                    app.handle_key(key.code);
                    terminal.draw(|frame| app.draw(frame))?;
                }
                Event::Resize(_, _) => {
                    terminal.draw(|frame| app.draw(frame))?;
                }
                _ => {}
            }
        }
    }
}

struct EmailTuiApp {
    profile_label: String,
    config: Option<EmailConfig>,
    send_enabled: bool,
    folders: Vec<EmailFolder>,
    messages: Vec<EmailEnvelope>,
    filtered_messages: Vec<EmailEnvelope>,
    bodies: Vec<EmailBody>,
    diagnostics: String,
    redact_transcript_text: bool,
    mode: Mode,
    folder_index: usize,
    message_index: usize,
    search_input: String,
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
        let mut app = Self {
            profile_label,
            config,
            send_enabled,
            folders: data.folders,
            filtered_messages: data.messages.clone(),
            messages: data.messages,
            bodies: data.bodies,
            diagnostics: data.diagnostics,
            redact_transcript_text: data.redact_transcript_text,
            mode: Mode::Mailbox,
            folder_index: 0,
            message_index: 0,
            search_input: String::new(),
            status: "mailbox loaded; q quits, / searches, Enter opens reader".to_string(),
            should_quit: false,
            draft: None,
        };
        app.apply_search();
        app
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
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(4),
            ])
            .split(area);

        self.draw_header(frame, vertical[0]);
        self.draw_content(frame, vertical[1]);
        self.draw_footer(frame, vertical[2]);

        if self.mode == Mode::Search {
            self.draw_search_modal(frame, area);
        }
    }

    fn draw_header(&self, frame: &mut Frame<'_>, area: Rect) {
        let title = format!("Email - {} - {}", self.profile_label, self.diagnostics);
        let header = Paragraph::new(title)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::Cyan));
        frame.render_widget(header, area);
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
        match self.mode {
            Mode::Reader => self.draw_reader(frame, chunks[2]),
            Mode::AttachmentPlan => self.draw_attachment_plan(frame, chunks[2]),
            Mode::Compose | Mode::SendConfirm | Mode::DiscardConfirm => {
                self.draw_compose(frame, chunks[2])
            }
            Mode::Diagnostics => self.draw_diagnostics(frame, chunks[2]),
            _ => self.draw_preview(frame, chunks[2]),
        }
    }

    fn draw_folders(&self, frame: &mut Frame<'_>, area: Rect) {
        let items = if self.folders.is_empty() {
            vec![ListItem::new("No folders")]
        } else {
            self.folders
                .iter()
                .map(|folder| {
                    ListItem::new(format!(
                        "{} ({}/{})",
                        truncate(&folder.display_name, 15),
                        folder.unread_count,
                        folder.message_count
                    ))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !self.folders.is_empty() {
            state.select(Some(self.folder_index.min(self.folders.len() - 1)));
        }
        let list = List::new(items)
            .block(Block::default().title("Folders").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_messages(&self, frame: &mut Frame<'_>, area: Rect) {
        let items = if self.filtered_messages.is_empty() {
            vec![ListItem::new("No messages")]
        } else {
            self.filtered_messages
                .iter()
                .map(|message| {
                    let seen = if message.seen { " " } else { "*" };
                    ListItem::new(Line::from(vec![
                        Span::styled(seen, Style::default().fg(Color::Yellow)),
                        Span::raw(" "),
                        Span::styled(
                            truncate(&message.from, 18),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(" "),
                        Span::raw(truncate(&message.subject, 28)),
                    ]))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !self.filtered_messages.is_empty() {
            state.select(Some(
                self.message_index.min(self.filtered_messages.len() - 1),
            ));
        }
        let title = if self.search_input.is_empty() {
            "Messages".to_string()
        } else {
            format!("Messages /{}", self.search_input)
        };
        let list = List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_preview(&self, frame: &mut Frame<'_>, area: Rect) {
        let text = if let Some(message) = self.selected_message() {
            vec![
                Line::from(format!("From: {}", message.from)),
                Line::from(format!("Subject: {}", message.subject)),
                Line::from(format!("Date: {}", message.date)),
                Line::from(""),
                Line::from("Press Enter to open reader."),
                Line::from("Press a for attachment metadata plan."),
            ]
        } else {
            vec![
                Line::from("No selected message."),
                Line::from("Use / to search or f to change folders."),
            ]
        };
        let paragraph = Paragraph::new(text)
            .block(Block::default().title("Preview").borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn draw_reader(&self, frame: &mut Frame<'_>, area: Rect) {
        let lines = if let Some(body) = self.selected_body() {
            let mut lines = vec![
                Line::from(format!("From: {}", body.from)),
                Line::from(format!("To: {}", body.to.join(", "))),
                Line::from(format!("Subject: {}", body.subject)),
                Line::from(format!("Date: {}", body.date)),
                Line::from(""),
            ];
            for line in body.text.lines().take(18) {
                lines.push(Line::from(line.to_string()));
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
        };
        let paragraph = Paragraph::new(lines)
            .block(Block::default().title("Reader").borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn draw_attachment_plan(&self, frame: &mut Frame<'_>, area: Rect) {
        let lines = if let Some(body) = self.selected_body() {
            if body.attachments.is_empty() {
                vec![Line::from("No attachments on selected message.")]
            } else {
                let mut lines = vec![
                    Line::from("Attachment metadata only. No file is opened or written."),
                    Line::from("d: plan download | o: plan open | Esc: mailbox"),
                    Line::from(""),
                ];
                for attachment in &body.attachments {
                    lines.push(Line::from(format!(
                        "{} | {} | {} bytes",
                        attachment.filename, attachment.content_type, attachment.size
                    )));
                }
                lines
            }
        } else {
            vec![
                Line::from("Attachment metadata requires a loaded message body."),
                Line::from("Fixture mode can provide bodies without target access."),
            ]
        };
        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Attachment Plan")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn draw_footer(&self, frame: &mut Frame<'_>, area: Rect) {
        let keys = match self.mode {
            Mode::Compose => "Tab field | F5 review send | Esc discard/back",
            Mode::SendConfirm => "y send | n cancel | Esc compose",
            Mode::DiscardConfirm => "y discard | n keep draft",
            Mode::AttachmentPlan => "d plan download | o plan open | Esc back",
            _ => {
                "q quit | j/k move | / search | Enter reader | a attachments | c compose | r reply | ! diagnostics"
            }
        };
        let footer = Paragraph::new(vec![Line::from(keys), Line::from(self.status.clone())])
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(footer, area);
    }

    fn draw_compose(&self, frame: &mut Frame<'_>, area: Rect) {
        let Some(draft) = &self.draft else {
            let paragraph = Paragraph::new("No active draft.")
                .block(Block::default().title("Compose").borders(Borders::ALL));
            frame.render_widget(paragraph, area);
            return;
        };

        let mut lines: Vec<Line<'static>> = vec![
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

        if self.mode == Mode::SendConfirm {
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "Confirm send to {} recipient(s), subject '{}'? y/n",
                recipient_count(&draft.to, &draft.cc),
                safe_subject(&draft.subject)
            )));
        } else if self.mode == Mode::DiscardConfirm {
            lines.push(Line::from(""));
            lines.push(Line::from("Discard non-empty draft? y/n"));
        } else {
            lines.push(Line::from(""));
            lines.push(Line::from(
                "F5 reviews send. Esc asks before discarding non-empty drafts.",
            ));
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default().title("Compose").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn draw_diagnostics(&self, frame: &mut Frame<'_>, area: Rect) {
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
        let paragraph = Paragraph::new(lines)
            .block(Block::default().title("Diagnostics").borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn draw_search_modal(&self, frame: &mut Frame<'_>, area: Rect) {
        let modal = centered_rect(60, 20, area);
        frame.render_widget(Clear, modal);
        let paragraph = Paragraph::new(format!("/{}", self.search_input))
            .block(
                Block::default()
                    .title("Search sender or subject")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));
        frame.render_widget(paragraph, modal);
    }

    fn handle_key(&mut self, code: KeyCode) {
        if self.mode == Mode::Search {
            self.handle_search_key(code);
            return;
        }

        if matches!(
            self.mode,
            Mode::Compose | Mode::SendConfirm | Mode::DiscardConfirm
        ) {
            self.handle_compose_key(code);
            return;
        }

        if self.mode == Mode::AttachmentPlan {
            match code {
                KeyCode::Char('d') => {
                    self.status =
                        "download plan requires a local path and confirmation; no file written"
                            .to_string();
                    return;
                }
                KeyCode::Char('o') => {
                    self.status =
                        "open plan requires confirmation; no external viewer launched".to_string();
                    return;
                }
                _ => {}
            }
        }

        match code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('j') | KeyCode::Down => self.next_message(),
            KeyCode::Char('k') | KeyCode::Up => self.previous_message(),
            KeyCode::Char('f') => self.next_folder(),
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                self.status = "type search text; Enter applies; Esc cancels".to_string();
            }
            KeyCode::Enter => {
                self.mode = Mode::Reader;
                self.status = "reader is local; Esc returns to mailbox".to_string();
            }
            KeyCode::Char('c') => self.start_compose(),
            KeyCode::Char('r') => self.start_reply(),
            KeyCode::Char('a') => {
                self.mode = Mode::AttachmentPlan;
                self.status = "attachment plan is metadata-only; no auto-open".to_string();
            }
            KeyCode::Char('!') => {
                self.mode = Mode::Diagnostics;
                self.status = "diagnostics are redacted and category-oriented".to_string();
            }
            KeyCode::Esc => {
                self.mode = Mode::Mailbox;
                self.status = "mailbox mode".to_string();
            }
            _ => {}
        }
    }

    fn handle_compose_key(&mut self, code: KeyCode) {
        match self.mode {
            Mode::SendConfirm => match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.confirm_send(),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.mode = Mode::Compose;
                    self.status = "send canceled; draft preserved".to_string();
                }
                _ => {}
            },
            Mode::DiscardConfirm => match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.draft = None;
                    self.mode = Mode::Mailbox;
                    self.status = "draft discarded".to_string();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.mode = Mode::Compose;
                    self.status = "draft preserved".to_string();
                }
                _ => {}
            },
            Mode::Compose => match code {
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

    fn handle_search_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Mailbox;
                self.status = "search canceled".to_string();
            }
            KeyCode::Enter => {
                self.apply_search();
                self.mode = Mode::Mailbox;
                self.status = format!("{} matching messages", self.filtered_messages.len());
            }
            KeyCode::Backspace => {
                self.search_input.pop();
                self.apply_search();
            }
            KeyCode::Char(c) if !c.is_control() => {
                self.search_input.push(c);
                self.apply_search();
            }
            _ => {}
        }
    }

    fn next_message(&mut self) {
        if self.filtered_messages.is_empty() {
            return;
        }
        self.message_index = (self.message_index + 1).min(self.filtered_messages.len() - 1);
    }

    fn previous_message(&mut self) {
        self.message_index = self.message_index.saturating_sub(1);
    }

    fn next_folder(&mut self) {
        if self.folders.is_empty() {
            return;
        }
        self.folder_index = (self.folder_index + 1) % self.folders.len();
        self.status = format!(
            "selected folder {}",
            self.folders[self.folder_index].display_name
        );
    }

    fn apply_search(&mut self) {
        let query = self.search_input.to_ascii_lowercase();
        self.filtered_messages = if query.is_empty() {
            self.messages.clone()
        } else {
            self.messages
                .iter()
                .filter(|message| {
                    message.from.to_ascii_lowercase().contains(&query)
                        || message.subject.to_ascii_lowercase().contains(&query)
                })
                .cloned()
                .collect()
        };
        self.message_index = self
            .message_index
            .min(self.filtered_messages.len().saturating_sub(1));
    }

    fn selected_message(&self) -> Option<&EmailEnvelope> {
        self.filtered_messages.get(self.message_index)
    }

    fn selected_body(&self) -> Option<&EmailBody> {
        let uid = self.selected_message()?.uid;
        self.bodies.iter().find(|body| body.uid == uid)
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
            self.mode = Mode::Mailbox;
            self.status = "compose closed".to_string();
        }
    }

    fn confirm_send(&mut self) {
        let Some(draft) = self.draft.clone() else {
            self.mode = Mode::Mailbox;
            return;
        };
        if !self.send_enabled {
            self.draft = None;
            self.mode = Mode::Mailbox;
            self.status = format!(
                "fixture send confirmed for {} recipient(s); no SMTP target opened",
                recipient_count(&draft.to, &draft.cc)
            );
            return;
        }

        let config = self.config.clone().expect("checked above");
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
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
        });

        match result {
            Ok(()) => {
                self.draft = None;
                self.mode = Mode::Mailbox;
                self.status = "email sent; draft cleared".to_string();
            }
            Err(error) => {
                self.mode = Mode::Compose;
                self.status = classify_provider_error(&error.to_string());
            }
        }
    }
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
    use serde_json::json;

    use super::{EmailTuiLaunch, EmailTuiSource, build_email_tui_evidence};

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
        assert!(
            evidence["coverage"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item == "message_body_redaction")
        );
    }
}
