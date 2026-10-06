#![allow(clippy::result_large_err)]

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::Read;
use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use voidb_core::{
    CapabilityApprovalField, CapabilityApprovalRiskEmphasis, CapabilityApprovalSchema,
    CapabilityApprovalValueType, CapabilityAuthorizationMetadata, CapabilityConstraintKind,
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityExecutionMode,
    CapabilityInvocation, CapabilityInvocationResult, CapabilityRiskLevel,
    CapabilitySessionHandoff, CredentialClass, InvocationOutputPage, InvocationStatus,
    LocalPathError, LocalPathScope, RedactionStatus, TargetSystemFailure,
};

use crate::config::{EmailConfig, EmailProtocol, SecurityType};
use crate::policy::{
    EmailExecutionMode, EmailGuardedOperation, EmailMessageIdentity, OutboundAttachmentSummary,
    RecipientGuardrails, message_mutation_preview, require_guarded_execution, send_preview,
    summarize_recipients, validate_attachment_filename, validate_idempotency_key,
    validate_outbound_content,
};
use crate::service::{EmailService, SendAttachment, StructuredEmail};
use crate::types::{
    Attachment, EmailBody, EmailDeleteMode, EmailEnvelope, EmailFlagAction, EmailFolder,
};

const PLUGIN_ID: &str = "email";
const DEFAULT_MESSAGE_LIMIT: u32 = 25;
const MAX_MESSAGE_LIMIT: u32 = 100;
const DEFAULT_TEXT_LIMIT_BYTES: usize = 64 * 1024;
const MAX_TEXT_LIMIT_BYTES: usize = 256 * 1024;
const MAX_MUTATION_MESSAGES: usize = 100;
const MAX_REFERENCES: usize = 20;
const IDEMPOTENCY_CACHE_LIMIT: usize = 256;

pub fn email_capabilities() -> Vec<CapabilityDefinition> {
    vec![
        capability(
            "diagnostics",
            "Return agent-safe email profile diagnostics without opening a network connection.",
            empty_input_schema(),
            json!({
                "type": "object",
                "required": [
                    "protocol",
                    "receive_security",
                    "receive_port",
                    "smtp_security",
                    "smtp_port",
                    "verify_tls",
                    "delete_deferred",
                    "send_deferred",
                    "network_checked"
                ],
                "properties": {
                    "protocol": protocol_schema(),
                    "receive_security": security_schema(),
                    "receive_port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                    "smtp_security": security_schema(),
                    "smtp_port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                    "verify_tls": { "type": "boolean" },
                    "delete_deferred": { "type": "boolean" },
                    "send_deferred": { "type": "boolean" },
                    "network_checked": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "email.diagnostics"],
            false,
            false,
            Some(5_000),
        ),
        capability(
            "folders",
            "List mailbox folders with message and unread counts.",
            empty_input_schema(),
            json!({
                "type": "object",
                "required": ["folders", "folder_count"],
                "properties": {
                    "folders": { "type": "array", "items": folder_schema() },
                    "folder_count": { "type": "integer", "minimum": 0 }
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "email.folders"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "list",
            "List message envelopes from one folder with bounded pagination.",
            list_input_schema(false),
            message_list_output_schema(false),
            vec!["connection.read", "email.list"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "search",
            "Search a bounded page of message envelopes by sender or subject.",
            list_input_schema(true),
            message_list_output_schema(true),
            vec!["connection.read", "email.search"],
            false,
            false,
            Some(30_000),
        ),
        capability(
            "fetch",
            "Fetch one message body without marking it read.",
            json!({
                "type": "object",
                "required": ["folder", "uid"],
                "properties": {
                    "folder": { "type": "string", "minLength": 1 },
                    "uid": { "type": "integer", "minimum": 1 },
                    "include_html": { "type": "boolean", "default": false },
                    "max_text_bytes": text_limit_schema(),
                    "max_html_bytes": text_limit_schema()
                },
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": message_body_schema()
                },
                "additionalProperties": false
            }),
            vec!["connection.read", "email.fetch"],
            false,
            false,
            Some(30_000),
        ),
        planned_email_capability(),
        guarded_email_capability(
            EmailGuardedOperation::Send,
            "Send a structured message after a redacted dry-run preview and acknowledgement.",
            send_input_schema(),
            send_output_schema(),
            CapabilityExecutionMode::Stateless,
            None,
            Some(120_000),
        ),
        guarded_email_capability(
            EmailGuardedOperation::Move,
            "Move stable IMAP UIDs after UIDVALIDITY and optional MODSEQ validation.",
            mailbox_mutation_input_schema("move"),
            mailbox_mutation_output_schema(),
            CapabilityExecutionMode::Stateless,
            None,
            Some(60_000),
        ),
        guarded_email_capability(
            EmailGuardedOperation::Delete,
            "Move stable IMAP UIDs to Trash or explicitly UID-expunge them.",
            mailbox_mutation_input_schema("delete"),
            mailbox_mutation_output_schema(),
            CapabilityExecutionMode::Stateless,
            None,
            Some(60_000),
        ),
        guarded_email_capability(
            EmailGuardedOperation::SetFlags,
            "Apply allowlisted flags to stable IMAP UIDs with bounded partial-failure reporting.",
            mailbox_mutation_input_schema("set_flags"),
            mailbox_mutation_output_schema(),
            CapabilityExecutionMode::Stateless,
            None,
            Some(60_000),
        ),
        capability(
            "attachments",
            "List bounded attachment metadata for one stable IMAP message identity.",
            attachment_identity_input_schema(),
            attachment_list_output_schema(),
            vec!["connection.read", "email.attachments"],
            false,
            false,
            Some(30_000),
        ),
        guarded_email_capability(
            EmailGuardedOperation::DownloadAttachment,
            "Write one attachment to an approved local destination with no replacement.",
            attachment_download_input_schema(),
            attachment_download_output_schema(),
            CapabilityExecutionMode::Stateless,
            None,
            Some(120_000),
        ),
        email_idle_capability(),
    ]
}

pub async fn invoke_email_capability(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    if invocation.plugin_id != PLUGIN_ID {
        return Err(validation_error(
            "validation.plugin_mismatch",
            "Invocation plugin_id does not match Email.",
            json!({ "expected": PLUGIN_ID, "actual": invocation.plugin_id }),
        ));
    }

    match invocation.capability_id.as_str() {
        "diagnostics" => Ok(diagnostics_result(config, invocation.id)),
        "folders" => invoke_folders(config, invocation).await,
        "list" => invoke_list(config, invocation, None).await,
        "search" => {
            let query = required_string(&invocation.input, "query")?;
            invoke_list(config, invocation, Some(query)).await
        }
        "fetch" => invoke_fetch(config, invocation).await,
        "draft" => invoke_send(config, invocation, false).await,
        "send" => invoke_send(config, invocation, true).await,
        "move" => invoke_mailbox_mutation(config, invocation, EmailGuardedOperation::Move).await,
        "delete" => {
            invoke_mailbox_mutation(config, invocation, EmailGuardedOperation::Delete).await
        }
        "set_flags" => {
            invoke_mailbox_mutation(config, invocation, EmailGuardedOperation::SetFlags).await
        }
        "attachments" => invoke_attachments(config, invocation).await,
        "download_attachment" => invoke_download_attachment(config, invocation).await,
        "idle" => Err(unavailable_error(
            "unavailable.session_required",
            "Email IDLE is available only through a persistent Agent Session.",
            json!({ "capability_id": "idle", "execution_mode": "session_only" }),
        )),
        other => Err(unavailable_error(
            "unavailable.capability_not_found",
            "Email capability was not found.",
            json!({ "capability_id": other }),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn capability(
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    destructive: bool,
    supports_dry_run: bool,
    default_timeout_ms: Option<u64>,
) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.to_string(),
        id: id.to_string(),
        description: description.to_string(),
        input_schema,
        output_schema,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        authorization: email_authorization_metadata(id),
        risk: CapabilityRiskLevel::from_destructive(destructive),
        destructive,
        streaming: false,
        execution_mode: voidb_core::CapabilityExecutionMode::Stateless,
        session_handoff: None,
        connection_required: true,
        required_secret_classes: Vec::<CredentialClass>::new(),
        supports_dry_run,
        default_timeout_ms,
    }
}

fn planned_email_capability() -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.into(),
        id: "draft".into(),
        description:
            "Validate and return a redacted message plan without contacting SMTP or persisting a draft."
                .into(),
        input_schema: send_input_schema(),
        output_schema: send_output_schema(),
        permissions: vec!["connection.read".into(), "email.draft".into()],
        authorization: CapabilityAuthorizationMetadata::declared().with_note(
            "Draft planning is local validation only and returns no addresses, subject, body, paths, or attachment bytes.",
        ),
        risk: CapabilityRiskLevel::ReadOnly,
        destructive: false,
        streaming: false,
        execution_mode: CapabilityExecutionMode::Stateless,
        session_handoff: None,
        connection_required: false,
        required_secret_classes: Vec::new(),
        supports_dry_run: false,
        default_timeout_ms: Some(5_000),
    }
}

fn guarded_email_capability(
    operation: EmailGuardedOperation,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    execution_mode: CapabilityExecutionMode,
    session_handoff: Option<CapabilitySessionHandoff>,
    default_timeout_ms: Option<u64>,
) -> CapabilityDefinition {
    let policy = operation.policy();
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.into(),
        id: policy.capability_id.into(),
        description: description.into(),
        input_schema,
        output_schema,
        permissions: vec!["connection.write".into(), policy.permission.into()],
        authorization: guarded_email_authorization(operation),
        risk: policy.risk,
        destructive: operation == EmailGuardedOperation::Delete,
        streaming: false,
        execution_mode,
        session_handoff,
        connection_required: true,
        required_secret_classes: Vec::new(),
        supports_dry_run: policy.supports_dry_run(),
        default_timeout_ms,
    }
}

fn guarded_email_authorization(
    operation: EmailGuardedOperation,
) -> CapabilityAuthorizationMetadata {
    let destructive = CapabilityApprovalRiskEmphasis::Destructive;
    let fields = match operation {
        EmailGuardedOperation::Send => vec![
            CapabilityApprovalField::new(
                "/to",
                "To recipients",
                CapabilityApprovalValueType::StringList,
            )
            .required()
            .with_constraint(CapabilityConstraintKind::Subset)
            .with_risk_emphasis(destructive),
            CapabilityApprovalField::new(
                "/cc",
                "Cc recipients",
                CapabilityApprovalValueType::StringList,
            )
            .with_constraint(CapabilityConstraintKind::Subset),
            CapabilityApprovalField::new(
                "/bcc",
                "Bcc recipients",
                CapabilityApprovalValueType::StringList,
            )
            .with_constraint(CapabilityConstraintKind::Subset)
            .with_risk_emphasis(destructive),
            CapabilityApprovalField::new(
                "/local_root",
                "Attachment source root",
                CapabilityApprovalValueType::Path,
            )
            .with_constraint(CapabilityConstraintKind::Exact),
            CapabilityApprovalField::new(
                "/attachments",
                "Attachment sources",
                CapabilityApprovalValueType::Json,
            )
            .with_constraint(CapabilityConstraintKind::Subset),
        ],
        EmailGuardedOperation::Move => message_approval_fields(true, true),
        EmailGuardedOperation::Delete => message_approval_fields(true, true),
        EmailGuardedOperation::SetFlags => message_approval_fields(true, false),
        EmailGuardedOperation::DownloadAttachment => {
            vec![
                CapabilityApprovalField::new(
                    "/folder",
                    "Mailbox folder",
                    CapabilityApprovalValueType::Path,
                )
                .required()
                .with_constraint(CapabilityConstraintKind::Exact),
                CapabilityApprovalField::new(
                    "/uid_validity",
                    "Mailbox UIDVALIDITY",
                    CapabilityApprovalValueType::Integer,
                )
                .required(),
                CapabilityApprovalField::new(
                    "/uid",
                    "Message UID",
                    CapabilityApprovalValueType::Integer,
                )
                .required(),
                CapabilityApprovalField::new(
                    "/attachment_index",
                    "Attachment index",
                    CapabilityApprovalValueType::Integer,
                )
                .required(),
                CapabilityApprovalField::new(
                    "/local_root",
                    "Attachment destination root",
                    CapabilityApprovalValueType::Path,
                )
                .required(),
                CapabilityApprovalField::new(
                    "/local_path",
                    "Attachment destination",
                    CapabilityApprovalValueType::Path,
                )
                .required()
                .with_risk_emphasis(destructive),
            ]
        }
    };
    CapabilityAuthorizationMetadata::declared()
        .with_note(
            "Email writes require scoped approval, redacted preview support, an invocation acknowledgement, and an idempotency key.",
        )
        .with_approval_schema(CapabilityApprovalSchema::v1(fields))
}

fn message_approval_fields(
    destructive: bool,
    include_destination: bool,
) -> Vec<CapabilityApprovalField> {
    let mut messages = CapabilityApprovalField::new(
        "/messages",
        "Stable message identities",
        CapabilityApprovalValueType::Json,
    )
    .required()
    .with_constraint(CapabilityConstraintKind::Subset);
    if destructive {
        messages = messages.with_risk_emphasis(CapabilityApprovalRiskEmphasis::Destructive);
    }
    let mut fields = vec![messages];
    if include_destination {
        fields.push(
            CapabilityApprovalField::new(
                "/destination_folder",
                "Destination mailbox",
                CapabilityApprovalValueType::Path,
            )
            .with_constraint(CapabilityConstraintKind::Exact)
            .with_risk_emphasis(CapabilityApprovalRiskEmphasis::Destructive),
        );
    }
    fields
}

fn email_idle_capability() -> CapabilityDefinition {
    let (purpose, contract) = crate::agent_session::email_idle_session_contract();
    let handoff = CapabilitySessionHandoff::new(
        purpose.clone(),
        contract
            .operations
            .capabilities()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .with_live_session(contract.clone());
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.into(),
        id: "idle".into(),
        description:
            "Observe bounded IMAP mailbox changes with reconnect, heartbeat, cursor, cancellation, and close semantics."
                .into(),
        input_schema: live_read_schema(),
        output_schema: live_batch_schema(),
        permissions: vec!["connection.read".into(), "email.idle".into()],
        authorization: CapabilityAuthorizationMetadata::declared()
            .with_session_purposes(vec![purpose])
            .with_note("IMAP IDLE session scope is one mailbox and reconnect resumes from a UIDVALIDITY/UID checkpoint.")
            .with_approval_schema(CapabilityApprovalSchema::v1(vec![
                CapabilityApprovalField::new(
                    "/resource/folder",
                    "Mailbox folder",
                    CapabilityApprovalValueType::Path,
                )
                .required()
                .with_constraint(CapabilityConstraintKind::Exact),
            ])),
        risk: CapabilityRiskLevel::ReadOnly,
        destructive: false,
        streaming: true,
        execution_mode: CapabilityExecutionMode::SessionOnly,
        session_handoff: Some(handoff),
        connection_required: true,
        required_secret_classes: Vec::new(),
        supports_dry_run: false,
        default_timeout_ms: Some(30_000),
    }
}

fn email_authorization_metadata(id: &str) -> voidb_core::CapabilityAuthorizationMetadata {
    let fields = match id {
        "list" | "search" => vec![
            voidb_core::CapabilityApprovalField::new(
                "/folder",
                "Mailbox folder",
                voidb_core::CapabilityApprovalValueType::Path,
            )
            .with_constraint(voidb_core::CapabilityConstraintKind::Prefix),
        ],
        "fetch" => vec![
            voidb_core::CapabilityApprovalField::new(
                "/folder",
                "Mailbox folder",
                voidb_core::CapabilityApprovalValueType::Path,
            )
            .required()
            .with_constraint(voidb_core::CapabilityConstraintKind::Prefix),
            voidb_core::CapabilityApprovalField::new(
                "/uid",
                "Message UID",
                voidb_core::CapabilityApprovalValueType::Integer,
            )
            .required(),
        ],
        _ => Vec::new(),
    };
    let metadata = voidb_core::CapabilityAuthorizationMetadata::declared()
        .with_note("Read operations are bounded and cannot use Email write permissions.");
    if fields.is_empty() {
        metadata
    } else {
        metadata.with_approval_schema(voidb_core::CapabilityApprovalSchema::v1(fields))
    }
}

fn diagnostics_result(config: &EmailConfig, invocation_id: String) -> CapabilityInvocationResult {
    let output = json!({
        "protocol": protocol_label(config.protocol),
        "receive_security": security_label(config.receive_security),
        "receive_port": config.receive.port,
        "smtp_security": security_label(config.smtp_security),
        "smtp_port": config.smtp.port,
        "verify_tls": config.verify_tls,
        "delete_deferred": false,
        "send_deferred": false,
        "network_checked": false
    });
    result(invocation_id, output.clone(), output, None)
}

async fn invoke_folders(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let mut service = connected_service(config, "email.folders_failed").await?;
    let folders = service
        .list_folders_direct()
        .await
        .map_err(|e| target_error("email.folders_failed", e, config))?;
    let folder_count = folders.len();
    let output_folders = folders.into_iter().map(folder_output).collect::<Vec<_>>();
    let output = json!({
        "folders": output_folders,
        "folder_count": folder_count
    });
    let summary = json!({ "folder_count": folder_count });

    Ok(result(invocation.id, output, summary, None))
}

async fn invoke_list(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
    query: Option<String>,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let folder = optional_string(&invocation.input, "folder")?.unwrap_or_else(|| "INBOX".into());
    let unread_only = optional_bool(&invocation.input, "unread_only")?.unwrap_or(false);
    let page_request = page_request(&invocation)?;
    let mut service = connected_service(config, "email.list_failed").await?;
    let (messages, total) = if unread_only {
        service
            .list_unseen_messages_direct(folder.clone(), page_request.page, page_request.limit)
            .await
    } else {
        service
            .list_messages_direct(folder.clone(), page_request.page, page_request.limit)
            .await
    }
    .map_err(|e| target_error("email.list_failed", e, config))?;

    let source_count = messages.len();
    let messages = if let Some(query) = &query {
        let query = query.to_ascii_lowercase();
        messages
            .into_iter()
            .filter(|message| envelope_matches(message, &query))
            .collect::<Vec<_>>()
    } else {
        messages
    };
    let message_count = messages.len();
    let next_cursor = next_page_cursor(page_request.page, page_request.limit, total);
    let truncated = next_cursor.is_some();
    let output_messages = messages
        .into_iter()
        .map(envelope_output)
        .collect::<Vec<_>>();
    let output = json!({
        "folder": folder,
        "messages": output_messages,
        "message_count": message_count,
        "total": total,
        "page": page_request.page,
        "limit": page_request.limit,
        "cursor": page_request.cursor,
        "next_cursor": next_cursor,
        "truncated": truncated,
        "unread_only": unread_only,
        "query": query,
        "search_scope": if query.is_some() { "paged_envelope" } else { "none" },
        "searched_count": source_count
    });
    let page = output["next_cursor"]
        .as_str()
        .map(|next_cursor| InvocationOutputPage {
            next_cursor: Some(next_cursor.to_string()),
        });
    let summary = json!({
        "folder": output["folder"],
        "message_count": message_count,
        "total": total,
        "truncated": truncated,
        "next_cursor": output["next_cursor"],
        "unread_only": unread_only,
        "query": output["query"]
    });

    Ok(result(invocation.id, output, summary, page))
}

async fn invoke_fetch(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let folder = required_string(&invocation.input, "folder")?;
    let uid = required_u32(&invocation.input, "uid")?;
    let include_html = optional_bool(&invocation.input, "include_html")?.unwrap_or(false);
    let max_text_bytes = text_limit(&invocation.input, "max_text_bytes")?;
    let max_html_bytes = text_limit(&invocation.input, "max_html_bytes")?;
    let mut service = connected_service(config, "email.fetch_failed").await?;
    let body = service
        .fetch_body_read_only_direct(folder.clone(), uid)
        .await
        .map_err(|e| target_error("email.fetch_failed", e, config))?;
    let output = json!({
        "message": body_output(body, include_html, max_text_bytes, max_html_bytes)
    });
    let summary = json!({
        "uid": output["message"]["uid"],
        "folder": folder,
        "subject": output["message"]["subject"],
        "text_truncated": output["message"]["text_truncated"],
        "html_truncated": output["message"]["html_truncated"],
        "attachment_count": output["message"]["attachments"].as_array().map(Vec::len).unwrap_or(0)
    });

    Ok(result(invocation.id, output, summary, None))
}

#[derive(Debug)]
struct SendRequest {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    reply_to: Option<String>,
    subject: String,
    text_body: String,
    html_body: Option<String>,
    in_reply_to: Option<String>,
    references: Vec<String>,
    idempotency_key: String,
    local_root: Option<String>,
    attachments: Vec<OutboundAttachmentInput>,
    guardrails: RecipientGuardrails,
}

#[derive(Debug)]
struct OutboundAttachmentInput {
    local_path: String,
    filename: String,
    content_type: Option<String>,
    byte_size: u64,
}

async fn invoke_send(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
    apply_capability: bool,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let request = parse_send_request(&invocation.input)?;
    validate_idempotency_key(&request.idempotency_key).map_err(policy_validation_error)?;
    validate_thread_headers(request.in_reply_to.as_deref(), &request.references)?;
    let attachment_summaries = request
        .attachments
        .iter()
        .map(|attachment| OutboundAttachmentSummary {
            byte_size: attachment.byte_size,
        })
        .collect::<Vec<_>>();
    validate_outbound_content(
        &request.subject,
        &request.text_body,
        request.html_body.as_deref(),
        &attachment_summaries,
    )
    .map_err(policy_validation_error)?;
    let recipients = summarize_recipients(
        &config.email,
        &request.to,
        &request.cc,
        &request.bcc,
        &request.guardrails,
    )
    .map_err(policy_validation_error)?;
    let mut preview = send_preview(
        &recipients,
        &request.subject,
        &request.text_body,
        request.html_body.as_deref(),
        &attachment_summaries,
    );
    preview["operation"] = json!(if apply_capability { "send" } else { "draft" });

    if !apply_capability {
        let output = json!({
            "status": "planned",
            "dry_run": true,
            "sent": false,
            "idempotent_replay": false,
            "preview": preview
        });
        return Ok(result(
            invocation.id,
            output.clone(),
            output_summary_for_send(&output),
            None,
        ));
    }

    let mode = require_guarded_execution(EmailGuardedOperation::Send, &invocation.controls)
        .map_err(policy_validation_error)?;
    if mode == EmailExecutionMode::Preview {
        let output = json!({
            "status": "previewed",
            "dry_run": true,
            "sent": false,
            "idempotent_replay": false,
            "preview": preview
        });
        return Ok(result(
            invocation.id,
            output.clone(),
            output_summary_for_send(&output),
            None,
        ));
    }

    let fingerprint = invocation_fingerprint(&invocation.input);
    if let Some(output) = idempotency_lookup("send", &request.idempotency_key, &fingerprint)? {
        let mut output = output;
        output["idempotent_replay"] = json!(true);
        return Ok(result(
            invocation.id,
            output.clone(),
            output_summary_for_send(&output),
            None,
        ));
    }

    let attachments = load_outbound_attachments(
        request.local_root.as_deref(),
        &request.attachments,
        &invocation.id,
    )?;
    let mut service = EmailService::new_direct()
        .map_err(|error| target_error("email.send_failed", error, config))?;
    let message_id = service
        .send_structured_email_direct(
            config.clone(),
            StructuredEmail {
                from: config.email.clone(),
                to: request.to,
                cc: request.cc,
                bcc: request.bcc,
                reply_to: request.reply_to,
                subject: request.subject,
                text_body: request.text_body,
                html_body: request.html_body,
                in_reply_to: request.in_reply_to,
                references: request.references,
                attachments,
            },
        )
        .await
        .map_err(|error| target_error("email.send_failed", error, config))?;
    let output = json!({
        "status": "accepted",
        "dry_run": false,
        "sent": true,
        "idempotent_replay": false,
        "message_id": message_id,
        "recipient_count": recipients.recipient_count,
        "attachment_count": request.attachments.len(),
        "content_redacted": true
    });
    idempotency_record("send", request.idempotency_key, fingerprint, output.clone());
    Ok(result(
        invocation.id,
        output.clone(),
        output_summary_for_send(&output),
        None,
    ))
}

async fn invoke_mailbox_mutation(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
    operation: EmailGuardedOperation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    require_imap(config, operation.policy().capability_id)?;
    let identities = parse_message_identities(&invocation.input)?;
    let idempotency_key = required_string(&invocation.input, "idempotency_key")?;
    validate_idempotency_key(&idempotency_key).map_err(policy_validation_error)?;
    let mut destination = optional_string(&invocation.input, "destination_folder")?;
    let flags = optional_string_array(&invocation.input, "flags")?.unwrap_or_default();
    let flag_action = parse_flag_action(&invocation.input)?;
    let delete_mode = parse_delete_mode(&invocation.input)?;
    if operation == EmailGuardedOperation::Delete
        && delete_mode == EmailDeleteMode::Trash
        && destination.is_none()
    {
        destination = Some("Trash".into());
    }
    let preview =
        message_mutation_preview(operation, &identities, destination.is_some(), flags.len());
    let mode = require_guarded_execution(operation, &invocation.controls)
        .map_err(policy_validation_error)?;
    if mode == EmailExecutionMode::Preview {
        let output = mutation_output(operation, true, &identities, Vec::new(), preview);
        return Ok(result(
            invocation.id,
            output.clone(),
            mutation_summary(&output),
            None,
        ));
    }

    let fingerprint = invocation_fingerprint(&invocation.input);
    if let Some(output) = idempotency_lookup(
        operation.policy().capability_id,
        &idempotency_key,
        &fingerprint,
    )? {
        let mut output = output;
        output["idempotent_replay"] = json!(true);
        return Ok(result(
            invocation.id,
            output.clone(),
            mutation_summary(&output),
            None,
        ));
    }

    let mut service = connected_service(config, "email.mutation_failed").await?;
    let mut outcomes = Vec::with_capacity(identities.len());
    for (index, identity) in identities.iter().cloned().enumerate() {
        let operation_result = match operation {
            EmailGuardedOperation::Move => {
                let destination = destination.as_deref().ok_or_else(|| {
                    validation_error(
                        "validation.destination_folder_required",
                        "Move requires a destination folder.",
                        json!({ "field": "destination_folder" }),
                    )
                })?;
                service
                    .move_message_direct(identity, destination.to_string())
                    .await
            }
            EmailGuardedOperation::Delete => {
                let expunge = delete_mode == EmailDeleteMode::Expunge;
                service
                    .delete_message_by_identity_direct(identity, expunge, destination.clone())
                    .await
            }
            EmailGuardedOperation::SetFlags => {
                service
                    .set_message_flags_direct(identity, flag_action, flags.clone())
                    .await
            }
            _ => unreachable!("mailbox mutation operation"),
        };
        outcomes.push(match operation_result {
            Ok(()) => json!({ "index": index, "status": "succeeded" }),
            Err(error) => json!({
                "index": index,
                "status": "failed",
                "error_code": safe_mutation_error_code(&error)
            }),
        });
    }
    let output = mutation_output(operation, false, &identities, outcomes, preview);
    idempotency_record(
        operation.policy().capability_id,
        idempotency_key,
        fingerprint,
        output.clone(),
    );
    Ok(result(
        invocation.id,
        output.clone(),
        mutation_summary(&output),
        None,
    ))
}

async fn invoke_attachments(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    require_imap(config, "attachments")?;
    let identity = parse_message_identity(&invocation.input)?;
    let mut service = connected_service(config, "email.attachments_failed").await?;
    let body = service
        .fetch_body_by_identity_direct(identity.clone())
        .await
        .map_err(|error| target_error("email.attachments_failed", error, config))?;
    let attachments = body
        .attachments
        .into_iter()
        .enumerate()
        .map(|(index, attachment)| attachment_metadata(index, attachment))
        .collect::<Vec<_>>();
    let output = json!({
        "folder": identity.folder,
        "uid_validity": identity.uid_validity,
        "uid": identity.uid,
        "attachment_count": attachments.len(),
        "attachments": attachments,
        "bytes_omitted": true
    });
    Ok(result(
        invocation.id,
        output.clone(),
        json!({
            "uid_validity": output["uid_validity"],
            "uid": output["uid"],
            "attachment_count": output["attachment_count"],
            "bytes_omitted": true
        }),
        None,
    ))
}

async fn invoke_download_attachment(
    config: &EmailConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    require_imap(config, "download_attachment")?;
    let identity = parse_message_identity(&invocation.input)?;
    let attachment_index = required_u32_allow_zero(&invocation.input, "attachment_index")? as usize;
    let local_root = required_string(&invocation.input, "local_root")?;
    let local_path = required_string(&invocation.input, "local_path")?;
    let idempotency_key = required_string(&invocation.input, "idempotency_key")?;
    validate_idempotency_key(&idempotency_key).map_err(policy_validation_error)?;
    let expected_sha256 = optional_string(&invocation.input, "expected_sha256")?;
    if let Some(expected) = &expected_sha256 {
        validate_sha256(expected)?;
    }
    let mode = require_guarded_execution(
        EmailGuardedOperation::DownloadAttachment,
        &invocation.controls,
    )
    .map_err(policy_validation_error)?;
    let scope_id = format!("local-scope:{}", invocation.id);
    let preview = json!({
        "operation": "download_attachment",
        "dry_run": true,
        "attachment_index": attachment_index,
        "destination_scope": scope_id,
        "no_overwrite": true,
        "message_content_redacted": true
    });
    if mode == EmailExecutionMode::Preview {
        let output = json!({
            "status": "previewed",
            "dry_run": true,
            "written": false,
            "idempotent_replay": false,
            "preview": preview
        });
        return Ok(result(invocation.id, output.clone(), output.clone(), None));
    }
    let fingerprint = invocation_fingerprint(&invocation.input);
    if let Some(output) = idempotency_lookup("download_attachment", &idempotency_key, &fingerprint)?
    {
        let mut output = output;
        output["idempotent_replay"] = json!(true);
        return Ok(result(invocation.id, output.clone(), output.clone(), None));
    }
    let destination = LocalPathScope::new(&local_root)
        .map_err(|error| local_path_error(&scope_id, "write_new_file", error))?;
    destination
        .validate_new_file(&local_path)
        .map_err(|error| local_path_error(&scope_id, "write_new_file", error))?;
    let mut service = connected_service(config, "email.attachment_download_failed").await?;
    let body = service
        .fetch_body_by_identity_direct(identity)
        .await
        .map_err(|error| target_error("email.attachment_download_failed", error, config))?;
    let attachment = body
        .attachments
        .into_iter()
        .nth(attachment_index)
        .ok_or_else(|| {
            validation_error(
                "validation.attachment_index_invalid",
                "Attachment index does not exist for the selected message.",
                json!({ "attachment_index": attachment_index }),
            )
        })?;
    validate_attachment_filename(&attachment.filename).map_err(policy_validation_error)?;
    if attachment.size as u64 > crate::policy::MAX_ATTACHMENT_BYTES {
        return Err(validation_error(
            "validation.attachment_too_large",
            "Attachment exceeds the guarded download byte limit.",
            json!({ "maximum_bytes": crate::policy::MAX_ATTACHMENT_BYTES }),
        ));
    }
    let sha256 = hex_sha256(&attachment.data);
    if expected_sha256
        .as_ref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(&sha256))
    {
        return Err(capability_error(
            CapabilityErrorCategory::Conflict,
            "conflict.attachment_checksum",
            "Attachment checksum did not match the approved expectation.",
            json!({ "checksum_match": false }),
            None,
            false,
        ));
    }
    destination
        .write_new_file(&local_path, &attachment.data)
        .map_err(|error| local_path_error(&scope_id, "write_new_file", error))?;
    let output = json!({
        "status": "written",
        "dry_run": false,
        "written": true,
        "idempotent_replay": false,
        "bytes": attachment.data.len(),
        "sha256": sha256,
        "content_type": attachment.content_type,
        "local_scope_id": scope_id,
        "no_overwrite": true,
        "progress": {
            "bytes_completed": attachment.data.len(),
            "terminal": true
        }
    });
    idempotency_record(
        "download_attachment",
        idempotency_key,
        fingerprint,
        output.clone(),
    );
    Ok(result(
        invocation.id,
        output.clone(),
        json!({
            "status": output["status"],
            "written": true,
            "bytes": output["bytes"],
            "sha256": output["sha256"],
            "local_scope_id": output["local_scope_id"]
        }),
        None,
    ))
}

async fn connected_service(
    config: &EmailConfig,
    code: &str,
) -> Result<EmailService, CapabilityError> {
    let mut service = EmailService::new_direct().map_err(|e| target_error(code, e, config))?;
    service
        .connect_direct(config.clone())
        .await
        .map_err(|e| target_error(code, e, config))?;
    Ok(service)
}

fn parse_send_request(input: &Value) -> Result<SendRequest, CapabilityError> {
    let attachments = input
        .get("attachments")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| {
                    validation_error(
                        "validation.attachments_invalid",
                        "Attachments must be an array.",
                        json!({ "field": "attachments" }),
                    )
                })?
                .iter()
                .map(|attachment| {
                    let local_path = required_string(attachment, "local_path")?;
                    let filename = optional_string(attachment, "filename")?
                        .unwrap_or_else(|| local_filename(&local_path));
                    validate_attachment_filename(&filename).map_err(policy_validation_error)?;
                    let byte_size = required_u64(attachment, "byte_size")?;
                    Ok(OutboundAttachmentInput {
                        local_path,
                        filename,
                        content_type: optional_string(attachment, "content_type")?,
                        byte_size,
                    })
                })
                .collect::<Result<Vec<_>, CapabilityError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let maximum_recipients = optional_u64(input, "maximum_recipients")?
        .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
        .unwrap_or(crate::policy::MAX_RECIPIENTS);
    let allowed_domains = optional_string_array(input, "allowed_domains")?.unwrap_or_default();
    let blocked_domains = optional_string_array(input, "blocked_domains")?.unwrap_or_default();
    let guardrails = RecipientGuardrails::new(maximum_recipients, allowed_domains, blocked_domains)
        .map_err(policy_validation_error)?;
    Ok(SendRequest {
        to: required_string_array(input, "to")?,
        cc: optional_string_array(input, "cc")?.unwrap_or_default(),
        bcc: optional_string_array(input, "bcc")?.unwrap_or_default(),
        reply_to: optional_string(input, "reply_to")?,
        subject: required_string_allow_empty(input, "subject")?,
        text_body: required_string_allow_empty(input, "text_body")?,
        html_body: optional_string_allow_empty(input, "html_body")?,
        in_reply_to: optional_string(input, "in_reply_to")?,
        references: optional_string_array(input, "references")?.unwrap_or_default(),
        idempotency_key: required_string(input, "idempotency_key")?,
        local_root: optional_string(input, "local_root")?,
        attachments,
        guardrails,
    })
}

fn load_outbound_attachments(
    local_root: Option<&str>,
    inputs: &[OutboundAttachmentInput],
    invocation_id: &str,
) -> Result<Vec<SendAttachment>, CapabilityError> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let root = local_root.ok_or_else(|| {
        validation_error(
            "validation.local_root_required",
            "Attachment upload requires an approved local root.",
            json!({ "field": "local_root" }),
        )
    })?;
    let scope_id = format!("local-scope:{invocation_id}");
    let scope = LocalPathScope::new(root)
        .map_err(|error| local_path_error(&scope_id, "read_file", error))?;
    let mut attachments = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut source = scope
            .open_existing_file(&input.local_path)
            .map_err(|error| local_path_error(&scope_id, "read_file", error))?;
        if source.len() != input.byte_size {
            return Err(capability_error(
                CapabilityErrorCategory::Conflict,
                "conflict.attachment_size_changed",
                "Attachment size changed after preview.",
                json!({ "local_scope_id": scope_id, "size_match": false }),
                None,
                true,
            ));
        }
        if source.len() > crate::policy::MAX_ATTACHMENT_BYTES {
            return Err(validation_error(
                "validation.attachment_too_large",
                "Attachment exceeds the guarded upload byte limit.",
                json!({ "maximum_bytes": crate::policy::MAX_ATTACHMENT_BYTES }),
            ));
        }
        let mut data = Vec::with_capacity(source.len() as usize);
        source.read_to_end(&mut data).map_err(|_| {
            capability_error(
                CapabilityErrorCategory::Conflict,
                "conflict.attachment_changed",
                "Attachment changed while it was being read.",
                json!({ "local_scope_id": scope_id }),
                None,
                true,
            )
        })?;
        attachments.push(SendAttachment {
            filename: input.filename.clone(),
            content_type: input.content_type.clone(),
            data,
        });
    }
    Ok(attachments)
}

fn parse_message_identities(input: &Value) -> Result<Vec<EmailMessageIdentity>, CapabilityError> {
    let values = input
        .get("messages")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= MAX_MUTATION_MESSAGES)
        .ok_or_else(|| {
            validation_error(
                "validation.messages_invalid",
                "Messages must be a non-empty bounded array.",
                json!({ "maximum": MAX_MUTATION_MESSAGES }),
            )
        })?;
    values.iter().map(parse_message_identity).collect()
}

fn parse_message_identity(input: &Value) -> Result<EmailMessageIdentity, CapabilityError> {
    let identity = EmailMessageIdentity {
        folder: required_string(input, "folder")?,
        uid_validity: required_u32(input, "uid_validity")?,
        uid: required_u32(input, "uid")?,
        expected_modseq: optional_u64(input, "expected_modseq")?,
    };
    identity.validate().map_err(policy_validation_error)?;
    Ok(identity)
}

fn parse_flag_action(input: &Value) -> Result<EmailFlagAction, CapabilityError> {
    match input.get("action").and_then(Value::as_str).unwrap_or("add") {
        "add" => Ok(EmailFlagAction::Add),
        "remove" => Ok(EmailFlagAction::Remove),
        "replace" => Ok(EmailFlagAction::Replace),
        _ => Err(validation_error(
            "validation.flag_action_invalid",
            "Flag action must be add, remove, or replace.",
            json!({ "field": "action" }),
        )),
    }
}

fn parse_delete_mode(input: &Value) -> Result<EmailDeleteMode, CapabilityError> {
    match input
        .get("delete_mode")
        .and_then(Value::as_str)
        .unwrap_or("trash")
    {
        "trash" => Ok(EmailDeleteMode::Trash),
        "expunge" => Ok(EmailDeleteMode::Expunge),
        _ => Err(validation_error(
            "validation.delete_mode_invalid",
            "Delete mode must be trash or expunge.",
            json!({ "field": "delete_mode" }),
        )),
    }
}

fn require_imap(config: &EmailConfig, capability: &str) -> Result<(), CapabilityError> {
    if config.protocol != EmailProtocol::IMAP {
        return Err(unavailable_error(
            "unavailable.imap_required",
            "This Email workflow requires IMAP stable-UID semantics.",
            json!({ "capability_id": capability, "protocol": "pop3" }),
        ));
    }
    Ok(())
}

fn mutation_output(
    operation: EmailGuardedOperation,
    dry_run: bool,
    identities: &[EmailMessageIdentity],
    outcomes: Vec<Value>,
    preview: Value,
) -> Value {
    let succeeded = outcomes
        .iter()
        .filter(|outcome| outcome["status"] == "succeeded")
        .count();
    let failed = outcomes.len().saturating_sub(succeeded);
    json!({
        "operation": operation,
        "dry_run": dry_run,
        "would_execute": dry_run,
        "idempotent_replay": false,
        "message_count": identities.len(),
        "succeeded": succeeded,
        "failed": failed,
        "partial_failure": failed > 0 && succeeded > 0,
        "outcomes": outcomes,
        "preview": preview
    })
}

fn mutation_summary(output: &Value) -> Value {
    json!({
        "operation": output["operation"],
        "dry_run": output["dry_run"],
        "message_count": output["message_count"],
        "succeeded": output["succeeded"],
        "failed": output["failed"],
        "partial_failure": output["partial_failure"],
        "idempotent_replay": output["idempotent_replay"]
    })
}

fn output_summary_for_send(output: &Value) -> Value {
    json!({
        "status": output["status"],
        "dry_run": output["dry_run"],
        "sent": output["sent"],
        "idempotent_replay": output["idempotent_replay"],
        "content_redacted": true
    })
}

fn attachment_metadata(index: usize, attachment: Attachment) -> Value {
    let safe = validate_attachment_filename(&attachment.filename).is_ok();
    json!({
        "index": index,
        "filename": safe.then_some(attachment.filename),
        "filename_safe": safe,
        "content_type": attachment.content_type,
        "size": attachment.size,
        "bytes_omitted": true
    })
}

fn safe_mutation_error_code(error: &anyhow::Error) -> &'static str {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("uidvalidity")
        || message.contains("modseq")
        || message.contains("stale")
        || message.contains("missing")
    {
        "conflict.stale_message_identity"
    } else if message.contains("requires imap") {
        "unavailable.imap_required"
    } else {
        "target.email_mutation_failed"
    }
}

fn validate_thread_headers(
    in_reply_to: Option<&str>,
    references: &[String],
) -> Result<(), CapabilityError> {
    if references.len() > MAX_REFERENCES {
        return Err(validation_error(
            "validation.references_too_many",
            "Message reference count exceeds the bounded limit.",
            json!({ "maximum": MAX_REFERENCES }),
        ));
    }
    for value in in_reply_to
        .into_iter()
        .chain(references.iter().map(String::as_str))
    {
        if value.is_empty()
            || value.len() > 998
            || value.contains(['\r', '\n', '\0'])
            || value.chars().any(char::is_control)
        {
            return Err(validation_error(
                "validation.message_reference_invalid",
                "Message references must be bounded single-line values.",
                Value::Null,
            ));
        }
    }
    Ok(())
}

fn local_filename(local_path: &str) -> String {
    local_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_string()
}

fn validate_sha256(value: &str) -> Result<(), CapabilityError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(validation_error(
            "validation.sha256_invalid",
            "Expected SHA-256 must be 64 hexadecimal characters.",
            json!({ "field": "expected_sha256" }),
        ));
    }
    Ok(())
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn policy_validation_error(error: crate::policy::EmailPolicyError) -> CapabilityError {
    let category = if error.code.starts_with("policy.") {
        CapabilityErrorCategory::Policy
    } else {
        CapabilityErrorCategory::Validation
    };
    capability_error(
        category,
        error.code,
        error.message,
        error.details,
        None,
        false,
    )
}

fn local_path_error(scope_id: &str, access: &str, error: LocalPathError) -> CapabilityError {
    capability_error(
        error.category(),
        error.code(),
        error.safe_message(),
        json!({ "local_scope_id": scope_id, "access": access }),
        None,
        error.retryable(),
    )
}

#[derive(Debug, Clone)]
struct CachedIdempotentOutcome {
    capability_id: String,
    key: String,
    fingerprint: String,
    output: Value,
}

#[derive(Default)]
struct IdempotencyCache {
    order: VecDeque<(String, String)>,
    outcomes: HashMap<(String, String), CachedIdempotentOutcome>,
}

fn idempotency_cache() -> &'static Mutex<IdempotencyCache> {
    static CACHE: OnceLock<Mutex<IdempotencyCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(IdempotencyCache::default()))
}

fn idempotency_lookup(
    capability_id: &str,
    key: &str,
    fingerprint: &str,
) -> Result<Option<Value>, CapabilityError> {
    let cache = idempotency_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(outcome) = cache
        .outcomes
        .get(&(capability_id.to_string(), key.to_string()))
    else {
        return Ok(None);
    };
    if outcome.fingerprint != fingerprint {
        return Err(capability_error(
            CapabilityErrorCategory::Conflict,
            "conflict.idempotency_key_reused",
            "Idempotency key was already used for different Email input.",
            json!({ "capability_id": capability_id }),
            None,
            false,
        ));
    }
    debug_assert_eq!(outcome.capability_id, capability_id);
    debug_assert_eq!(outcome.key, key);
    Ok(Some(outcome.output.clone()))
}

fn idempotency_record(capability_id: &str, key: String, fingerprint: String, output: Value) {
    let mut cache = idempotency_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache_key = (capability_id.to_string(), key.clone());
    if !cache.outcomes.contains_key(&cache_key) {
        cache.order.push_back(cache_key.clone());
    }
    cache.outcomes.insert(
        cache_key,
        CachedIdempotentOutcome {
            capability_id: capability_id.to_string(),
            key,
            fingerprint,
            output,
        },
    );
    while cache.order.len() > IDEMPOTENCY_CACHE_LIMIT {
        if let Some(oldest) = cache.order.pop_front() {
            cache.outcomes.remove(&oldest);
        }
    }
}

fn invocation_fingerprint(input: &Value) -> String {
    serde_json::to_vec(input)
        .map(|bytes| hex_sha256(&bytes))
        .unwrap_or_else(|_| "serialization-failed".into())
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

fn protocol_schema() -> Value {
    json!({ "type": "string", "enum": ["imap", "pop3"] })
}

fn security_schema() -> Value {
    json!({ "type": "string", "enum": ["ssl_tls", "starttls", "none"] })
}

fn text_limit_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": 1,
        "maximum": MAX_TEXT_LIMIT_BYTES,
        "default": DEFAULT_TEXT_LIMIT_BYTES
    })
}

fn list_input_schema(search: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": {
            "folder": { "type": "string", "minLength": 1, "default": "INBOX" },
            "unread_only": { "type": "boolean", "default": false }
        },
        "additionalProperties": false
    });
    if search {
        schema["required"] = json!(["query"]);
        schema["properties"]["query"] = json!({
            "type": "string",
            "minLength": 1,
            "description": "Case-insensitive search over sender and subject for the fetched page."
        });
    }
    schema
}

fn folder_schema() -> Value {
    json!({
        "type": "object",
        "required": ["name", "display_name", "delimiter", "message_count", "unread_count"],
        "properties": {
            "name": { "type": "string" },
            "display_name": { "type": "string" },
            "delimiter": { "type": "string" },
            "message_count": { "type": "integer", "minimum": 0 },
            "unread_count": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn envelope_schema() -> Value {
    json!({
        "type": "object",
        "required": ["uid", "uid_validity", "modseq", "from", "subject", "date", "seen", "size"],
        "properties": {
            "uid": { "type": "integer", "minimum": 1 },
            "uid_validity": { "type": ["integer", "null"], "minimum": 1 },
            "modseq": { "type": ["integer", "null"], "minimum": 1 },
            "from": { "type": "string" },
            "subject": { "type": "string" },
            "date": { "type": "string" },
            "seen": { "type": "boolean" },
            "size": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn message_list_output_schema(search: bool) -> Value {
    let mut required = vec![
        "folder",
        "messages",
        "message_count",
        "total",
        "page",
        "limit",
        "truncated",
        "unread_only",
    ];
    if search {
        required.push("query");
        required.push("search_scope");
        required.push("searched_count");
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "folder": { "type": "string" },
            "messages": { "type": "array", "items": envelope_schema() },
            "message_count": { "type": "integer", "minimum": 0 },
            "total": { "type": "integer", "minimum": 0 },
            "page": { "type": "integer", "minimum": 0 },
            "limit": { "type": "integer", "minimum": 1, "maximum": MAX_MESSAGE_LIMIT },
            "cursor": { "type": ["string", "null"] },
            "next_cursor": { "type": ["string", "null"] },
            "truncated": { "type": "boolean" },
            "unread_only": { "type": "boolean" },
            "query": { "type": ["string", "null"] },
            "search_scope": { "type": "string", "enum": ["none", "paged_envelope"] },
            "searched_count": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn message_body_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "uid",
            "uid_validity",
            "modseq",
            "from",
            "to",
            "cc",
            "subject",
            "date",
            "text",
            "text_truncated",
            "text_byte_limit",
            "html",
            "html_available",
            "html_truncated",
            "html_byte_limit",
            "attachments"
        ],
        "properties": {
            "uid": { "type": "integer", "minimum": 1 },
            "uid_validity": { "type": ["integer", "null"], "minimum": 1 },
            "modseq": { "type": ["integer", "null"], "minimum": 1 },
            "from": { "type": "string" },
            "to": { "type": "array", "items": { "type": "string" } },
            "cc": { "type": "array", "items": { "type": "string" } },
            "subject": { "type": "string" },
            "date": { "type": "string" },
            "text": { "type": "string" },
            "text_truncated": { "type": "boolean" },
            "text_byte_limit": { "type": "integer", "minimum": 1, "maximum": MAX_TEXT_LIMIT_BYTES },
            "html": { "type": ["string", "null"] },
            "html_available": { "type": "boolean" },
            "html_truncated": { "type": "boolean" },
            "html_byte_limit": { "type": "integer", "minimum": 1, "maximum": MAX_TEXT_LIMIT_BYTES },
            "attachments": { "type": "array", "items": attachment_schema() }
        },
        "additionalProperties": false
    })
}

fn attachment_schema() -> Value {
    json!({
        "type": "object",
        "required": ["filename", "content_type", "size"],
        "properties": {
            "filename": { "type": "string" },
            "content_type": { "type": "string" },
            "size": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn email_address_array_schema() -> Value {
    json!({
        "type": "array",
        "maxItems": crate::policy::MAX_RECIPIENTS,
        "uniqueItems": true,
        "items": { "type": "string", "minLength": 3, "maxLength": 320 }
    })
}

fn idempotency_key_schema() -> Value {
    json!({
        "type": "string",
        "minLength": crate::policy::MIN_IDEMPOTENCY_KEY_BYTES,
        "maxLength": crate::policy::MAX_IDEMPOTENCY_KEY_BYTES,
        "pattern": "^[A-Za-z0-9_.:-]+$"
    })
}

fn send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["to", "subject", "text_body", "idempotency_key"],
        "properties": {
            "to": email_address_array_schema(),
            "cc": email_address_array_schema(),
            "bcc": email_address_array_schema(),
            "reply_to": { "type": "string", "minLength": 3, "maxLength": 320 },
            "subject": { "type": "string", "maxLength": crate::policy::MAX_SUBJECT_BYTES },
            "text_body": { "type": "string", "maxLength": crate::policy::MAX_TEXT_BODY_BYTES },
            "html_body": { "type": "string", "maxLength": crate::policy::MAX_HTML_BODY_BYTES },
            "in_reply_to": { "type": "string", "minLength": 1, "maxLength": 998 },
            "references": {
                "type": "array",
                "maxItems": MAX_REFERENCES,
                "items": { "type": "string", "minLength": 1, "maxLength": 998 }
            },
            "idempotency_key": idempotency_key_schema(),
            "local_root": { "type": "string", "minLength": 1 },
            "attachments": {
                "type": "array",
                "maxItems": crate::policy::MAX_ATTACHMENT_COUNT,
                "items": {
                    "type": "object",
                    "required": ["local_path", "byte_size"],
                    "properties": {
                        "local_path": { "type": "string", "minLength": 1 },
                        "filename": { "type": "string", "minLength": 1, "maxLength": 255 },
                        "content_type": { "type": "string", "minLength": 1, "maxLength": 255 },
                        "byte_size": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": crate::policy::MAX_ATTACHMENT_BYTES
                        }
                    },
                    "additionalProperties": false
                }
            },
            "maximum_recipients": {
                "type": "integer",
                "minimum": 1,
                "maximum": crate::policy::MAX_RECIPIENTS
            },
            "allowed_domains": {
                "type": "array",
                "maxItems": crate::policy::MAX_RECIPIENTS,
                "uniqueItems": true,
                "items": { "type": "string", "minLength": 1, "maxLength": 253 }
            },
            "blocked_domains": {
                "type": "array",
                "maxItems": crate::policy::MAX_RECIPIENTS,
                "uniqueItems": true,
                "items": { "type": "string", "minLength": 1, "maxLength": 253 }
            }
        },
        "additionalProperties": false
    })
}

fn send_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status", "dry_run", "sent", "idempotent_replay"],
        "properties": {
            "status": { "type": "string", "enum": ["planned", "previewed", "accepted"] },
            "dry_run": { "type": "boolean" },
            "sent": { "type": "boolean" },
            "idempotent_replay": { "type": "boolean" },
            "message_id": { "type": "string" },
            "recipient_count": { "type": "integer", "minimum": 1 },
            "attachment_count": { "type": "integer", "minimum": 0 },
            "content_redacted": { "type": "boolean" },
            "preview": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn message_identity_schema() -> Value {
    json!({
        "type": "object",
        "required": ["folder", "uid_validity", "uid"],
        "properties": {
            "folder": { "type": "string", "minLength": 1, "maxLength": 1024 },
            "uid_validity": { "type": "integer", "minimum": 1 },
            "uid": { "type": "integer", "minimum": 1 },
            "expected_modseq": { "type": "integer", "minimum": 1 }
        },
        "additionalProperties": false
    })
}

fn mailbox_mutation_input_schema(operation: &str) -> Value {
    let mut schema = json!({
        "type": "object",
        "required": ["messages", "idempotency_key"],
        "properties": {
            "messages": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_MUTATION_MESSAGES,
                "items": message_identity_schema()
            },
            "idempotency_key": idempotency_key_schema()
        },
        "additionalProperties": false
    });
    match operation {
        "move" => {
            schema["required"] = json!(["messages", "destination_folder", "idempotency_key"]);
            schema["properties"]["destination_folder"] =
                json!({ "type": "string", "minLength": 1, "maxLength": 1024 });
        }
        "delete" => {
            schema["properties"]["delete_mode"] =
                json!({ "type": "string", "enum": ["trash", "expunge"], "default": "trash" });
            schema["properties"]["destination_folder"] =
                json!({ "type": "string", "minLength": 1, "maxLength": 1024, "default": "Trash" });
        }
        "set_flags" => {
            schema["required"] = json!(["messages", "flags", "idempotency_key"]);
            schema["properties"]["action"] =
                json!({ "type": "string", "enum": ["add", "remove", "replace"], "default": "add" });
            schema["properties"]["flags"] = json!({
                "type": "array",
                "minItems": 1,
                "maxItems": 4,
                "uniqueItems": true,
                "items": {
                    "type": "string",
                    "enum": ["seen", "answered", "flagged", "deleted", "draft"]
                }
            });
        }
        _ => {}
    }
    schema
}

fn mailbox_mutation_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "operation", "dry_run", "would_execute", "idempotent_replay",
            "message_count", "succeeded", "failed", "partial_failure", "outcomes", "preview"
        ],
        "properties": {
            "operation": { "type": "string", "enum": ["move", "delete", "set_flags"] },
            "dry_run": { "type": "boolean" },
            "would_execute": { "type": "boolean" },
            "idempotent_replay": { "type": "boolean" },
            "message_count": { "type": "integer", "minimum": 1 },
            "succeeded": { "type": "integer", "minimum": 0 },
            "failed": { "type": "integer", "minimum": 0 },
            "partial_failure": { "type": "boolean" },
            "outcomes": {
                "type": "array",
                "maxItems": MAX_MUTATION_MESSAGES,
                "items": {
                    "type": "object",
                    "required": ["index", "status"],
                    "properties": {
                        "index": { "type": "integer", "minimum": 0 },
                        "status": { "type": "string", "enum": ["succeeded", "failed"] },
                        "error_code": { "type": "string" }
                    },
                    "additionalProperties": false
                }
            },
            "preview": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn attachment_identity_input_schema() -> Value {
    message_identity_schema()
}

fn attachment_list_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "folder", "uid_validity", "uid", "attachment_count", "attachments", "bytes_omitted"
        ],
        "properties": {
            "folder": { "type": "string" },
            "uid_validity": { "type": "integer", "minimum": 1 },
            "uid": { "type": "integer", "minimum": 1 },
            "attachment_count": { "type": "integer", "minimum": 0 },
            "attachments": {
                "type": "array",
                "maxItems": crate::policy::MAX_ATTACHMENT_COUNT,
                "items": {
                    "type": "object",
                    "required": ["index", "filename", "filename_safe", "content_type", "size", "bytes_omitted"],
                    "properties": {
                        "index": { "type": "integer", "minimum": 0 },
                        "filename": { "type": ["string", "null"] },
                        "filename_safe": { "type": "boolean" },
                        "content_type": { "type": "string" },
                        "size": { "type": "integer", "minimum": 0 },
                        "bytes_omitted": { "const": true }
                    },
                    "additionalProperties": false
                }
            },
            "bytes_omitted": { "const": true }
        },
        "additionalProperties": false
    })
}

fn attachment_download_input_schema() -> Value {
    let mut schema = message_identity_schema();
    schema["required"] = json!([
        "folder",
        "uid_validity",
        "uid",
        "attachment_index",
        "local_root",
        "local_path",
        "idempotency_key"
    ]);
    schema["properties"]["attachment_index"] = json!({ "type": "integer", "minimum": 0 });
    schema["properties"]["local_root"] = json!({ "type": "string", "minLength": 1 });
    schema["properties"]["local_path"] = json!({ "type": "string", "minLength": 1 });
    schema["properties"]["idempotency_key"] = idempotency_key_schema();
    schema["properties"]["expected_sha256"] =
        json!({ "type": "string", "pattern": "^[A-Fa-f0-9]{64}$" });
    schema
}

fn attachment_download_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status", "dry_run", "written", "idempotent_replay"],
        "properties": {
            "status": { "type": "string", "enum": ["previewed", "written"] },
            "dry_run": { "type": "boolean" },
            "written": { "type": "boolean" },
            "idempotent_replay": { "type": "boolean" },
            "bytes": { "type": "integer", "minimum": 0 },
            "sha256": { "type": "string" },
            "content_type": { "type": "string" },
            "local_scope_id": { "type": "string" },
            "no_overwrite": { "type": "boolean" },
            "progress": { "type": "object" },
            "preview": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn live_read_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "after_sequence": { "type": "integer", "minimum": 0 },
            "max_events": { "type": "integer", "minimum": 1, "maximum": 1000 },
            "max_bytes": { "type": "integer", "minimum": 1, "maximum": 1048576 },
            "wait_timeout_ms": { "type": "integer", "minimum": 0, "maximum": 30000 }
        },
        "additionalProperties": false
    })
}

fn live_batch_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "protocol_version", "events", "next_sequence", "timed_out", "source_closed",
            "dropped_events", "dropped_bytes", "coalesced_events", "reconnect_attempts"
        ],
        "properties": {
            "protocol_version": { "type": "integer", "const": 1 },
            "events": { "type": "array", "maxItems": 1000 },
            "next_sequence": { "type": "integer", "minimum": 1 },
            "resume_cursor": { "type": "object" },
            "checkpoint": { "type": "object" },
            "oldest_available_sequence": { "type": "integer", "minimum": 1 },
            "truncated": { "type": "boolean" },
            "timed_out": { "type": "boolean" },
            "source_closed": { "type": "boolean" },
            "dropped_events": { "type": "integer", "minimum": 0 },
            "dropped_bytes": { "type": "integer", "minimum": 0 },
            "coalesced_events": { "type": "integer", "minimum": 0 },
            "reconnect_attempts": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn folder_output(folder: EmailFolder) -> Value {
    json!({
        "name": folder.name,
        "display_name": folder.display_name,
        "delimiter": folder.delimiter,
        "message_count": folder.message_count,
        "unread_count": folder.unread_count
    })
}

fn envelope_output(message: EmailEnvelope) -> Value {
    json!({
        "uid": message.uid,
        "uid_validity": message.uid_validity,
        "modseq": message.modseq,
        "from": message.from,
        "subject": message.subject,
        "date": message.date,
        "seen": message.seen,
        "size": message.size
    })
}

fn body_output(
    body: EmailBody,
    include_html: bool,
    max_text_bytes: usize,
    max_html_bytes: usize,
) -> Value {
    let (text, text_truncated) = truncate_string(body.text, max_text_bytes);
    let html_available = body.html.is_some();
    let (html, html_truncated) = match (include_html, body.html) {
        (true, Some(html)) => {
            let (html, truncated) = truncate_string(html, max_html_bytes);
            (Some(html), truncated)
        }
        _ => (None, false),
    };
    json!({
        "uid": body.uid,
        "uid_validity": body.uid_validity,
        "modseq": body.modseq,
        "from": body.from,
        "to": body.to,
        "cc": body.cc,
        "subject": body.subject,
        "date": body.date,
        "text": text,
        "text_truncated": text_truncated,
        "text_byte_limit": max_text_bytes,
        "html": html,
        "html_available": html_available,
        "html_truncated": html_truncated,
        "html_byte_limit": max_html_bytes,
        "attachments": body.attachments.into_iter().map(attachment_output).collect::<Vec<_>>()
    })
}

fn attachment_output(attachment: Attachment) -> Value {
    json!({
        "filename": attachment.filename,
        "content_type": attachment.content_type,
        "size": attachment.size
    })
}

fn envelope_matches(message: &EmailEnvelope, query: &str) -> bool {
    message.from.to_ascii_lowercase().contains(query)
        || message.subject.to_ascii_lowercase().contains(query)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PageRequest {
    page: u32,
    limit: u32,
    cursor: Option<String>,
}

fn page_request(invocation: &CapabilityInvocation) -> Result<PageRequest, CapabilityError> {
    let limit = invocation
        .controls
        .page
        .as_ref()
        .map(|page| page.limit)
        .unwrap_or(DEFAULT_MESSAGE_LIMIT);
    if limit == 0 || limit > MAX_MESSAGE_LIMIT {
        return Err(validation_error(
            "validation.page_limit_invalid",
            "Email message page limit must be between 1 and the maximum message limit.",
            json!({ "limit": limit, "maximum": MAX_MESSAGE_LIMIT }),
        ));
    }

    let cursor = invocation
        .controls
        .page
        .as_ref()
        .and_then(|page| page.cursor.clone());
    let page = cursor
        .as_deref()
        .map(parse_page_cursor)
        .transpose()?
        .unwrap_or(0);

    Ok(PageRequest {
        page,
        limit,
        cursor,
    })
}

fn parse_page_cursor(cursor: &str) -> Result<u32, CapabilityError> {
    cursor.parse::<u32>().map_err(|_| {
        validation_error(
            "validation.invalid_cursor",
            "Email message cursor must be an unsigned page number.",
            json!({ "cursor": cursor }),
        )
    })
}

fn next_page_cursor(page: u32, limit: u32, total: u32) -> Option<String> {
    let next_page = page.checked_add(1)?;
    let next_start = u64::from(next_page) * u64::from(limit);
    (next_start < u64::from(total)).then(|| next_page.to_string())
}

fn text_limit(input: &Value, field: &str) -> Result<usize, CapabilityError> {
    let Some(max_bytes) = optional_u64(input, field)? else {
        return Ok(DEFAULT_TEXT_LIMIT_BYTES);
    };
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        validation_error(
            "validation.text_limit_invalid",
            "Text byte limit is too large for this platform.",
            json!({ "field": field, "maximum": MAX_TEXT_LIMIT_BYTES }),
        )
    })?;
    if max_bytes == 0 || max_bytes > MAX_TEXT_LIMIT_BYTES {
        return Err(validation_error(
            "validation.text_limit_invalid",
            "Text byte limit must be between 1 and the maximum text limit.",
            json!({ "field": field, "max_bytes": max_bytes, "maximum": MAX_TEXT_LIMIT_BYTES }),
        ));
    }
    Ok(max_bytes)
}

fn truncate_string(value: String, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }

    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn required_string(input: &Value, field: &str) -> Result<String, CapabilityError> {
    match input.get(field) {
        Some(value) if !value.is_string() => Err(validation_error(
            "validation.input_field_invalid",
            "Required input field must be a string.",
            json!({ "field": field }),
        )),
        Some(value) => value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                validation_error(
                    "validation.input_field_required",
                    "Required string input field is missing.",
                    json!({ "field": field }),
                )
            }),
        None => Err(validation_error(
            "validation.input_field_required",
            "Required string input field is missing.",
            json!({ "field": field }),
        )),
    }
}

fn required_string_allow_empty(input: &Value, field: &str) -> Result<String, CapabilityError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            validation_error(
                "validation.input_field_required",
                "Required input field must be a string.",
                json!({ "field": field }),
            )
        })
}

fn required_string_array(input: &Value, field: &str) -> Result<Vec<String>, CapabilityError> {
    optional_string_array(input, field)?
        .filter(|values| !values.is_empty())
        .ok_or_else(|| {
            validation_error(
                "validation.input_field_required",
                "Required string array must not be empty.",
                json!({ "field": field }),
            )
        })
}

fn required_u64(input: &Value, field: &str) -> Result<u64, CapabilityError> {
    input.get(field).and_then(Value::as_u64).ok_or_else(|| {
        validation_error(
            "validation.input_field_required",
            "Required input field must be an unsigned integer.",
            json!({ "field": field }),
        )
    })
}

fn required_u32(input: &Value, field: &str) -> Result<u32, CapabilityError> {
    let value = input.get(field).and_then(Value::as_u64).ok_or_else(|| {
        validation_error(
            "validation.input_field_required",
            "Required integer input field is missing.",
            json!({ "field": field }),
        )
    })?;
    if value == 0 {
        return Err(validation_error(
            "validation.input_field_invalid",
            "Required integer input field must be greater than zero.",
            json!({ "field": field }),
        ));
    }
    u32::try_from(value).map_err(|_| {
        validation_error(
            "validation.input_field_invalid",
            "Required integer input field is out of range.",
            json!({ "field": field }),
        )
    })
}

fn required_u32_allow_zero(input: &Value, field: &str) -> Result<u32, CapabilityError> {
    let value = required_u64(input, field)?;
    u32::try_from(value).map_err(|_| {
        validation_error(
            "validation.input_field_invalid",
            "Required integer input field is out of range.",
            json!({ "field": field }),
        )
    })
}

fn optional_string(input: &Value, field: &str) -> Result<Option<String>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    validation_error(
                        "validation.input_field_invalid",
                        "Optional input field must be a non-empty string.",
                        json!({ "field": field }),
                    )
                })
        })
        .transpose()
}

fn optional_string_allow_empty(
    input: &Value,
    field: &str,
) -> Result<Option<String>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be a string.",
                    json!({ "field": field }),
                )
            })
        })
        .transpose()
}

fn optional_string_array(
    input: &Value,
    field: &str,
) -> Result<Option<Vec<String>>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            let values = value.as_array().ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be a string array.",
                    json!({ "field": field }),
                )
            })?;
            let mut unique = BTreeSet::new();
            let mut result = Vec::with_capacity(values.len());
            for value in values {
                let value = value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        validation_error(
                            "validation.input_field_invalid",
                            "String array entries must be non-empty strings.",
                            json!({ "field": field }),
                        )
                    })?
                    .to_string();
                if !unique.insert(value.clone()) {
                    return Err(validation_error(
                        "validation.input_field_invalid",
                        "String array entries must be unique.",
                        json!({ "field": field }),
                    ));
                }
                result.push(value);
            }
            Ok(result)
        })
        .transpose()
}

fn optional_bool(input: &Value, field: &str) -> Result<Option<bool>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be a boolean.",
                    json!({ "field": field }),
                )
            })
        })
        .transpose()
}

fn optional_u64(input: &Value, field: &str) -> Result<Option<u64>, CapabilityError> {
    input
        .get(field)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                validation_error(
                    "validation.input_field_invalid",
                    "Optional input field must be an unsigned integer.",
                    json!({ "field": field }),
                )
            })
        })
        .transpose()
}

fn protocol_label(protocol: EmailProtocol) -> &'static str {
    match protocol {
        EmailProtocol::IMAP => "imap",
        EmailProtocol::POP3 => "pop3",
    }
}

fn security_label(security: SecurityType) -> &'static str {
    match security {
        SecurityType::SslTls => "ssl_tls",
        SecurityType::STARTTLS => "starttls",
        SecurityType::None => "none",
    }
}

fn target_error(code: &str, error: anyhow::Error, config: &EmailConfig) -> CapabilityError {
    let (message, redaction) = redact_email_target_message(error.to_string(), config);
    CapabilityError {
        category: CapabilityErrorCategory::TargetSystem,
        code: code.to_string(),
        message: "Email target operation failed.".to_string(),
        details: Value::Null,
        target: Some(TargetSystemFailure {
            system: Some(PLUGIN_ID.to_string()),
            code: None,
            message: Some(message),
        }),
        retryable: false,
        redaction,
    }
}

fn redact_email_target_message(message: String, config: &EmailConfig) -> (String, RedactionStatus) {
    let original = message.clone();
    let mut redacted = message;
    for sensitive in [
        config.password.as_str(),
        config.email.as_str(),
        config.receive.host.as_str(),
        config.smtp.host.as_str(),
    ] {
        if !sensitive.is_empty() {
            redacted = redacted.replace(sensitive, "<redacted>");
        }
    }
    let status = if redacted != original {
        RedactionStatus::Applied
    } else {
        RedactionStatus::NotRequired
    };
    (redacted, status)
}

fn result(
    invocation_id: String,
    output: Value,
    output_summary: Value,
    page: Option<InvocationOutputPage>,
) -> CapabilityInvocationResult {
    CapabilityInvocationResult {
        invocation_id,
        status: InvocationStatus::Succeeded,
        output,
        output_summary,
        page,
    }
}

fn validation_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Validation,
        code,
        message,
        details,
        None,
        false,
    )
}

fn unavailable_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Unavailable,
        code,
        message,
        details,
        None,
        true,
    )
}

fn capability_error(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    target: Option<TargetSystemFailure>,
    retryable: bool,
) -> CapabilityError {
    CapabilityError {
        category,
        code: code.to_string(),
        message: message.to_string(),
        details,
        target,
        retryable,
        redaction: RedactionStatus::NotRequired,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;
    use voidb_core::{
        CapabilityExecutionMode, CapabilityInvocation, InvocationConnectionTarget,
        InvocationControls, Pagination,
    };

    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn catalog_exposes_guarded_complete_email_workflows() {
        let capabilities = email_capabilities();
        for id in ["diagnostics", "folders", "list", "search", "fetch"] {
            let capability = capabilities
                .iter()
                .find(|capability| capability.id == id)
                .expect("capability exists");
            assert!(!capability.destructive);
            assert!(!capability.supports_dry_run);
            assert_eq!(capability.risk, CapabilityRiskLevel::ReadOnly);
            assert!(
                capability
                    .permissions
                    .iter()
                    .any(|permission| permission == "connection.read")
            );
            assert!(
                capability
                    .permissions
                    .iter()
                    .any(|permission| permission == &format!("email.{id}"))
            );
        }

        let list = capability_by_id(&capabilities, "list");
        assert_eq!(
            list.output_schema["properties"]["limit"]["maximum"],
            json!(MAX_MESSAGE_LIMIT)
        );
        assert_eq!(
            list.output_schema["properties"]["next_cursor"]["type"][0],
            "string"
        );

        let fetch = capability_by_id(&capabilities, "fetch");
        assert!(fetch.description.contains("without marking it read"));
        assert_eq!(
            fetch.input_schema["properties"]["max_text_bytes"]["maximum"],
            json!(MAX_TEXT_LIMIT_BYTES)
        );
        assert_eq!(
            fetch.input_schema["properties"]["include_html"]["default"],
            json!(false)
        );

        let draft = capability_by_id(&capabilities, "draft");
        assert_eq!(draft.risk, CapabilityRiskLevel::ReadOnly);
        assert!(!draft.connection_required);
        assert!(!draft.supports_dry_run);

        for (id, risk) in [
            ("send", CapabilityRiskLevel::ExternalSideEffect),
            ("move", CapabilityRiskLevel::ExternalSideEffect),
            ("delete", CapabilityRiskLevel::Destructive),
            ("set_flags", CapabilityRiskLevel::ExternalSideEffect),
            (
                "download_attachment",
                CapabilityRiskLevel::ExternalSideEffect,
            ),
        ] {
            let capability = capability_by_id(&capabilities, id);
            assert_eq!(capability.risk, risk, "email.{id} risk");
            assert!(capability.supports_dry_run, "email.{id} preview");
            assert!(capability.requires_acknowledgement(), "email.{id} ack");
            assert!(
                capability.permissions.contains(&format!("email.{id}")),
                "email.{id} permission"
            );
            assert!(capability.authorization.approval_schema.is_some());
        }
        assert!(capability_by_id(&capabilities, "delete").destructive);
        assert!(!capability_by_id(&capabilities, "send").destructive);

        let attachments = capability_by_id(&capabilities, "attachments");
        assert_eq!(attachments.risk, CapabilityRiskLevel::ReadOnly);
        assert!(!attachments.supports_dry_run);
        assert_eq!(
            attachments.input_schema["required"],
            json!(["folder", "uid_validity", "uid"])
        );

        let idle = capability_by_id(&capabilities, "idle");
        assert_eq!(idle.execution_mode, CapabilityExecutionMode::SessionOnly);
        assert!(idle.streaming);
        let handoff = idle.session_handoff.as_ref().expect("IDLE handoff");
        let contract = handoff.live_session.as_ref().expect("IDLE contract");
        contract
            .validate(&handoff.capabilities)
            .expect("valid IDLE contract");
        assert_eq!(handoff.capabilities, vec!["email.idle"]);
    }

    #[tokio::test]
    async fn diagnostics_does_not_open_email_connection_or_expose_secret_material() {
        let result = invoke_email_capability(&config(), invocation("diagnostics", json!({})))
            .await
            .expect("diagnostics");
        let encoded = serde_json::to_string(&result).expect("serialize");

        assert_eq!(result.output["protocol"], "imap");
        assert_eq!(result.output["network_checked"], false);
        assert_eq!(result.output["verify_tls"], true);
        assert_eq!(result.output["delete_deferred"], false);
        assert_eq!(result.output["send_deferred"], false);
        assert!(!encoded.contains("user@example.com"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("imap.example.com"));
    }

    #[tokio::test]
    async fn send_requires_acknowledgement_but_dry_run_is_local_and_redacted() {
        let input = send_input();
        let error = invoke_email_capability(&config(), invocation("send", input.clone()))
            .await
            .expect_err("send without acknowledgement");
        assert_eq!(error.category, CapabilityErrorCategory::Policy);
        assert_eq!(error.code, "policy.acknowledgement_required");

        let mut preview = invocation("send", input);
        preview.controls.dry_run = true;
        let result = invoke_email_capability(&config(), preview)
            .await
            .expect("local send preview");
        let encoded = serde_json::to_string(&result).expect("serialize preview");
        assert_eq!(result.output["status"], "previewed");
        assert_eq!(result.output["sent"], false);
        assert_eq!(result.output["preview"]["content_redacted"], true);
        for sensitive in [
            "recipient@outside.test",
            "private subject",
            "private body",
            "user@example.com",
            "secret",
        ] {
            assert!(!encoded.contains(sensitive));
        }
    }

    #[tokio::test]
    async fn mailbox_mutation_preview_uses_stable_identity_without_connecting() {
        let mut preview = invocation(
            "delete",
            json!({
                "messages": [{
                    "folder": "INBOX",
                    "uid_validity": 77,
                    "uid": 42,
                    "expected_modseq": 9
                }],
                "delete_mode": "expunge",
                "idempotency_key": "delete-preview-0001"
            }),
        );
        preview.controls.dry_run = true;
        let result = invoke_email_capability(&config(), preview)
            .await
            .expect("delete preview");
        let encoded = serde_json::to_string(&result).expect("serialize preview");
        assert_eq!(result.output["dry_run"], true);
        assert_eq!(result.output["message_count"], 1);
        assert_eq!(result.output["preview"]["message_content_redacted"], true);
        assert!(!encoded.contains("user@example.com"));
        assert!(!encoded.contains("secret"));
    }

    #[tokio::test]
    async fn malicious_attachment_filename_is_rejected_before_file_or_network_access() {
        let mut input = send_input();
        input["attachments"] = json!([{
            "local_path": "payload.txt",
            "filename": "../escape.txt",
            "byte_size": 8
        }]);
        input["local_root"] = json!("/not/used");
        let error = invoke_email_capability(&config(), invocation("draft", input))
            .await
            .expect_err("unsafe attachment");
        assert_eq!(error.code, "validation.attachment_filename_unsafe");
    }

    #[tokio::test]
    async fn recipient_domain_guardrail_denies_unapproved_send() {
        let mut input = send_input();
        input["allowed_domains"] = json!(["example.com"]);
        let error = invoke_email_capability(&config(), invocation("draft", input))
            .await
            .expect_err("recipient outside allowlist");
        assert_eq!(error.category, CapabilityErrorCategory::Policy);
        assert_eq!(error.code, "policy.recipient_domain_not_allowed");
    }

    #[test]
    fn target_errors_redact_email_credentials_and_hosts() {
        let error = target_error(
            "email.list_failed",
            anyhow::anyhow!(
                "login failed for user@example.com using secret at imap.example.com via smtp.example.com"
            ),
            &config(),
        );
        let encoded = serde_json::to_string(&error).expect("serialize error");

        assert_eq!(error.redaction, RedactionStatus::Applied);
        assert!(!encoded.contains("user@example.com"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("imap.example.com"));
        assert!(!encoded.contains("smtp.example.com"));
        assert!(encoded.contains("<redacted>"));
    }

    #[test]
    fn invalid_page_cursor_is_rejected_before_connecting() {
        let mut invocation = invocation("list", json!({ "folder": "INBOX" }));
        invocation.controls.page = Some(Pagination {
            limit: 10,
            cursor: Some("later".into()),
        });
        let error = page_request(&invocation).unwrap_err();
        assert_eq!(error.code, "validation.invalid_cursor");
    }

    #[test]
    fn truncation_preserves_utf8_boundaries() {
        let (value, truncated) = truncate_string("ab猫cd".to_string(), 4);

        assert_eq!(value, "ab");
        assert!(truncated);
    }

    fn capability_by_id<'a>(
        capabilities: &'a [CapabilityDefinition],
        id: &str,
    ) -> &'a CapabilityDefinition {
        capabilities
            .iter()
            .find(|capability| capability.id == id)
            .unwrap_or_else(|| panic!("missing email capability {id}"))
    }

    fn invocation(capability_id: &str, input: Value) -> CapabilityInvocation {
        CapabilityInvocation {
            id: "invoke-test".into(),
            plugin_id: PLUGIN_ID.into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls::default(),
            actor: None,
            requested_at: Utc::now(),
        }
    }

    fn send_input() -> Value {
        json!({
            "to": ["recipient@outside.test"],
            "subject": "private subject",
            "text_body": "private body",
            "idempotency_key": "email-send-test-0001"
        })
    }

    fn config() -> EmailConfig {
        EmailConfig {
            email: "user@example.com".into(),
            password: "secret".into(),
            protocol: EmailProtocol::IMAP,
            receive: ServerConfig {
                host: "imap.example.com".into(),
                port: 993,
            },
            smtp: ServerConfig {
                host: "smtp.example.com".into(),
                port: 587,
            },
            receive_security: SecurityType::SslTls,
            smtp_security: SecurityType::STARTTLS,
            verify_tls: true,
        }
    }
}
