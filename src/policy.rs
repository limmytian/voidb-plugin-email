use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use voidb_core::{CapabilityRiskLevel, InvocationControls};

pub const MAX_RECIPIENTS: usize = 50;
pub const MAX_SUBJECT_BYTES: usize = 998;
pub const MAX_TEXT_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_HTML_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ATTACHMENT_COUNT: usize = 20;
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
pub const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;
pub const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailGuardedOperation {
    Send,
    Move,
    Delete,
    SetFlags,
    DownloadAttachment,
}

impl EmailGuardedOperation {
    pub const ALL: [Self; 5] = [
        Self::Send,
        Self::Move,
        Self::Delete,
        Self::SetFlags,
        Self::DownloadAttachment,
    ];

    pub fn policy(self) -> EmailOperationPolicy {
        match self {
            Self::Send => EmailOperationPolicy {
                capability_id: "send",
                permission: "email.send",
                risk: CapabilityRiskLevel::ExternalSideEffect,
                requires_message_identity: false,
                requires_idempotency_key: true,
            },
            Self::Move => EmailOperationPolicy {
                capability_id: "move",
                permission: "email.move",
                risk: CapabilityRiskLevel::ExternalSideEffect,
                requires_message_identity: true,
                requires_idempotency_key: true,
            },
            Self::Delete => EmailOperationPolicy {
                capability_id: "delete",
                permission: "email.delete",
                risk: CapabilityRiskLevel::Destructive,
                requires_message_identity: true,
                requires_idempotency_key: true,
            },
            Self::SetFlags => EmailOperationPolicy {
                capability_id: "set_flags",
                permission: "email.set_flags",
                risk: CapabilityRiskLevel::ExternalSideEffect,
                requires_message_identity: true,
                requires_idempotency_key: true,
            },
            Self::DownloadAttachment => EmailOperationPolicy {
                capability_id: "download_attachment",
                permission: "email.download_attachment",
                risk: CapabilityRiskLevel::ExternalSideEffect,
                requires_message_identity: true,
                requires_idempotency_key: true,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailOperationPolicy {
    pub capability_id: &'static str,
    pub permission: &'static str,
    pub risk: CapabilityRiskLevel,
    pub requires_message_identity: bool,
    pub requires_idempotency_key: bool,
}

impl EmailOperationPolicy {
    pub fn requires_acknowledgement(self) -> bool {
        true
    }

    pub fn supports_dry_run(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMessageIdentity {
    pub folder: String,
    pub uid_validity: u32,
    pub uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_modseq: Option<u64>,
}

impl EmailMessageIdentity {
    pub fn validate(&self) -> Result<(), EmailPolicyError> {
        validate_mailbox_name(&self.folder)?;
        if self.uid_validity == 0 {
            return Err(EmailPolicyError::new(
                "validation.uid_validity_invalid",
                "Message UIDVALIDITY must be greater than zero.",
                json!({ "field": "uid_validity" }),
            ));
        }
        if self.uid == 0 {
            return Err(EmailPolicyError::new(
                "validation.uid_invalid",
                "Message UID must be greater than zero.",
                json!({ "field": "uid" }),
            ));
        }
        if self.expected_modseq == Some(0) {
            return Err(EmailPolicyError::new(
                "validation.modseq_invalid",
                "Expected modification sequence must be greater than zero when provided.",
                json!({ "field": "expected_modseq" }),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientGuardrails {
    pub maximum_recipients: usize,
    pub allowed_domains: BTreeSet<String>,
    pub blocked_domains: BTreeSet<String>,
}

impl Default for RecipientGuardrails {
    fn default() -> Self {
        Self {
            maximum_recipients: MAX_RECIPIENTS,
            allowed_domains: BTreeSet::new(),
            blocked_domains: BTreeSet::new(),
        }
    }
}

impl RecipientGuardrails {
    pub fn new(
        maximum_recipients: usize,
        allowed_domains: impl IntoIterator<Item = String>,
        blocked_domains: impl IntoIterator<Item = String>,
    ) -> Result<Self, EmailPolicyError> {
        if maximum_recipients == 0 || maximum_recipients > MAX_RECIPIENTS {
            return Err(EmailPolicyError::new(
                "validation.recipient_limit_invalid",
                "Recipient limit must be within the Email policy maximum.",
                json!({ "maximum": MAX_RECIPIENTS }),
            ));
        }
        Ok(Self {
            maximum_recipients,
            allowed_domains: normalize_domain_set(allowed_domains)?,
            blocked_domains: normalize_domain_set(blocked_domains)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSummary {
    pub recipient_count: usize,
    pub external_recipient_count: usize,
    pub distinct_domain_count: usize,
}

pub fn summarize_recipients(
    sender: &str,
    to: &[String],
    cc: &[String],
    bcc: &[String],
    guardrails: &RecipientGuardrails,
) -> Result<RecipientSummary, EmailPolicyError> {
    let sender_domain = address_domain(sender)?;
    let recipients = to.iter().chain(cc).chain(bcc).collect::<Vec<_>>();
    if recipients.is_empty() {
        return Err(EmailPolicyError::new(
            "validation.recipient_required",
            "At least one recipient is required.",
            json!({ "minimum": 1 }),
        ));
    }
    if recipients.len() > guardrails.maximum_recipients {
        return Err(EmailPolicyError::new(
            "validation.recipient_limit_exceeded",
            "Recipient count exceeds the approved maximum.",
            json!({
                "recipient_count": recipients.len(),
                "maximum": guardrails.maximum_recipients
            }),
        ));
    }

    let mut domains = BTreeSet::new();
    let mut external_recipient_count = 0usize;
    for recipient in &recipients {
        let domain = address_domain(recipient)?;
        if guardrails.blocked_domains.contains(&domain) {
            return Err(EmailPolicyError::new(
                "policy.recipient_domain_blocked",
                "A recipient domain is blocked by Email policy.",
                json!({ "blocked": true }),
            ));
        }
        if !guardrails.allowed_domains.is_empty() && !guardrails.allowed_domains.contains(&domain) {
            return Err(EmailPolicyError::new(
                "policy.recipient_domain_not_allowed",
                "A recipient domain is outside the approved allowlist.",
                json!({ "allowlist_required": true }),
            ));
        }
        external_recipient_count += usize::from(domain != sender_domain);
        domains.insert(domain);
    }

    Ok(RecipientSummary {
        recipient_count: recipients.len(),
        external_recipient_count,
        distinct_domain_count: domains.len(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAttachmentSummary {
    pub byte_size: u64,
}

pub fn validate_outbound_content(
    subject: &str,
    text_body: &str,
    html_body: Option<&str>,
    attachments: &[OutboundAttachmentSummary],
) -> Result<(), EmailPolicyError> {
    if subject.contains(['\r', '\n']) || subject.len() > MAX_SUBJECT_BYTES {
        return Err(EmailPolicyError::new(
            "validation.subject_invalid",
            "Subject must be single-line and within the byte limit.",
            json!({ "maximum_bytes": MAX_SUBJECT_BYTES }),
        ));
    }
    if text_body.len() > MAX_TEXT_BODY_BYTES {
        return Err(EmailPolicyError::new(
            "validation.text_body_too_large",
            "Text body exceeds the Email policy byte limit.",
            json!({ "maximum_bytes": MAX_TEXT_BODY_BYTES }),
        ));
    }
    if html_body.is_some_and(|body| body.len() > MAX_HTML_BODY_BYTES) {
        return Err(EmailPolicyError::new(
            "validation.html_body_too_large",
            "HTML body exceeds the Email policy byte limit.",
            json!({ "maximum_bytes": MAX_HTML_BODY_BYTES }),
        ));
    }
    if attachments.len() > MAX_ATTACHMENT_COUNT {
        return Err(EmailPolicyError::new(
            "validation.attachment_count_exceeded",
            "Attachment count exceeds the Email policy limit.",
            json!({ "maximum": MAX_ATTACHMENT_COUNT }),
        ));
    }
    let mut total_bytes = 0u64;
    for attachment in attachments {
        if attachment.byte_size > MAX_ATTACHMENT_BYTES {
            return Err(EmailPolicyError::new(
                "validation.attachment_too_large",
                "An attachment exceeds the per-file byte limit.",
                json!({ "maximum_bytes": MAX_ATTACHMENT_BYTES }),
            ));
        }
        total_bytes = total_bytes
            .checked_add(attachment.byte_size)
            .ok_or_else(|| {
                EmailPolicyError::new(
                    "validation.attachment_total_too_large",
                    "Attachment byte total exceeds the Email policy limit.",
                    json!({ "maximum_bytes": MAX_TOTAL_ATTACHMENT_BYTES }),
                )
            })?;
    }
    if total_bytes > MAX_TOTAL_ATTACHMENT_BYTES {
        return Err(EmailPolicyError::new(
            "validation.attachment_total_too_large",
            "Attachment byte total exceeds the Email policy limit.",
            json!({ "maximum_bytes": MAX_TOTAL_ATTACHMENT_BYTES }),
        ));
    }
    Ok(())
}

pub fn validate_idempotency_key(value: &str) -> Result<(), EmailPolicyError> {
    let valid_length =
        (MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&value.len());
    let valid_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if !valid_length || !valid_chars {
        return Err(EmailPolicyError::new(
            "validation.idempotency_key_invalid",
            "Idempotency key must use bounded printable token characters.",
            json!({
                "minimum_bytes": MIN_IDEMPOTENCY_KEY_BYTES,
                "maximum_bytes": MAX_IDEMPOTENCY_KEY_BYTES
            }),
        ));
    }
    Ok(())
}

pub fn require_guarded_execution(
    operation: EmailGuardedOperation,
    controls: &InvocationControls,
) -> Result<EmailExecutionMode, EmailPolicyError> {
    if controls.dry_run {
        return Ok(EmailExecutionMode::Preview);
    }
    if controls.acknowledgement.is_none() {
        return Err(EmailPolicyError::new(
            "policy.acknowledgement_required",
            "Email write operations require an invocation acknowledgement.",
            json!({ "operation": operation }),
        ));
    }
    Ok(EmailExecutionMode::Apply)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailExecutionMode {
    Preview,
    Apply,
}

pub fn send_preview(
    recipients: &RecipientSummary,
    subject: &str,
    text_body: &str,
    html_body: Option<&str>,
    attachments: &[OutboundAttachmentSummary],
) -> Value {
    let attachment_bytes = attachments
        .iter()
        .fold(0u64, |total, item| total.saturating_add(item.byte_size));
    json!({
        "operation": "send",
        "dry_run": true,
        "risk": "external_side_effect",
        "requires_acknowledgement": true,
        "recipient_count": recipients.recipient_count,
        "external_recipient_count": recipients.external_recipient_count,
        "distinct_domain_count": recipients.distinct_domain_count,
        "subject_bytes": subject.len(),
        "text_body_bytes": text_body.len(),
        "html_body_bytes": html_body.map(str::len).unwrap_or(0),
        "attachment_count": attachments.len(),
        "attachment_bytes": attachment_bytes,
        "content_redacted": true
    })
}

pub fn message_mutation_preview(
    operation: EmailGuardedOperation,
    identities: &[EmailMessageIdentity],
    destination_folder_present: bool,
    flag_count: usize,
) -> Value {
    json!({
        "operation": operation,
        "dry_run": true,
        "risk": operation.policy().risk,
        "requires_acknowledgement": true,
        "message_count": identities.len(),
        "mailbox_count": identities.iter().map(|identity| identity.folder.as_str()).collect::<BTreeSet<_>>().len(),
        "destination_folder_present": destination_folder_present,
        "flag_count": flag_count,
        "message_content_redacted": true
    })
}

pub fn validate_attachment_filename(filename: &str) -> Result<(), EmailPolicyError> {
    let trimmed = filename.trim();
    let invalid = trimmed != filename
        || trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.len() > 255
        || trimmed.contains(['/', '\\', '\0'])
        || trimmed.chars().any(char::is_control);
    if invalid {
        return Err(EmailPolicyError::new(
            "validation.attachment_filename_unsafe",
            "Attachment filename is unsafe for local materialization.",
            json!({ "safe_filename_required": true }),
        ));
    }
    Ok(())
}

fn validate_mailbox_name(folder: &str) -> Result<(), EmailPolicyError> {
    let folder = folder.trim();
    if folder.is_empty()
        || folder.len() > 1024
        || folder.contains(['\r', '\n', '\0'])
        || folder.chars().any(|character| character.is_control())
    {
        return Err(EmailPolicyError::new(
            "validation.mailbox_invalid",
            "Mailbox name is empty, too large, or contains control characters.",
            json!({ "field": "folder" }),
        ));
    }
    Ok(())
}

fn normalize_domain_set(
    domains: impl IntoIterator<Item = String>,
) -> Result<BTreeSet<String>, EmailPolicyError> {
    domains
        .into_iter()
        .map(|domain| normalize_domain(&domain))
        .collect()
}

fn address_domain(address: &str) -> Result<String, EmailPolicyError> {
    if address.contains(['\r', '\n', '\0']) || address.contains(['<', '>', ',', ';']) {
        return Err(invalid_recipient_error());
    }
    let (local, domain) = address
        .trim()
        .rsplit_once('@')
        .ok_or_else(invalid_recipient_error)?;
    if local.is_empty() || local.len() > 64 {
        return Err(invalid_recipient_error());
    }
    normalize_domain(domain)
}

fn normalize_domain(domain: &str) -> Result<String, EmailPolicyError> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(invalid_recipient_error());
    }
    Ok(domain)
}

fn invalid_recipient_error() -> EmailPolicyError {
    EmailPolicyError::new(
        "validation.recipient_invalid",
        "Recipient must be a structured mailbox address.",
        json!({ "structured_address_required": true }),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailPolicyError {
    pub code: &'static str,
    pub message: &'static str,
    pub details: Value,
}

impl EmailPolicyError {
    fn new(code: &'static str, message: &'static str, details: Value) -> Self {
        Self {
            code,
            message,
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use voidb_core::{ActorRef, ActorType, InvocationAcknowledgement};

    use super::*;

    #[test]
    fn every_guarded_operation_has_a_write_permission_and_preview_gate() {
        for operation in EmailGuardedOperation::ALL {
            let policy = operation.policy();
            assert!(policy.permission.starts_with("email."));
            assert_ne!(policy.risk, CapabilityRiskLevel::ReadOnly);
            assert!(policy.supports_dry_run());
            assert!(policy.requires_acknowledgement());
            assert!(policy.requires_idempotency_key);
        }
    }

    #[test]
    fn send_preview_contains_shape_but_not_message_content_or_addresses() {
        let recipients = summarize_recipients(
            "sender@example.com",
            &["alice@example.com".into(), "bob@outside.test".into()],
            &[],
            &[],
            &RecipientGuardrails::default(),
        )
        .expect("recipient summary");
        let preview = send_preview(
            &recipients,
            "private subject",
            "private text",
            Some("<p>private html</p>"),
            &[OutboundAttachmentSummary { byte_size: 42 }],
        );
        let encoded = serde_json::to_string(&preview).expect("serialize preview");

        assert_eq!(preview["recipient_count"], 2);
        assert_eq!(preview["external_recipient_count"], 1);
        assert_eq!(preview["attachment_bytes"], 42);
        assert!(preview["content_redacted"].as_bool().unwrap());
        for secret in [
            "alice@example.com",
            "bob@outside.test",
            "private subject",
            "private text",
            "private html",
        ] {
            assert!(!encoded.contains(secret));
        }
    }

    #[test]
    fn recipient_guardrails_reject_blocked_and_unapproved_domains() {
        let blocked =
            RecipientGuardrails::new(5, [], ["blocked.test".into()]).expect("blocked guardrail");
        let error = summarize_recipients(
            "sender@example.com",
            &["agent@blocked.test".into()],
            &[],
            &[],
            &blocked,
        )
        .unwrap_err();
        assert_eq!(error.code, "policy.recipient_domain_blocked");

        let allowed =
            RecipientGuardrails::new(5, ["example.com".into()], []).expect("allowed guardrail");
        let error = summarize_recipients(
            "sender@example.com",
            &["agent@outside.test".into()],
            &[],
            &[],
            &allowed,
        )
        .unwrap_err();
        assert_eq!(error.code, "policy.recipient_domain_not_allowed");
    }

    #[test]
    fn message_identity_requires_uidvalidity_and_uid() {
        let valid = EmailMessageIdentity {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid: 42,
            expected_modseq: Some(9),
        };
        valid.validate().expect("valid identity");

        let mut invalid = valid.clone();
        invalid.uid_validity = 0;
        assert_eq!(
            invalid.validate().unwrap_err().code,
            "validation.uid_validity_invalid"
        );
        invalid.uid_validity = 7;
        invalid.uid = 0;
        assert_eq!(
            invalid.validate().unwrap_err().code,
            "validation.uid_invalid"
        );
    }

    #[test]
    fn writes_require_acknowledgement_but_previews_do_not() {
        let preview = InvocationControls {
            dry_run: true,
            ..InvocationControls::default()
        };
        assert_eq!(
            require_guarded_execution(EmailGuardedOperation::Delete, &preview).unwrap(),
            EmailExecutionMode::Preview
        );

        let error = require_guarded_execution(
            EmailGuardedOperation::Delete,
            &InvocationControls::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, "policy.acknowledgement_required");

        let apply = InvocationControls {
            acknowledgement: Some(InvocationAcknowledgement {
                actor: ActorRef {
                    id: "human-1".into(),
                    actor_type: ActorType::Human,
                },
                acknowledged_at: Utc::now(),
                reason: Some("reviewed preview".into()),
                approval_id: None,
            }),
            ..InvocationControls::default()
        };
        assert_eq!(
            require_guarded_execution(EmailGuardedOperation::Delete, &apply).unwrap(),
            EmailExecutionMode::Apply
        );
    }

    #[test]
    fn unsafe_attachment_names_and_idempotency_tokens_are_rejected() {
        for filename in ["../secret", "folder/file", "folder\\file", "\n.txt"] {
            assert_eq!(
                validate_attachment_filename(filename).unwrap_err().code,
                "validation.attachment_filename_unsafe"
            );
        }
        validate_attachment_filename("report.pdf").expect("safe filename");

        assert_eq!(
            validate_idempotency_key("short").unwrap_err().code,
            "validation.idempotency_key_invalid"
        );
        validate_idempotency_key("mail-send:2026-07-25:0001").expect("idempotency key");
    }
}
