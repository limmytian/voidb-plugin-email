//! Bounded IMAP IDLE sessions for agent mailbox observation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use voidb_core::{
    AGENT_LIVE_SESSION_PROTOCOL_VERSION, AgentLiveSessionAuditIdentity,
    AgentLiveSessionBackpressureMode, AgentLiveSessionBufferOverflow, AgentLiveSessionBufferPolicy,
    AgentLiveSessionCallCancellation, AgentLiveSessionCancelBehavior, AgentLiveSessionCloseEffect,
    AgentLiveSessionContract, AgentLiveSessionControlPolicy, AgentLiveSessionCursor,
    AgentLiveSessionCursorKind, AgentLiveSessionCursorScopePolicy, AgentLiveSessionDeliveryPolicy,
    AgentLiveSessionEventBuffer, AgentLiveSessionEventKind, AgentLiveSessionHeartbeatPolicy,
    AgentLiveSessionKind, AgentLiveSessionOperations, AgentLiveSessionReadRequest,
    AgentLiveSessionReconnectMode, AgentLiveSessionReconnectPolicy,
    AgentLiveSessionResourceDescriptor, AgentLiveSessionResumeMode, AgentLiveSessionStartRequest,
    AgentSessionCallRequest, AgentSessionCallResult, AgentSessionOpenContext, CapabilityRiskLevel,
    PluginAgentSession, PluginAgentSessionFactory, PluginSessionError, PluginSessionErrorCode,
    PluginSessionHealth, PluginSessionPurpose, RedactionStatus, agent_live_session_cursor_scope,
};

use crate::config::{EmailConfig, EmailProtocol};
use crate::service::imap_worker::ImapClient;
use crate::types::EmailMailboxSnapshot;

pub(crate) const EMAIL_IDLE_CAPABILITY: &str = "email.idle";
const HEARTBEAT_INTERVAL_MS: u64 = 15_000;
const IDLE_TIMEOUT_MS: u64 = 5_000;
const SESSION_IDLE_LIMIT_MS: u64 = 60_000;
const MAX_RECONNECT_ATTEMPTS: u32 = 5;

pub struct EmailAgentSessionFactory {
    config: EmailConfig,
}

impl EmailAgentSessionFactory {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PluginAgentSessionFactory for EmailAgentSessionFactory {
    fn plugin_id(&self) -> &str {
        "email"
    }

    async fn open(
        &self,
        context: AgentSessionOpenContext,
    ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError> {
        if self.config.protocol != EmailProtocol::IMAP {
            return Err(error(
                PluginSessionErrorCode::Unsupported,
                "Email IDLE sessions require an IMAP profile.",
            ));
        }
        if context.binding.purpose != PluginSessionPurpose::WatchStream
            || context.binding.allowed_capabilities.len() != 1
            || context.binding.allowed_capabilities[0]
                .strip_prefix("email.")
                .unwrap_or(&context.binding.allowed_capabilities[0])
                != "idle"
        {
            return Err(error(
                PluginSessionErrorCode::BindingMismatch,
                "Email IDLE requires one watch-stream binding for email.idle.",
            ));
        }

        let (purpose, contract) = email_idle_session_contract();
        if context.binding.purpose != purpose {
            return Err(error(
                PluginSessionErrorCode::BindingMismatch,
                "Email IDLE session purpose does not match its capability.",
            ));
        }
        contract.validate(&context.binding.allowed_capabilities)?;
        contract.validate_start(&context.request.input)?;
        let start: AgentLiveSessionStartRequest = serde_json::from_value(context.request.input)
            .map_err(|_| {
                error(
                    PluginSessionErrorCode::PolicyDenied,
                    "Email IDLE start envelope is invalid.",
                )
            })?;
        let folder = start
            .resource
            .get("folder")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                error(
                    PluginSessionErrorCode::PolicyDenied,
                    "Email IDLE mailbox folder is required.",
                )
            })?
            .to_string();
        let scope = agent_live_session_cursor_scope(EMAIL_IDLE_CAPABILITY, &start.resource)?;
        if start
            .resume_from
            .as_ref()
            .and_then(|cursor| cursor.scope.as_deref())
            .is_some_and(|supplied| supplied != scope)
        {
            return Err(error(
                PluginSessionErrorCode::BindingMismatch,
                "Email IDLE resume cursor belongs to another mailbox.",
            ));
        }
        let resume_value = start.resume_from.map(|cursor| cursor.value);
        let policy = start.buffer.unwrap_or_else(|| contract.buffer.clone());
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), policy)?;

        let config = self.config.clone();
        let opening_config = config.clone();
        let opening_folder = folder.clone();
        let (client, snapshot) = tokio::task::spawn_blocking(move || {
            let mut client = connect_imap(&opening_config)?;
            let snapshot = client.mailbox_snapshot(&opening_folder)?;
            anyhow::Ok((client, snapshot))
        })
        .await
        .map_err(|_| owner_error("Email IDLE connection task failed."))?
        .map_err(|_| owner_error("Email IDLE mailbox could not be opened."))?;

        let producer_buffer = buffer.clone();
        let task = tokio::spawn(async move {
            run_idle(
                config,
                folder,
                client,
                snapshot,
                producer_buffer.clone(),
                scope,
                resume_value,
            )
            .await;
            producer_buffer.close_source().await;
        });
        Ok(Arc::new(EmailIdleSession {
            buffer,
            task: Mutex::new(Some(task)),
            cancellations: AgentLiveSessionCallCancellation::default(),
            closed: AtomicBool::new(false),
        }))
    }
}

struct EmailIdleSession {
    buffer: AgentLiveSessionEventBuffer,
    task: Mutex<Option<JoinHandle<()>>>,
    cancellations: AgentLiveSessionCallCancellation,
    closed: AtomicBool,
}

#[async_trait]
impl PluginAgentSession for EmailIdleSession {
    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        if request.capability != EMAIL_IDLE_CAPABILITY
            && request.capability != EMAIL_IDLE_CAPABILITY.trim_start_matches("email.")
        {
            return Err(error(
                PluginSessionErrorCode::PolicyDenied,
                "Email IDLE calls must use email.idle.",
            ));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(owner_error("Email IDLE session is closed."));
        }
        let mut read = if request.input.is_null() {
            AgentLiveSessionReadRequest::default()
        } else {
            serde_json::from_value(request.input.clone()).map_err(|_| {
                error(
                    PluginSessionErrorCode::PolicyDenied,
                    "Email IDLE read request is invalid.",
                )
            })?
        };
        read.max_bytes = read.max_bytes.min(request.output_limit_bytes);
        let call_id = request.call_id.clone();
        let batch = self
            .cancellations
            .run(&call_id, self.buffer.read(&read))
            .await?;
        let output = serde_json::to_value(batch).map_err(|_| {
            error(
                PluginSessionErrorCode::RedactionFailed,
                "Email IDLE event batch could not be serialized.",
            )
        })?;
        AgentSessionCallResult::bounded(request.call_id, output, request.output_limit_bytes)
    }

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
        Ok(if self.closed.load(Ordering::Acquire) {
            PluginSessionHealth::Closed
        } else {
            PluginSessionHealth::Ready
        })
    }

    async fn cancel(&self, call_id: &str) -> Result<(), PluginSessionError> {
        self.cancellations.cancel(call_id).await;
        Ok(())
    }

    async fn close(&self, _reason: String) -> Result<(), PluginSessionError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.cancellations.close().await;
        if let Some(task) = self.task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        self.buffer.close_source().await;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_idle(
    config: EmailConfig,
    folder: String,
    mut client: ImapClient,
    mut previous: EmailMailboxSnapshot,
    buffer: AgentLiveSessionEventBuffer,
    scope: String,
    resume_value: Option<String>,
) {
    let initial_cursor = snapshot_cursor(&previous, &scope);
    if resume_value.as_deref() != Some(initial_cursor.value.as_str())
        && push_snapshot(&buffer, &previous, &scope, "snapshot")
            .await
            .is_err()
    {
        return;
    }
    let mut last_heartbeat = Instant::now();
    loop {
        let idle_folder = folder.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let result = client.idle_snapshot(&idle_folder, Duration::from_millis(IDLE_TIMEOUT_MS));
            (client, result)
        })
        .await;
        match joined {
            Ok((next_client, Ok(snapshot))) => {
                client = next_client;
                if snapshot != previous {
                    let change_kind = if snapshot.uid_validity != previous.uid_validity {
                        "uid_validity_changed"
                    } else if snapshot.highest_uid > previous.highest_uid {
                        "message_arrival"
                    } else {
                        "mailbox_changed"
                    };
                    if push_snapshot(&buffer, &snapshot, &scope, change_kind)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    previous = snapshot;
                }
            }
            Ok((_, Err(_))) | Err(_) => {
                let Some((next_client, snapshot)) = reconnect(&config, &folder, &buffer).await
                else {
                    return;
                };
                client = next_client;
                if snapshot != previous {
                    if push_snapshot(&buffer, &snapshot, &scope, "reconnected")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    previous = snapshot;
                }
            }
        }
        if last_heartbeat.elapsed() >= Duration::from_millis(HEARTBEAT_INTERVAL_MS) {
            if buffer
                .push(
                    Utc::now(),
                    AgentLiveSessionEventKind::Heartbeat,
                    Value::Null,
                    None,
                    RedactionStatus::NotRequired,
                    false,
                )
                .await
                .is_err()
            {
                return;
            }
            last_heartbeat = Instant::now();
        }
    }
}

async fn reconnect(
    config: &EmailConfig,
    folder: &str,
    buffer: &AgentLiveSessionEventBuffer,
) -> Option<(ImapClient, EmailMailboxSnapshot)> {
    for attempt in 0..MAX_RECONNECT_ATTEMPTS {
        if buffer.record_reconnect().await.is_err() {
            return None;
        }
        let delay_ms = (250u64.saturating_mul(1u64 << attempt.min(4))).min(4_000);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        let reconnect_config = config.clone();
        let reconnect_folder = folder.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut client = connect_imap(&reconnect_config)?;
            let snapshot = client.mailbox_snapshot(&reconnect_folder)?;
            anyhow::Ok((client, snapshot))
        })
        .await;
        if let Ok(Ok(connected)) = result {
            return Some(connected);
        }
    }
    None
}

fn connect_imap(config: &EmailConfig) -> anyhow::Result<ImapClient> {
    ImapClient::connect_with_security_and_tls_verification(
        &config.receive.host,
        config.receive.port,
        &config.email,
        &config.password,
        config.receive_security,
        config.verify_tls,
    )
}

async fn push_snapshot(
    buffer: &AgentLiveSessionEventBuffer,
    snapshot: &EmailMailboxSnapshot,
    scope: &str,
    change_kind: &str,
) -> Result<(), PluginSessionError> {
    buffer
        .push(
            Utc::now(),
            AgentLiveSessionEventKind::Data,
            json!({
                "uid_validity": snapshot.uid_validity,
                "highest_uid": snapshot.highest_uid,
                "exists": snapshot.exists,
                "highest_modseq": snapshot.highest_modseq,
                "change_kind": change_kind,
                "message_content_omitted": true
            }),
            Some(snapshot_cursor(snapshot, scope)),
            RedactionStatus::NotRequired,
            false,
        )
        .await
        .map(|_| ())
}

fn snapshot_cursor(snapshot: &EmailMailboxSnapshot, scope: &str) -> AgentLiveSessionCursor {
    AgentLiveSessionCursor {
        kind: AgentLiveSessionCursorKind::EventId,
        value: format!("{}:{}", snapshot.uid_validity, snapshot.highest_uid),
        scope: Some(scope.to_string()),
    }
}

pub(crate) fn email_idle_session_contract() -> (PluginSessionPurpose, AgentLiveSessionContract) {
    (
        PluginSessionPurpose::WatchStream,
        AgentLiveSessionContract {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            kind: AgentLiveSessionKind::Events,
            resource: AgentLiveSessionResourceDescriptor {
                resource_type: "email_mailbox".into(),
                identity_schema: json!({
                    "type": "object",
                    "required": ["folder"],
                    "properties": {
                        "folder": { "type": "string", "minLength": 1, "maxLength": 1024 }
                    },
                    "additionalProperties": false
                }),
                identity_fields: vec!["/folder".into()],
                audit_identity: AgentLiveSessionAuditIdentity::Fingerprint,
            },
            start_parameters_schema: json!({
                "type": "object",
                "additionalProperties": false
            }),
            event_schema: json!({
                "type": "object",
                "required": [
                    "uid_validity", "highest_uid", "exists", "highest_modseq",
                    "change_kind", "message_content_omitted"
                ],
                "properties": {
                    "uid_validity": { "type": "integer", "minimum": 1 },
                    "highest_uid": { "type": "integer", "minimum": 0 },
                    "exists": { "type": "integer", "minimum": 0 },
                    "highest_modseq": { "type": ["integer", "null"], "minimum": 1 },
                    "change_kind": {
                        "type": "string",
                        "enum": [
                            "snapshot", "message_arrival", "mailbox_changed",
                            "uid_validity_changed", "reconnected"
                        ]
                    },
                    "message_content_omitted": { "const": true }
                },
                "additionalProperties": false
            }),
            operations: AgentLiveSessionOperations {
                events: EMAIL_IDLE_CAPABILITY.into(),
                input: None,
                resize: None,
                signal: None,
            },
            buffer: AgentLiveSessionBufferPolicy {
                max_events: 512,
                max_bytes: 512 * 1024,
                overflow: AgentLiveSessionBufferOverflow::DropOldest,
            },
            reconnect: AgentLiveSessionReconnectPolicy {
                mode: AgentLiveSessionReconnectMode::Transient,
                max_attempts: MAX_RECONNECT_ATTEMPTS,
                initial_backoff_ms: 250,
                max_backoff_ms: 4_000,
                resume: AgentLiveSessionResumeMode::BestEffortCursor,
                cursor_kind: Some(AgentLiveSessionCursorKind::EventId),
            },
            delivery: AgentLiveSessionDeliveryPolicy {
                backpressure: AgentLiveSessionBackpressureMode::BoundedBuffer,
                cursor_scope: AgentLiveSessionCursorScopePolicy::Required,
                heartbeat: AgentLiveSessionHeartbeatPolicy {
                    interval_ms: Some(HEARTBEAT_INTERVAL_MS),
                    idle_timeout_ms: Some(SESSION_IDLE_LIMIT_MS),
                },
                max_read_wait_ms: 30_000,
            },
            control: AgentLiveSessionControlPolicy {
                cancel: AgentLiveSessionCancelBehavior::CallOnly,
                close: AgentLiveSessionCloseEffect::StopObservation,
            },
            start_risk: CapabilityRiskLevel::ReadOnly,
        },
    )
}

fn owner_error(message: &str) -> PluginSessionError {
    error(PluginSessionErrorCode::OwnerUnavailable, message)
}

fn error(code: PluginSessionErrorCode, message: &str) -> PluginSessionError {
    PluginSessionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SecurityType, ServerConfig};
    use voidb_core::{AgentSessionRef, PluginSessionErrorCode};

    #[test]
    fn idle_contract_is_bounded_scoped_and_resumable() {
        let (purpose, contract) = email_idle_session_contract();
        assert_eq!(purpose, PluginSessionPurpose::WatchStream);
        contract
            .validate(&[EMAIL_IDLE_CAPABILITY.into()])
            .expect("valid contract");
        assert_eq!(contract.buffer.max_events, 512);
        assert_eq!(
            contract.buffer.overflow,
            AgentLiveSessionBufferOverflow::DropOldest
        );
        assert_eq!(
            contract.reconnect.resume,
            AgentLiveSessionResumeMode::BestEffortCursor
        );
        assert_eq!(
            contract.delivery.cursor_scope,
            AgentLiveSessionCursorScopePolicy::Required
        );
        assert_eq!(
            contract.control.cancel,
            AgentLiveSessionCancelBehavior::CallOnly
        );
        assert_eq!(
            contract.control.close,
            AgentLiveSessionCloseEffect::StopObservation
        );
    }

    #[tokio::test]
    async fn snapshot_events_have_mailbox_scoped_uid_cursors_and_no_content() {
        let (_, contract) = email_idle_session_contract();
        let buffer =
            AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone()).unwrap();
        let resource = json!({ "folder": "INBOX" });
        let scope = agent_live_session_cursor_scope(EMAIL_IDLE_CAPABILITY, &resource).unwrap();
        let snapshot = EmailMailboxSnapshot {
            folder: "INBOX".into(),
            uid_validity: 19,
            highest_uid: 42,
            exists: 7,
            highest_modseq: Some(55),
        };
        push_snapshot(&buffer, &snapshot, &scope, "message_arrival")
            .await
            .unwrap();
        let batch = buffer
            .read_available(&AgentLiveSessionReadRequest::default())
            .await
            .unwrap();
        let encoded = serde_json::to_string(&batch).unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].data["message_content_omitted"], true);
        assert_eq!(batch.events[0].cursor.as_ref().unwrap().value, "19:42");
        assert_eq!(
            batch.events[0].cursor.as_ref().unwrap().scope.as_deref(),
            Some(scope.as_str())
        );
        assert!(!encoded.contains("INBOX"));
    }

    #[tokio::test]
    async fn idle_read_call_can_be_cancelled_without_closing_source() {
        let (_, contract) = email_idle_session_contract();
        let session = Arc::new(EmailIdleSession {
            buffer: AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())
                .unwrap(),
            task: Mutex::new(None),
            cancellations: AgentLiveSessionCallCancellation::default(),
            closed: AtomicBool::new(false),
        });
        let pending = {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                session
                    .call(AgentSessionCallRequest {
                        session: AgentSessionRef::new("email-idle-test", 1),
                        call_id: "email-idle-call".into(),
                        capability: EMAIL_IDLE_CAPABILITY.into(),
                        input: json!({ "wait_timeout_ms": 30_000 }),
                        destructive_acknowledged: false,
                        timeout_ms: Some(30_000),
                        output_limit_bytes: 64 * 1024,
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        session.cancel("email-idle-call").await.unwrap();
        let error = pending
            .await
            .expect("call task")
            .expect_err("cancelled call");
        assert_eq!(error.code, PluginSessionErrorCode::Cancelled);
        assert_eq!(session.health().await.unwrap(), PluginSessionHealth::Ready);
        session.close("test complete".into()).await.unwrap();
        session.close("idempotent close".into()).await.unwrap();
        assert_eq!(session.health().await.unwrap(), PluginSessionHealth::Closed);
    }

    #[tokio::test]
    async fn pop3_profile_is_rejected_before_target_connection() {
        let config = EmailConfig {
            email: "user@example.test".into(),
            password: "secret".into(),
            protocol: EmailProtocol::POP3,
            receive: ServerConfig {
                host: "does-not-exist.invalid".into(),
                port: 110,
            },
            smtp: ServerConfig {
                host: "does-not-exist.invalid".into(),
                port: 25,
            },
            receive_security: SecurityType::None,
            smtp_security: SecurityType::None,
            verify_tls: true,
        };
        let factory = EmailAgentSessionFactory::new(config);
        let result = factory
            .open(AgentSessionOpenContext {
                binding: voidb_core::AgentSessionBinding {
                    grant_id: "grant".into(),
                    profile_id: "profile".into(),
                    plugin_id: "email".into(),
                    purpose: PluginSessionPurpose::WatchStream,
                    allowed_capabilities: vec![EMAIL_IDLE_CAPABILITY.into()],
                    host_generation: 1,
                },
                request: voidb_core::AgentSessionOpenRequest {
                    purpose: PluginSessionPurpose::WatchStream,
                    capabilities: vec![EMAIL_IDLE_CAPABILITY.into()],
                    lease_seconds: 60,
                    concurrency: Default::default(),
                    destructive_acknowledged: false,
                    input: json!({
                        "resource": { "folder": "INBOX" },
                        "parameters": {}
                    }),
                },
                lease_expires_at: Utc::now() + chrono::Duration::seconds(60),
            })
            .await;
        let error = match result {
            Ok(_) => panic!("POP3 IDLE should be denied"),
            Err(error) => error,
        };
        assert_eq!(error.code, PluginSessionErrorCode::Unsupported);
    }
}
