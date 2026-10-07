//! Email fixture-backed capability smoke driver.
//!
//! This example is script-facing. It seeds a disposable local GreenMail mailbox
//! through the plugin service layer, then exercises the read-only Email
//! capability surface against the generated fixture environment.

#![allow(clippy::result_large_err)]

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use serde_json::{Value, json};
use voidb_core::{
    ActorRef, ActorType, AgentSessionBinding, AgentSessionCallRequest, AgentSessionOpenContext,
    AgentSessionOpenRequest, AgentSessionRef, CapabilityError, CapabilityInvocation,
    CapabilityInvocationResult, InvocationAcknowledgement, InvocationConnectionTarget,
    InvocationControls, InvocationStatus, Pagination, PluginAgentSession,
    PluginAgentSessionFactory, PluginSessionErrorCode, PluginSessionPurpose, RedactionStatus,
};
use voidb_plugin_email::service::imap_worker::ImapClient;
use voidb_plugin_email::{
    EmailAgentSessionFactory, EmailConfig, EmailProtocol, EmailService, SecurityType, ServerConfig,
    invoke_email_capability,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = config_from_env()?;
    ensure!(
        config.receive_security == SecurityType::None && !config.verify_tls,
        "fixture smoke expects a local plaintext receive endpoint"
    );
    ensure!(
        config.smtp_security == SecurityType::None,
        "fixture smoke expects a local plaintext SMTP endpoint"
    );

    let run_id =
        std::env::var("VOIDB_FIXTURE_RUN_ID").unwrap_or_else(|_| "email-fixture-smoke".into());
    let folder = std::env::var("VOIDB_EMAIL_SMOKE_FOLDER").unwrap_or_else(|_| "INBOX".into());
    let subject_a = format!("VoidB fixture smoke {run_id} alpha");
    let subject_b = format!("VoidB fixture smoke {run_id} beta");
    let body_a = format!(
        "VoidB fixture message alpha for {run_id}. This body is intentionally long enough to exercise truncation in the fetch capability."
    );
    let body_b = format!("VoidB fixture message beta for {run_id}.");

    let diagnostics = invoke_checked(
        &config,
        "diagnostics",
        json!({}),
        None,
        "email.diagnostics should succeed",
    )
    .await?;
    ensure_succeeded(&diagnostics, "email.diagnostics")?;
    ensure!(
        diagnostics.output["network_checked"] == false
            && diagnostics.output["send_deferred"] == false
            && diagnostics.output["delete_deferred"] == false,
        "diagnostics should be offline and report guarded send/delete availability: {}",
        diagnostics.output
    );
    ensure_output_excludes(&diagnostics, &config.password, "email.diagnostics")?;
    ensure_output_excludes(&diagnostics, &config.email, "email.diagnostics")?;

    seed_message(&config, &subject_a, &body_a).await?;
    seed_message(&config, &subject_b, &body_b).await?;

    let folders = invoke_checked(
        &config,
        "folders",
        json!({}),
        None,
        "email.folders should succeed",
    )
    .await?;
    ensure_succeeded(&folders, "email.folders")?;
    ensure_folder_present(&folders.output, &folder)?;

    let paged = wait_for_messages(&config, &folder, 2).await?;
    ensure!(
        paged.output["message_count"].as_u64().unwrap_or_default() <= 1,
        "email.list should honor page limit: {}",
        paged.output
    );
    ensure!(
        paged.output["total"].as_u64().unwrap_or_default() >= 2
            && paged.output["next_cursor"].is_string(),
        "email.list should report pagination for seeded messages: {}",
        paged.output
    );

    let all_messages = invoke_checked(
        &config,
        "list",
        json!({ "folder": folder }),
        Some(Pagination {
            limit: 10,
            cursor: None,
        }),
        "email.list full page should succeed",
    )
    .await?;
    ensure_succeeded(&all_messages, "email.list full page")?;
    let uid = message_uid_by_subject(&all_messages.output, &subject_a)
        .or_else(|| message_uid_by_subject(&all_messages.output, &subject_b))
        .context("seeded message should appear in email.list output")?;

    let search = invoke_checked(
        &config,
        "search",
        json!({ "folder": folder, "query": run_id }),
        Some(Pagination {
            limit: 10,
            cursor: None,
        }),
        "email.search should succeed",
    )
    .await?;
    ensure_succeeded(&search, "email.search")?;
    ensure!(
        search.output["message_count"].as_u64().unwrap_or_default() >= 1,
        "email.search should find the seeded fixture message: {}",
        search.output
    );

    let empty_page = invoke_checked(
        &config,
        "list",
        json!({ "folder": folder }),
        Some(Pagination {
            limit: 10,
            cursor: Some("99".into()),
        }),
        "email.list empty page should succeed",
    )
    .await?;
    ensure_succeeded(&empty_page, "email.list empty page")?;
    ensure!(
        empty_page.output["message_count"] == 0,
        "out-of-range page should be empty: {}",
        empty_page.output
    );

    let fetch = invoke_checked(
        &config,
        "fetch",
        json!({
            "folder": folder,
            "uid": uid,
            "include_html": false,
            "max_text_bytes": 48
        }),
        None,
        "email.fetch should succeed",
    )
    .await?;
    ensure_succeeded(&fetch, "email.fetch")?;
    ensure!(
        fetch.output["message"]["text_truncated"] == true
            && fetch.output["message"]["text"]
                .as_str()
                .unwrap_or_default()
                .len()
                <= 48,
        "email.fetch should respect text bounds: {}",
        fetch.output
    );

    ensure_failed_auth_redacts(&config).await?;
    run_guarded_workflows(&config, &folder, &run_id).await?;

    println!("email fixture capability smoke passed");
    println!(
        "capabilities: diagnostics, folders, list, search, fetch, draft, send, move, delete, set_flags, attachments, download_attachment, idle"
    );
    println!("seeded_messages: 2");
    Ok(())
}

async fn run_guarded_workflows(config: &EmailConfig, folder: &str, run_id: &str) -> Result<()> {
    let staging_root = std::env::temp_dir().join(format!("voidb-email-fixture-{run_id}"));
    if staging_root.exists() {
        fs::remove_dir_all(&staging_root).context("remove stale Email fixture staging root")?;
    }
    fs::create_dir_all(&staging_root).context("create Email fixture staging root")?;
    let upload_name = "fixture-upload.txt";
    let upload_bytes = b"PRIVATE_ATTACHMENT_BYTES_MUST_NOT_APPEAR";
    fs::write(staging_root.join(upload_name), upload_bytes).context("write fixture attachment")?;

    let subject = format!("VoidB guarded send {run_id}");
    let private_body = format!("PRIVATE_EMAIL_BODY_{run_id}");
    let send_input = json!({
        "to": [config.email],
        "subject": subject,
        "text_body": private_body,
        "idempotency_key": format!("fixture-send-{run_id}"),
        "local_root": staging_root,
        "attachments": [{
            "local_path": upload_name,
            "filename": upload_name,
            "content_type": "text/plain",
            "byte_size": upload_bytes.len()
        }]
    });

    let denied = invoke_guarded(config, "send", send_input.clone(), false, false)
        .await
        .expect_err("send without acknowledgement must be denied");
    ensure!(
        denied.code == "policy.acknowledgement_required",
        "send denial should require acknowledgement: {denied:?}"
    );

    let preview = invoke_guarded(config, "send", send_input.clone(), true, false)
        .await
        .map_err(|error| anyhow::anyhow!("email.send preview: {error:?}"))?;
    ensure!(
        preview.output["dry_run"] == true
            && preview.output["sent"] == false
            && preview.output["preview"]["content_redacted"] == true,
        "send preview should be redacted and side-effect free: {}",
        preview.output
    );
    for sample in [
        config.email.as_str(),
        private_body.as_str(),
        staging_root.to_string_lossy().as_ref(),
        "PRIVATE_ATTACHMENT_BYTES_MUST_NOT_APPEAR",
    ] {
        ensure_output_excludes(&preview, sample, "email.send preview")?;
    }

    let sent = invoke_guarded(config, "send", send_input.clone(), false, true)
        .await
        .map_err(|error| anyhow::anyhow!("email.send apply: {error:?}"))?;
    ensure!(
        sent.output["sent"] == true
            && sent.output["dry_run"] == false
            && sent.output["content_redacted"] == true,
        "acknowledged send should succeed: {}",
        sent.output
    );
    ensure_output_excludes(&sent, config.email.as_str(), "email.send apply")?;
    ensure_output_excludes(&sent, private_body.as_str(), "email.send apply")?;

    let replay = invoke_guarded(config, "send", send_input, false, true)
        .await
        .map_err(|error| anyhow::anyhow!("email.send idempotent replay: {error:?}"))?;
    ensure!(
        replay.output["idempotent_replay"] == true,
        "send retry should reuse the bounded idempotent outcome: {}",
        replay.output
    );

    let message = wait_for_subject(config, folder, &subject).await?;
    let identity = stable_identity(&message, folder)?;
    let stale_identity = json!({
        "folder": folder,
        "uid_validity": identity["uid_validity"],
        "uid": identity["uid"].as_u64().unwrap_or_default().saturating_add(1_000_000)
    });
    let flag_input = json!({
        "messages": [identity.clone(), stale_identity],
        "action": "add",
        "flags": ["flagged"],
        "idempotency_key": format!("fixture-flags-{run_id}")
    });
    let flag_preview = invoke_guarded(config, "set_flags", flag_input.clone(), true, false)
        .await
        .map_err(|error| anyhow::anyhow!("email.set_flags preview: {error:?}"))?;
    ensure!(
        flag_preview.output["dry_run"] == true
            && flag_preview.output["preview"]["message_content_redacted"] == true,
        "flag preview should be redacted: {}",
        flag_preview.output
    );
    let flags = invoke_guarded(config, "set_flags", flag_input, false, true)
        .await
        .map_err(|error| anyhow::anyhow!("email.set_flags apply: {error:?}"))?;
    ensure!(
        flags.output["succeeded"] == 1
            && flags.output["failed"] == 1
            && flags.output["partial_failure"] == true,
        "flag batch should report deterministic partial failure: {}",
        flags.output
    );

    let attachment_list = invoke_checked(
        config,
        "attachments",
        identity.clone(),
        None,
        "email.attachments should succeed",
    )
    .await?;
    ensure!(
        attachment_list.output["attachment_count"] == 1
            && attachment_list.output["bytes_omitted"] == true,
        "attachment metadata should omit bytes: {}",
        attachment_list.output
    );

    let download_input = merge_json(
        identity.clone(),
        json!({
            "attachment_index": 0,
            "local_root": staging_root,
            "local_path": "downloaded.txt",
            "idempotency_key": format!("fixture-download-{run_id}")
        }),
    );
    let download_preview = invoke_guarded(
        config,
        "download_attachment",
        download_input.clone(),
        true,
        false,
    )
    .await
    .map_err(|error| anyhow::anyhow!("attachment download preview: {error:?}"))?;
    ensure!(
        download_preview.output["written"] == false
            && !staging_root.join("downloaded.txt").exists(),
        "download preview must not write a file: {}",
        download_preview.output
    );
    let downloaded = invoke_guarded(config, "download_attachment", download_input, false, true)
        .await
        .map_err(|error| anyhow::anyhow!("attachment download apply: {error:?}"))?;
    ensure!(
        downloaded.output["written"] == true
            && fs::read(staging_root.join("downloaded.txt"))? == upload_bytes,
        "downloaded attachment should match fixture bytes: {}",
        downloaded.output
    );

    let traversal = merge_json(
        identity.clone(),
        json!({
            "attachment_index": 0,
            "local_root": staging_root,
            "local_path": "../escape.txt",
            "idempotency_key": format!("fixture-traversal-{run_id}")
        }),
    );
    let traversal_error = invoke_guarded(config, "download_attachment", traversal, false, true)
        .await
        .expect_err("attachment traversal must be rejected");
    ensure!(
        traversal_error.category == voidb_core::CapabilityErrorCategory::Permission,
        "traversal should fail at the local path policy boundary: {traversal_error:?}"
    );

    let archive = format!("VoidB-{run_id}-Archive");
    ensure_fixture_mailbox(config, &archive)?;
    let move_input = json!({
        "messages": [identity],
        "destination_folder": archive,
        "idempotency_key": format!("fixture-move-{run_id}")
    });
    let moved = invoke_guarded(config, "move", move_input, false, true)
        .await
        .map_err(|error| anyhow::anyhow!("email.move apply: {error:?}"))?;
    ensure!(
        moved.output["succeeded"] == 1 && moved.output["failed"] == 0,
        "stable message move should succeed: {}",
        moved.output
    );

    let delete_subject = format!("VoidB delete target {run_id}");
    seed_message(config, &delete_subject, "disposable delete target").await?;
    let delete_message = wait_for_subject(config, folder, &delete_subject).await?;
    let delete_identity = stable_identity(&delete_message, folder)?;
    let delete_input = json!({
        "messages": [delete_identity],
        "delete_mode": "expunge",
        "idempotency_key": format!("fixture-delete-{run_id}")
    });
    let deleted = invoke_guarded(config, "delete", delete_input, false, true)
        .await
        .map_err(|error| anyhow::anyhow!("email.delete apply: {error:?}"))?;
    ensure!(
        deleted.output["succeeded"] == 1 && deleted.output["failed"] == 0,
        "stable UID expunge should succeed: {}",
        deleted.output
    );

    run_idle_session_journey(config, folder, run_id).await?;
    fs::remove_dir_all(&staging_root).context("remove Email fixture staging root")?;
    Ok(())
}

async fn run_idle_session_journey(config: &EmailConfig, folder: &str, run_id: &str) -> Result<()> {
    let factory = EmailAgentSessionFactory::new(config.clone());
    let session = factory
        .open(AgentSessionOpenContext {
            binding: AgentSessionBinding {
                grant_id: "email-fixture-grant".into(),
                profile_id: "email-fixture-profile".into(),
                plugin_id: "email".into(),
                purpose: PluginSessionPurpose::WatchStream,
                allowed_capabilities: vec!["email.idle".into()],
                host_generation: 1,
            },
            request: AgentSessionOpenRequest {
                purpose: PluginSessionPurpose::WatchStream,
                capabilities: vec!["email.idle".into()],
                lease_seconds: 60,
                concurrency: Default::default(),
                destructive_acknowledged: false,
                input: json!({
                    "resource": { "folder": folder },
                    "parameters": {}
                }),
            },
            lease_expires_at: Utc::now() + chrono::Duration::seconds(60),
        })
        .await
        .map_err(|error| anyhow::anyhow!("open email.idle session: {error}"))?;
    let first = idle_call(
        session.as_ref(),
        "idle-initial",
        json!({ "wait_timeout_ms": 10_000 }),
    )
    .await?;
    ensure!(
        first["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty()),
        "IDLE should publish an initial bounded mailbox checkpoint: {first}"
    );
    let after_sequence = first["next_sequence"]
        .as_u64()
        .unwrap_or(1)
        .saturating_sub(1);

    let subject = format!("VoidB IDLE event {run_id}");
    let input = json!({
        "to": [config.email],
        "subject": subject,
        "text_body": "IDLE_BODY_MUST_NOT_APPEAR",
        "idempotency_key": format!("fixture-idle-send-{run_id}")
    });
    invoke_guarded(config, "send", input, false, true)
        .await
        .map_err(|error| anyhow::anyhow!("send IDLE trigger: {error:?}"))?;
    let update = idle_call(
        session.as_ref(),
        "idle-update",
        json!({
            "after_sequence": after_sequence,
            "wait_timeout_ms": 30_000
        }),
    )
    .await?;
    ensure!(
        update["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| {
                event["data"]["change_kind"] == "message_arrival"
                    && event["data"]["message_content_omitted"] == true
            })),
        "IDLE should emit a content-free arrival event: {update}"
    );
    ensure!(
        !serde_json::to_string(&update)?.contains("IDLE_BODY_MUST_NOT_APPEAR"),
        "IDLE event exposed message content"
    );

    let pending = {
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            idle_call(
                session.as_ref(),
                "idle-cancel",
                json!({
                    "after_sequence": 9_999_999,
                    "wait_timeout_ms": 30_000
                }),
            )
            .await
        })
    };
    tokio::task::yield_now().await;
    session
        .cancel("idle-cancel")
        .await
        .map_err(|error| anyhow::anyhow!("cancel IDLE read: {error}"))?;
    let cancellation = pending.await.context("join cancelled IDLE call")?;
    let error = cancellation.expect_err("IDLE read should observe cancellation");
    ensure!(
        error
            .downcast_ref::<voidb_core::PluginSessionError>()
            .is_some_and(|error| error.code == PluginSessionErrorCode::Cancelled),
        "IDLE cancellation should return the stable cancelled code: {error:#}"
    );
    session
        .close("fixture complete".into())
        .await
        .map_err(|error| anyhow::anyhow!("close email.idle session: {error}"))?;
    Ok(())
}

async fn idle_call(session: &dyn PluginAgentSession, call_id: &str, input: Value) -> Result<Value> {
    let result = session
        .call(AgentSessionCallRequest {
            session: AgentSessionRef::new("email-fixture-idle", 1),
            call_id: call_id.into(),
            capability: "email.idle".into(),
            input,
            destructive_acknowledged: false,
            timeout_ms: Some(30_000),
            output_limit_bytes: 128 * 1024,
        })
        .await
        .map_err(anyhow::Error::new)?;
    Ok(result.output)
}

fn ensure_fixture_mailbox(config: &EmailConfig, folder: &str) -> Result<()> {
    let mut client = ImapClient::connect_with_security_and_tls_verification(
        &config.receive.host,
        config.receive.port,
        &config.email,
        &config.password,
        config.receive_security,
        config.verify_tls,
    )
    .context("connect fixture IMAP client")?;
    client
        .ensure_mailbox(folder)
        .context("create fixture mailbox")
}

async fn wait_for_subject(config: &EmailConfig, folder: &str, subject: &str) -> Result<Value> {
    for _ in 0..30 {
        let messages = invoke_checked(
            config,
            "list",
            json!({ "folder": folder }),
            Some(Pagination {
                limit: 100,
                cursor: None,
            }),
            "email.list while waiting for subject",
        )
        .await?;
        if let Some(message) = messages.output["messages"].as_array().and_then(|messages| {
            messages
                .iter()
                .find(|message| message["subject"] == subject)
        }) {
            return Ok(message.clone());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    bail!("message with expected fixture subject did not appear")
}

fn stable_identity(message: &Value, folder: &str) -> Result<Value> {
    let uid = message["uid"].as_u64().context("message UID")?;
    let uid_validity = message["uid_validity"]
        .as_u64()
        .context("message UIDVALIDITY")?;
    let mut identity = json!({
        "folder": folder,
        "uid_validity": uid_validity,
        "uid": uid
    });
    if let Some(modseq) = message["modseq"].as_u64() {
        identity["expected_modseq"] = json!(modseq);
    }
    Ok(identity)
}

fn merge_json(mut base: Value, extra: Value) -> Value {
    let base = base.as_object_mut().expect("object identity");
    for (key, value) in extra.as_object().expect("object fields") {
        base.insert(key.clone(), value.clone());
    }
    Value::Object(base.clone())
}

fn config_from_env() -> Result<EmailConfig> {
    Ok(EmailConfig {
        email: required_env("VOIDB_EMAIL_SMOKE_EMAIL")?,
        password: required_env("VOIDB_EMAIL_SMOKE_PASSWORD")?,
        protocol: EmailProtocol::IMAP,
        receive: ServerConfig {
            host: required_env("VOIDB_EMAIL_SMOKE_IMAP_HOST")?,
            port: required_env("VOIDB_EMAIL_SMOKE_IMAP_PORT")?
                .parse()
                .context("VOIDB_EMAIL_SMOKE_IMAP_PORT must be a u16")?,
        },
        smtp: ServerConfig {
            host: required_env("VOIDB_EMAIL_SMOKE_SMTP_HOST")?,
            port: required_env("VOIDB_EMAIL_SMOKE_SMTP_PORT")?
                .parse()
                .context("VOIDB_EMAIL_SMOKE_SMTP_PORT must be a u16")?,
        },
        receive_security: SecurityType::None,
        smtp_security: SecurityType::None,
        verify_tls: false,
    })
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

async fn seed_message(config: &EmailConfig, subject: &str, body: &str) -> Result<()> {
    let mut service = EmailService::new_direct().context("create direct EmailService")?;
    service
        .send_email_direct(
            config.smtp.host.clone(),
            config.smtp.port,
            config.smtp_security,
            config.email.clone(),
            config.email.clone(),
            config.password.clone(),
            config.email.clone(),
            subject.to_string(),
            body.to_string(),
            Vec::new(),
        )
        .await
        .context("seed fixture message through SMTP")
}

async fn wait_for_messages(
    config: &EmailConfig,
    folder: &str,
    expected_total: u64,
) -> Result<CapabilityInvocationResult> {
    let mut last = None;
    for _ in 0..20 {
        let result = invoke_checked(
            config,
            "list",
            json!({ "folder": folder }),
            Some(Pagination {
                limit: 1,
                cursor: None,
            }),
            "email.list paged should succeed",
        )
        .await?;
        if result.output["total"].as_u64().unwrap_or_default() >= expected_total {
            return Ok(result);
        }
        last = Some(result.output);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    bail!(
        "seeded messages did not appear in mailbox; last list output: {}",
        last.unwrap_or(Value::Null)
    )
}

async fn invoke(
    config: &EmailConfig,
    capability_id: &str,
    input: Value,
    page: Option<Pagination>,
) -> std::result::Result<CapabilityInvocationResult, CapabilityError> {
    invoke_with_controls(config, capability_id, input, false, false, page).await
}

async fn invoke_guarded(
    config: &EmailConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    acknowledged: bool,
) -> std::result::Result<CapabilityInvocationResult, CapabilityError> {
    invoke_with_controls(config, capability_id, input, dry_run, acknowledged, None).await
}

async fn invoke_with_controls(
    config: &EmailConfig,
    capability_id: &str,
    input: Value,
    dry_run: bool,
    acknowledged: bool,
    page: Option<Pagination>,
) -> std::result::Result<CapabilityInvocationResult, CapabilityError> {
    let actor = ActorRef {
        id: "agent:email-fixture-smoke".into(),
        actor_type: ActorType::Agent,
    };
    invoke_email_capability(
        config,
        CapabilityInvocation {
            id: format!("email-fixture-smoke-{capability_id}"),
            plugin_id: "email".into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls {
                dry_run,
                acknowledgement: acknowledged.then(|| InvocationAcknowledgement {
                    actor: actor.clone(),
                    acknowledged_at: Utc::now(),
                    reason: Some("deterministic disposable fixture mutation".into()),
                    approval_id: None,
                }),
                page,
                ..InvocationControls::default()
            },
            actor: Some(actor),
            requested_at: Utc::now(),
        },
    )
    .await
}

async fn invoke_checked(
    config: &EmailConfig,
    capability_id: &str,
    input: Value,
    page: Option<Pagination>,
    label: &str,
) -> Result<CapabilityInvocationResult> {
    invoke(config, capability_id, input, page)
        .await
        .map_err(|error| {
            let error_json = serde_json::to_string(&error).unwrap_or_else(|_| format!("{error:?}"));
            anyhow::anyhow!("{label}: {error_json}")
        })
}

fn ensure_succeeded(result: &CapabilityInvocationResult, label: &str) -> Result<()> {
    ensure!(
        result.status == InvocationStatus::Succeeded,
        "{label} returned non-success status: {:?}",
        result.status
    );
    Ok(())
}

fn ensure_output_excludes(
    result: &CapabilityInvocationResult,
    sample: &str,
    label: &str,
) -> Result<()> {
    let output = serde_json::to_string(&result.output)?;
    let summary = serde_json::to_string(&result.output_summary)?;
    ensure!(
        !output.contains(sample) && !summary.contains(sample),
        "{label} output exposed protected sample"
    );
    Ok(())
}

fn ensure_folder_present(output: &Value, folder: &str) -> Result<()> {
    let folders = output["folders"]
        .as_array()
        .context("email.folders output should include folders array")?;
    ensure!(
        folders.iter().any(|item| item["name"] == folder),
        "email.folders did not include expected folder {folder}: {}",
        output
    );
    Ok(())
}

fn message_uid_by_subject(output: &Value, subject: &str) -> Option<u64> {
    output["messages"]
        .as_array()?
        .iter()
        .find(|message| message["subject"] == subject)
        .and_then(|message| message["uid"].as_u64())
}

async fn ensure_failed_auth_redacts(config: &EmailConfig) -> Result<()> {
    let mut bad = config.clone();
    bad.password = format!("{}-wrong-secret", config.password);
    match invoke(&bad, "folders", json!({}), None).await {
        Ok(result) => bail!(
            "expected email.folders auth failure, got output: {}",
            result.output
        ),
        Err(error) => {
            let text = serde_json::to_string(&error)?;
            for sample in [
                bad.password.as_str(),
                bad.email.as_str(),
                bad.receive.host.as_str(),
                bad.smtp.host.as_str(),
            ] {
                ensure!(
                    !text.contains(sample),
                    "target error exposed Email auth or host material: {text}"
                );
            }
            ensure!(
                matches!(
                    error.redaction,
                    RedactionStatus::Applied | RedactionStatus::NotRequired
                ),
                "target error should report a non-failed redaction state: {:?}",
                error.redaction
            );
        }
    }
    Ok(())
}
