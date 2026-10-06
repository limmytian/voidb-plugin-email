---
name: voidb-plugin-email
description: Guide for the VoidB Email plugin. Use when modifying crates/plugins/voidb-plugin-email, email.* capabilities, IMAP/POP3/SMTP services, Email CLI commands, standalone Email TUI, message parsing, diagnostics, or email release-readiness checks.
---

# VoidB Email Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-email`.

Inspect:

- `src/config.rs` for `EmailConfig`, protocols, server config, and security modes.
- `src/service/` for IMAP/POP3 workers, SMTP, commands, and events.
- `src/imap_client.rs` and `src/pop3_client.rs` for protocol-specific client code.
- `src/capabilities.rs` for `email.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli email ...`.
- `src/tui.rs` for standalone Email TUI behavior.
- `docs/email-tui.md` and `docs/email-release-readiness.md`.

## Boundaries

- Keep mail protocol clients and TLS details inside the plugin crate.
- Preserve redaction of usernames, passwords, server addresses where policy requires it, and message metadata in diagnostics.
- Keep destructive delete behavior policy-aware.
- Do not block TUI rendering on network reads; use service commands/events.
- Treat message body parsing and attachment handling as untrusted input.

## CLI And Capabilities

- CLI commands: `folders`, `list`, `read`, `delete`, `tui`.
- Capabilities: `email.diagnostics`, `email.folders`, `email.list`, `email.search`, `email.fetch`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-email`.
- Add `cargo test -p voidb-cli email_release_readiness_catalog` and `cargo test -p voidb-cli email_diagnostics` for readiness/diagnostics changes.
- Secret-free smoke: `scripts/release-plugin-smoke.sh --plugin email`.
- Fixture gate when feasible: `scripts/email-fixture-smoke.sh`.
- Always run `git diff --check`.
