# VoidB Email Plugin (`voidb-plugin-email`)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Independent process plugin for [VoidB](https://github.com/limmytian/voidb) to connect, inspect, and manage email mailboxes via IMAP/POP3 and send messages via SMTP.

## Features

- **Autonomous Process Architecture**: Runs in an isolated OS process communicating with VoidB via `stdio-jsonrpc`.
- **Tri-Modal Operation**:
  - `test`: Automated connectivity verification.
  - `tui`: Standalone full-screen interactive terminal interface.
  - `serve`: `stdio-jsonrpc` protocol server for AI Agents and automated orchestration.
  - Domain commands: Mailbox folders, message listing, message inspection, and message deletion.
- **Capability Surface**:
  - `diagnostics`: Return agent-safe email profile diagnostics without opening network connections.
  - `folders`: List mailbox folders with message and unread counts.
  - `list`: List message envelopes from a folder with bounded pagination.
  - `search`: Search a bounded page of message envelopes by sender or subject.
  - `fetch`: Fetch message body without marking it read.
  - `draft`: Validate and preview a redacted message plan without contacting SMTP.
  - `send`: Send structured email messages via SMTP with dry-run preview and acknowledgement gates.
  - `move`: Move stable IMAP UIDs after UIDVALIDITY validation.
  - `delete`: Move stable IMAP UIDs to Trash or expunge them.
  - `set_flags`: Apply allowlisted flags to stable IMAP UIDs.
  - `attachments`: List bounded attachment metadata for stable message identities.
  - `download_attachment`: Download message attachments to approved destinations.
  - `idle`: Observe bounded IMAP mailbox changes.

## Usage & Operational Modes

When installed, `voidb-cli` automatically discovers this plugin and provides seamless transparent dispatch:

### 1. Human Operations (CLI & TUI)

```bash
# Connectivity test
voidb-cli email test --profile my-email

# Launch standalone interactive fullscreen TUI
voidb-cli email tui --profile my-email

# Mailbox operations
voidb-cli email folders --profile my-email
voidb-cli email list INBOX --limit 20 --profile my-email
voidb-cli email read INBOX 12345 --profile my-email
```

### 2. Machine Communication (AI Agents & JSON-RPC)

```bash
# Run the stdio-jsonrpc server directly or via voidb-cli
voidb-cli email serve
# Or directly run the binary:
./bin/voidb-plugin-email serve
```

## Quick Start

### Installation

Place this plugin directory or a packaged release archive under your VoidB plugins directory (`~/Library/Application Support/voidb/plugins/email` on macOS, or `~/.local/share/voidb/plugins/email` on Linux):

```bash
mkdir -p "$HOME/Library/Application Support/voidb/plugins/email"
cp -r plugin.toml bin schemas "$HOME/Library/Application Support/voidb/plugins/email/"
```

Verify discovery via `voidb`:

```bash
voidb-cli plugin list
voidb-cli email --help
```

### Development & Build

```bash
cargo build --release
mkdir -p bin
cp target/release/voidb-plugin-email bin/
```

## Protocol Specifications

Complies with the [VoidB Process Plugin Protocol](https://github.com/limmytian/voidb/blob/main/docs/quickstart-process-plugin.md) specification (v1.0).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
