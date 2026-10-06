#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RUN_ID=""
ROOT="${REPO_ROOT}/target/fixtures"
REPORT_PATH="${REPO_ROOT}/target/tmp/email-fixture-smoke-evidence.md"
IMAGE="greenmail/standalone:2.1.9"
TIMEOUT=90
TAIL_LINES=80
PULL=0

usage() {
  cat <<'EOF'
Usage: scripts/email-fixture-smoke.sh [options]

Starts a disposable local Email fixture, seeds messages through local SMTP,
exercises Email plugin capabilities, writes redacted evidence, and tears the
fixture down.

Options:
  --run-id <id>         Stable run id. Generated when omitted.
  --root <dir>          Fixture state root. Default: target/fixtures.
  --report <path>       Evidence report path. Default: target/tmp/email-fixture-smoke-evidence.md.
  --image <image>       Docker image for the fixture. Default: greenmail/standalone:2.1.9.
  --timeout <seconds>   Health wait timeout. Default: 90.
  --tail <lines>        Log lines to keep. Default: 80.
  --pull                Pull the fixture image when it is missing.
  -h, --help            Show this help.

The script prints resource names and variable names only. It does not print
mailbox credentials, message bodies, or fixture connection values.
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

generate_run_id() {
  printf 'email-cap-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

sanitize_id() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid id: ${value}"
}

fixture_dir() {
  printf '%s/%s\n' "${ROOT}" "${RUN_ID}"
}

env_path() {
  printf '%s/email.env\n' "$(fixture_dir)"
}

log_path() {
  printf '%s/email.log\n' "$(fixture_dir)"
}

container_name() {
  printf 'voidb-fixture-email-%s-main\n' "${RUN_ID}"
}

network_name() {
  printf 'voidb-fixture-email-%s\n' "${RUN_ID}"
}

cleanup_fixture() {
  "${SCRIPT_DIR}/local-fixture-smoke.sh" teardown \
    --fixture email \
    --run-id "${RUN_ID}" \
    --root "${ROOT}" >/dev/null 2>&1 || true
}

write_evidence() {
  local status="$1"
  local cleanup_status="$2"
  local smoke_log="$3"
  local commit
  commit="$(/usr/bin/git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"
  local docker_version
  docker_version="$(docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>/dev/null || echo "unknown")"

  mkdir -p "$(dirname "${REPORT_PATH}")"
  cat > "${REPORT_PATH}" <<EOF
# Email Fixture Capability Smoke Evidence

- Requirement: 4efde4aa-cabc-4ca1-bbf9-d85650f0a9d8 - Promote Email to a safe, complete Agent workflow
- Fixture: email
- Run id: ${RUN_ID}
- Commit: ${commit}
- Status: ${status}
- Platform: $(uname -s)-$(uname -m)
- Docker: ${docker_version}
- Image: ${IMAGE}
- Container: $(container_name)
- Network: $(network_name)
- Health: smtp and imap ports accepted local TCP connections
- Capabilities exercised: email.diagnostics, email.folders, email.list, email.search, email.fetch, email.draft, email.send, email.move, email.delete, email.set_flags, email.attachments, email.download_attachment, email.idle
- Fixture seed: local SMTP seeded two disposable messages through the Email service layer
- Mutation policy: unacknowledged send denied; previews are side-effect free; stable UIDVALIDITY/UID mutations report partial failures; attachment traversal denied; retry reuses a bounded idempotent outcome
- Live-session policy: IMAP IDLE emits content-free mailbox events with scoped cursors; blocked reads are cancellable and close cleanup is bounded
- Diagnostics policy: guarded send/delete reported available; unsupported IMAP ID response tolerated; failed auth diagnostics checked for redacted mailbox credentials and hosts
- Variables present by name: VOIDB_FIXTURE_RUN_ID, VOIDB_FIXTURE_NAME, VOIDB_FIXTURE_CONTAINER, VOIDB_FIXTURE_NETWORK, VOIDB_FIXTURE_IMAGE, VOIDB_FIXTURE_HOST, VOIDB_FIXTURE_PORT, VOIDB_EMAIL_SMOKE_CONNECTION, VOIDB_EMAIL_SMOKE_FOLDER, VOIDB_EMAIL_SMOKE_PROTOCOL, VOIDB_EMAIL_SMOKE_SECURITY, VOIDB_EMAIL_SMOKE_EMAIL, VOIDB_EMAIL_SMOKE_PASSWORD, VOIDB_EMAIL_SMOKE_IMAP_HOST, VOIDB_EMAIL_SMOKE_IMAP_PORT, VOIDB_EMAIL_SMOKE_POP3_HOST, VOIDB_EMAIL_SMOKE_POP3_PORT, VOIDB_EMAIL_SMOKE_SMTP_CONNECTION, VOIDB_EMAIL_SMOKE_SMTP_HOST, VOIDB_EMAIL_SMOKE_SMTP_PORT, VOIDB_EMAIL_SMOKE_SEND_TO, VOIDB_EMAIL_SMOKE_API_HOST, VOIDB_EMAIL_SMOKE_API_PORT
- Log capture: $(log_path)
- Capability log: ${smoke_log}
- Redaction: applied
- Cleanup: ${cleanup_status}
- Release decision: guarded mutation, transfer, and live-session fixture smoke passed
EOF

  echo "report: ${REPORT_PATH}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ $# -ge 2 ]] || die "missing value for --run-id"
      RUN_ID="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || die "missing value for --root"
      ROOT="$2"
      shift 2
      ;;
    --report)
      [[ $# -ge 2 ]] || die "missing value for --report"
      REPORT_PATH="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || die "missing value for --image"
      IMAGE="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "missing value for --timeout"
      TIMEOUT="$2"
      [[ "${TIMEOUT}" =~ ^[0-9]+$ ]] || die "timeout must be numeric"
      shift 2
      ;;
    --tail)
      [[ $# -ge 2 ]] || die "missing value for --tail"
      TAIL_LINES="$2"
      [[ "${TAIL_LINES}" =~ ^[0-9]+$ ]] || die "tail must be numeric"
      shift 2
      ;;
    --pull)
      PULL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(generate_run_id)"
fi
sanitize_id "${RUN_ID}"

START_ARGS=(
  --fixture email
  --run-id "${RUN_ID}"
  --root "${ROOT}"
  --image "${IMAGE}"
  --timeout "${TIMEOUT}"
  --tail "${TAIL_LINES}"
)
if [[ "${PULL}" -eq 1 ]]; then
  START_ARGS+=(--pull)
fi

mkdir -p "$(fixture_dir)"
cleanup_status="not_run"
smoke_log="$(fixture_dir)/email-capability-smoke.log"
trap 'cleanup_fixture' EXIT INT TERM ERR

"${SCRIPT_DIR}/local-fixture-smoke.sh" start "${START_ARGS[@]}"
"${SCRIPT_DIR}/local-fixture-smoke.sh" wait "${START_ARGS[@]}"

set -a
# shellcheck disable=SC1090
source "$(env_path)"
set +a

(
  cd "${REPO_ROOT}"
  cargo run -p voidb-plugin-email --example fixture_smoke --quiet
) > "${smoke_log}" 2>&1

"${SCRIPT_DIR}/local-fixture-smoke.sh" logs "${START_ARGS[@]}"
cleanup_fixture
cleanup_status="removed container, network, and generated env file"
trap - EXIT INT TERM ERR

write_evidence "passed" "${cleanup_status}" "${smoke_log}"
