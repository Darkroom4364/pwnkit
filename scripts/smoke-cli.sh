#!/usr/bin/env bash
#
# smoke-cli.sh — runtime-agnostic install-smoke for pwnkit-cli.
#
# Used by .github/workflows/ci.yml to guard against regressions in the
# subcommands that are most likely to silently break: the DB layer (history),
# the MCP stdio server, and the source-review pipeline.
#
# Call this with a single argument: the full command string that invokes
# pwnkit-cli. Examples:
#   scripts/smoke-cli.sh "node /tmp/smoke/node_modules/pwnkit-cli/pwnkit.js"
#   scripts/smoke-cli.sh "bun run /tmp/smoke/node_modules/pwnkit-cli/pwnkit.js"
#   scripts/smoke-cli.sh "docker run --rm pwnkit-ci-smoke"
#
# The script exits non-zero on the first failing subtest and prints which
# subcommand tripped.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 '<command to invoke pwnkit-cli>'" >&2
  exit 2
fi

CLI="$1"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Pick a portable "run with timeout" helper. GH Actions ubuntu runners have
# coreutils `timeout`; macOS devs running this locally usually don't (unless
# they brew installed it as `gtimeout`). Fall back to perl's SIGALRM which
# is present on every POSIX system we target.
if command -v timeout >/dev/null 2>&1; then
  timeout_cmd() { timeout "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
  timeout_cmd() { gtimeout "$@"; }
else
  timeout_cmd() {
    local secs="$1"; shift
    perl -e 'my $s=shift;$SIG{ALRM}=sub{kill "TERM",-$$;exit 124};alarm $s;exec @ARGV' "$secs" "$@"
  }
fi

say() { printf '\033[36m[smoke]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[smoke] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. --help ──────────────────────────────────────────────────────────────
# Proves the binary loads, commander is wired, and all subcommands registered.
say "--help"
$CLI --help > "$TMP/help.out" 2>&1 || fail "--help exited non-zero"
grep -q "Fully autonomous" "$TMP/help.out" || fail "--help did not contain tagline"
grep -q "scan" "$TMP/help.out" || fail "--help did not list scan subcommand"
grep -q "mcp-server" "$TMP/help.out" || fail "--help did not list mcp-server subcommand"
grep -q "review" "$TMP/help.out" || fail "--help did not list review subcommand"

# ── 2. doctor ──────────────────────────────────────────────────────────────
# Proves runtime detection boots and doesn't crash on a bare environment.
say "doctor"
$CLI doctor > "$TMP/doctor.out" 2>&1 || fail "doctor exited non-zero"
grep -q "pwnkit doctor" "$TMP/doctor.out" || fail "doctor did not produce the expected banner"

# ── 3. history (DB smoke) ──────────────────────────────────────────────────
# Proves the entire SQLite stack boots end-to-end: pwnkitDB ctor, WAL
# auto-migration, schema tables + indexes, drizzle session wiring, and
# listScans() query. This is the regression guard for the 0.7.0 → 0.7.1
# native-bindings → WASM swap and the 0.7.4 WAL header migration.
say "history (DB init)"
$CLI history --db-path "$TMP/smoke.db" > "$TMP/history.out" 2>&1 \
  || fail "history exited non-zero (DB layer broken)"
# An empty history run is fine; we're testing that it *runs*, not that it
# finds anything.

# ── 4. mcp-server stdio handshake ──────────────────────────────────────────
# Proves the MCP stdio transport boots and responds to an initialize request
# with a valid JSON-RPC 2.0 reply. Bounded by `timeout` in case the server
# hangs (we don't want this to stall CI forever).
say "mcp-server initialize"
INIT_MSG='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"pwnkit-ci-smoke","version":"0.0.0"}}}'
# `timeout 10` bounds runtime; `head -1` reads the first response line and
# closes the pipe, which SIGPIPEs the server so it exits cleanly.
printf '%s\n' "$INIT_MSG" \
  | timeout_cmd 10 $CLI mcp-server \
      --target https://example.invalid \
      --scan-id ci-smoke \
      --db-path "$TMP/mcp.db" 2> "$TMP/mcp.err" \
  | head -1 > "$TMP/mcp.out" || true
# Accept exit 0 (clean), 141 (SIGPIPE from head), or 143 (SIGTERM from timeout
# after response sent). Non-accepted: the command producing no output at all.
if ! [ -s "$TMP/mcp.out" ]; then
  echo "--- mcp-server stderr ---" >&2
  cat "$TMP/mcp.err" >&2 || true
  fail "mcp-server produced no response to initialize"
fi
grep -q '"jsonrpc":"2.0"' "$TMP/mcp.out" || fail "mcp-server response not JSON-RPC 2.0"
grep -q '"result"' "$TMP/mcp.out" || fail "mcp-server initialize returned no result"

# ── 5. review smoke (source-review pipeline bootstrap) ─────────────────────
# Creates a trivially small "repo" and runs `review` against it with a fake
# API key. We don't care if the LLM call succeeds — the smoke assertion is
# that the review subcommand bootstraps, walks the repo, and emits a report-
# shaped JSON document on stdout. Matches how the scan smoke behaves when the
# API is unreachable: 401 on the agentic loop, but an empty report still
# lands and exit code is 0.
say "review (source pipeline bootstrap)"
mkdir -p "$TMP/tinyrepo"
printf 'console.log("hello");\n' > "$TMP/tinyrepo/index.js"
ANTHROPIC_API_KEY=fake $CLI review "$TMP/tinyrepo" \
    --format json --timeout 3000 \
    > "$TMP/review.out" 2> "$TMP/review.err" \
  || fail "review exited non-zero — pipeline bootstrap broken"
# The report payload should at minimum mention the target we passed.
grep -q '"target"' "$TMP/review.out" || {
  echo "--- review stdout ---" >&2
  cat "$TMP/review.out" >&2 || true
  echo "--- review stderr ---" >&2
  cat "$TMP/review.err" >&2 || true
  fail "review did not emit a report-shaped JSON document"
}

say "all 5 subcommand smoke tests passed"
