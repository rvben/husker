#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="0000000000000000000000000000000000000001"
readonly UNIT="husker-deploy-rollback-drill-$$.service"
readonly UNIT_FILE="/run/systemd/system/${UNIT}"
DRILL_ROOT=""

log() {
    printf '[deploy-rollback-drill] %s\n' "$*"
}

fail() {
    printf '[deploy-rollback-drill] ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    systemctl stop "$UNIT" >/dev/null 2>&1
    systemctl reset-failed "$UNIT" >/dev/null 2>&1
    if [[ "$UNIT_FILE" == /run/systemd/system/husker-deploy-rollback-drill-*.service ]]; then
        rm -f -- "$UNIT_FILE"
        systemctl daemon-reload >/dev/null 2>&1
    fi
    if [[ -n "$DRILL_ROOT" && "$DRILL_ROOT" == /tmp/husker-deploy-rollback.* && -d "$DRILL_ROOT" ]]; then
        rm -rf -- "$DRILL_ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

[[ "$(uname -s)" == "Linux" ]] || fail "this drill requires Linux"
[[ "$EUID" -eq 0 ]] || fail "this drill must run as root"
for command_name in bash curl python3 sha256sum systemctl; do
    command -v "$command_name" >/dev/null 2>&1 ||
        fail "required command not found: $command_name"
done
[[ -d /run/systemd/system ]] || fail "systemd runtime unit directory is unavailable"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOY_SCRIPT="${REPO_ROOT}/scripts/deploy-linux.sh"
[[ -x "$DEPLOY_SCRIPT" ]] || fail "deployment script is not executable: $DEPLOY_SCRIPT"

DRILL_ROOT="$(mktemp -d /tmp/husker-deploy-rollback.XXXXXX)"
INSTALL_PATH="${DRILL_ROOT}/bin/husker"
ARTIFACT="${DRILL_ROOT}/candidate/husker"
STATE_DB="${DRILL_ROOT}/state/husker.db"
BACKUP_ROOT="${DRILL_ROOT}/backups"
SERVER_SCRIPT="${DRILL_ROOT}/server.py"
DEPLOY_LOG="${DRILL_ROOT}/deploy.log"
mkdir -p "$(dirname "$INSTALL_PATH")" "$(dirname "$ARTIFACT")" "$(dirname "$STATE_DB")"

PORT="$(python3 - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
HEALTH_URL="http://127.0.0.1:${PORT}/v1/health"

cat >"$SERVER_SCRIPT" <<'PY'
import http.server
import json
import os


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/v1/health":
            self.send_error(404)
            return
        body = json.dumps(
            {"status": "ok", "version": "1.0.0-drill"},
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


http.server.ThreadingHTTPServer(
    ("127.0.0.1", int(os.environ["DRILL_PORT"])), HealthHandler
).serve_forever()
PY

cat >"$INSTALL_PATH" <<'OLD_DAEMON'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
    echo "husker 1.0.0-drill"
    exit 0
fi
if [[ "${1:-}" == "--output" && "${2:-}" == "json" && "${3:-}" == "capabilities" ]]; then
    printf '{"embedded_agent":true}\n'
    exit 0
fi
exec python3 "${DRILL_SERVER:?}"
OLD_DAEMON
chmod 0755 "$INSTALL_PATH"

cat >"$ARTIFACT" <<'BAD_DAEMON'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
    echo "husker 2.0.0-drill"
    exit 0
fi
if [[ "${1:-}" == "--output" && "${2:-}" == "json" && "${3:-}" == "capabilities" ]]; then
    printf '{"embedded_agent":true}\n'
    exit 0
fi
printf 'corrupted-by-candidate\n' >"${DRILL_STATE_DB:?}"
exit 42
BAD_DAEMON
chmod 0755 "$ARTIFACT"

printf 'original-main\n' >"$STATE_DB"
printf 'original-wal\n' >"${STATE_DB}-wal"
printf 'original-shm\n' >"${STATE_DB}-shm"
ORIGINAL_BINARY_SHA="$(sha256sum "$INSTALL_PATH" | awk '{print $1}')"
ORIGINAL_MAIN_SHA="$(sha256sum "$STATE_DB" | awk '{print $1}')"
ORIGINAL_WAL_SHA="$(sha256sum "${STATE_DB}-wal" | awk '{print $1}')"
ORIGINAL_SHM_SHA="$(sha256sum "${STATE_DB}-shm" | awk '{print $1}')"
CANDIDATE_SHA="$(sha256sum "$ARTIFACT" | awk '{print $1}')"

cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Husker transactional deployment rollback drill

[Service]
Type=simple
Environment=DRILL_PORT=${PORT}
Environment=DRILL_SERVER=${SERVER_SCRIPT}
Environment=DRILL_STATE_DB=${STATE_DB}
ExecStart=${INSTALL_PATH}
Restart=no
EOF
systemctl daemon-reload
systemctl start "$UNIT"

for _attempt in $(seq 1 50); do
    if curl --fail --silent "$HEALTH_URL" >/dev/null 2>&1; then
        break
    fi
    systemctl is-active --quiet "$UNIT" || fail "disposable baseline service exited"
    sleep 0.1
done
curl --fail --silent "$HEALTH_URL" >/dev/null || fail "disposable baseline did not become healthy"

LIVE_PID_BEFORE="$(systemctl show husker.service -p MainPID --value 2>/dev/null || printf '0')"
LIVE_PID_BEFORE="${LIVE_PID_BEFORE:-0}"
log "forcing post-install health failure against disposable unit $UNIT"
if env \
    HUSKER_DEPLOY_HEALTH_ATTEMPTS=2 \
    HUSKER_DEPLOY_AGENT_LOG_ATTEMPTS=1 \
    HUSKER_DEPLOY_STABILITY_SECONDS=0 \
    bash "$DEPLOY_SCRIPT" \
        --remote-cutover \
        --commit "$COMMIT" \
        --artifact "$ARTIFACT" \
        --service "$UNIT" \
        --health-url "$HEALTH_URL" \
        --install-path "$INSTALL_PATH" \
        --state-db "$STATE_DB" \
        --backup-root "$BACKUP_ROOT" >"$DEPLOY_LOG" 2>&1; then
    fail "deliberately unhealthy candidate unexpectedly deployed"
fi
sed -n '1,160p' "$DEPLOY_LOG"

[[ "$(sha256sum "$INSTALL_PATH" | awk '{print $1}')" == "$ORIGINAL_BINARY_SHA" ]] ||
    fail "previous binary was not restored byte-for-byte"
[[ "$(sha256sum "$STATE_DB" | awk '{print $1}')" == "$ORIGINAL_MAIN_SHA" ]] ||
    fail "main database was not restored byte-for-byte"
[[ "$(sha256sum "${STATE_DB}-wal" | awk '{print $1}')" == "$ORIGINAL_WAL_SHA" ]] ||
    fail "database WAL was not restored byte-for-byte"
[[ "$(sha256sum "${STATE_DB}-shm" | awk '{print $1}')" == "$ORIGINAL_SHM_SHA" ]] ||
    fail "database SHM was not restored byte-for-byte"
systemctl is-active --quiet "$UNIT" || fail "previous disposable service is not active after rollback"
HEALTH="$(curl --fail --silent "$HEALTH_URL")"
[[ "$HEALTH" == *'"status":"ok"'* && "$HEALTH" == *'"version":"1.0.0-drill"'* ]] ||
    fail "previous disposable service is not healthy after rollback: $HEALTH"

mapfile -t BACKUP_DIRS < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#BACKUP_DIRS[@]}" -eq 1 ]] || fail "expected exactly one rollback snapshot"
ROLLBACK_DIR="${BACKUP_DIRS[0]}"
grep -Fxq "commit=${COMMIT}" "$ROLLBACK_DIR/manifest" || fail "rollback manifest commit mismatch"
grep -Fxq "previous_sha256=${ORIGINAL_BINARY_SHA}" "$ROLLBACK_DIR/manifest" ||
    fail "rollback manifest previous hash mismatch"
grep -Fxq "new_sha256=${CANDIDATE_SHA}" "$ROLLBACK_DIR/manifest" ||
    fail "rollback manifest candidate hash mismatch"
grep -Fxq "version=2.0.0-drill" "$ROLLBACK_DIR/manifest" ||
    fail "rollback manifest version mismatch"
grep -Fxq 'corrupted-by-candidate' "$ROLLBACK_DIR/failed-state/husker.db" ||
    fail "failed candidate state was not retained for diagnosis"
[[ "$(sha256sum "$ROLLBACK_DIR/failed-state/husker.db-wal" | awk '{print $1}')" == "$ORIGINAL_WAL_SHA" ]] ||
    fail "failed-state WAL evidence mismatch"
[[ "$(sha256sum "$ROLLBACK_DIR/failed-state/husker.db-shm" | awk '{print $1}')" == "$ORIGINAL_SHM_SHA" ]] ||
    fail "failed-state SHM evidence mismatch"

LIVE_PID_AFTER="$(systemctl show husker.service -p MainPID --value 2>/dev/null || printf '0')"
LIVE_PID_AFTER="${LIVE_PID_AFTER:-0}"
[[ "$LIVE_PID_AFTER" == "$LIVE_PID_BEFORE" ]] ||
    fail "live husker.service PID changed ($LIVE_PID_BEFORE -> $LIVE_PID_AFTER)"

log "rollback restored the binary and SQLite main/WAL/SHM byte-for-byte"
log "failed candidate state and a verified manifest were retained in the rollback snapshot"
log "live husker.service PID remained unchanged at $LIVE_PID_AFTER"
