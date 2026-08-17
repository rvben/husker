#!/usr/bin/env bash
set -euo pipefail

MODE="local"
DEPLOY_HOST="${HUSKER_DEPLOY_HOST:-}"
SERVICE="${HUSKER_DEPLOY_SERVICE:-husker}"
HEALTH_URL="${HUSKER_DEPLOY_HEALTH_URL:-http://127.0.0.1:7777/v1/health}"
INSTALL_PATH="${HUSKER_DEPLOY_INSTALL_PATH:-/usr/local/bin/husker}"
STATE_DB="${HUSKER_DEPLOY_STATE_DB:-/var/lib/husker/husker.db}"
BACKUP_ROOT="${HUSKER_DEPLOY_BACKUP_ROOT:-/var/lib/husker/deploy-backups}"
BUILD_CACHE_ROOT="${HUSKER_DEPLOY_BUILD_CACHE_ROOT:-/var/cache/husker-build}"
HEALTH_ATTEMPTS="${HUSKER_DEPLOY_HEALTH_ATTEMPTS:-30}"
AGENT_LOG_ATTEMPTS="${HUSKER_DEPLOY_AGENT_LOG_ATTEMPTS:-10}"
STABILITY_SECONDS="${HUSKER_DEPLOY_STABILITY_SECONDS:-3}"
KEEP_STAGING=0
COMMIT=""
SOURCE_DIR=""
ARTIFACT=""
LOCAL_TEMP_DIR=""

usage() {
    cat <<'EOF'
Deploy an exact committed Husker snapshot to a systemd-managed Linux host.

Usage:
  scripts/deploy-linux.sh --host USER@HOST [--keep-staging]

The deployment refuses tracked working-tree changes, archives HEAD (so untracked
files are never copied), runs target-native state and userdata tests, builds an
optimized daemon with its musl guest agent embedded, and validates that build
fact through `husker capabilities`.

Cutover is transactional: the current binary and stopped SQLite state are saved
before an atomic install. A failed start, health check, capability check, service
restart, or error-level startup log restores both snapshots automatically.

Environment overrides:
  HUSKER_DEPLOY_HOST          SSH destination (alternative to --host)
  HUSKER_DEPLOY_SERVICE       systemd unit name (default: husker)
  HUSKER_DEPLOY_HEALTH_URL    health endpoint (default: http://127.0.0.1:7777/v1/health)
  HUSKER_DEPLOY_INSTALL_PATH  daemon binary (default: /usr/local/bin/husker)
  HUSKER_DEPLOY_STATE_DB      SQLite database (default: /var/lib/husker/husker.db)
  HUSKER_DEPLOY_BACKUP_ROOT   retained rollback root (default: /var/lib/husker/deploy-backups)
  HUSKER_DEPLOY_BUILD_CACHE_ROOT
                              root-only Cargo cache (default: /var/cache/husker-build)

Internal test/build entrypoints:
  --remote-install             build and cut over a staged committed snapshot
  --remote-cutover             cut over a prebuilt artifact using the same transaction
EOF
}

log() {
    printf '[deploy] %s\n' "$*"
}

fail() {
    printf '[deploy] ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        fail "sha256sum or shasum is required"
    fi
}

cleanup_local() {
    if [[ -n "$LOCAL_TEMP_DIR" && -d "$LOCAL_TEMP_DIR" ]]; then
        rm -rf -- "$LOCAL_TEMP_DIR"
    fi
}

validate_remote_setting() {
    local label="$1"
    local value="$2"
    if [[ ! "$value" =~ ^[A-Za-z0-9_./:@-]+$ ]]; then
        fail "$label contains unsupported shell characters: $value"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            DEPLOY_HOST="${2:?--host requires USER@HOST}"
            shift 2
            ;;
        --keep-staging)
            KEEP_STAGING=1
            shift
            ;;
        --remote-install)
            MODE="remote"
            shift
            ;;
        --remote-cutover)
            MODE="cutover"
            shift
            ;;
        --commit)
            COMMIT="${2:?--commit requires a Git object ID}"
            shift 2
            ;;
        --source-dir)
            SOURCE_DIR="${2:?--source-dir requires a path}"
            shift 2
            ;;
        --artifact)
            ARTIFACT="${2:?--artifact requires a path}"
            shift 2
            ;;
        --service)
            SERVICE="${2:?--service requires a unit name}"
            shift 2
            ;;
        --health-url)
            HEALTH_URL="${2:?--health-url requires a URL}"
            shift 2
            ;;
        --install-path)
            INSTALL_PATH="${2:?--install-path requires a path}"
            shift 2
            ;;
        --state-db)
            STATE_DB="${2:?--state-db requires a path}"
            shift 2
            ;;
        --backup-root)
            BACKUP_ROOT="${2:?--backup-root requires a path}"
            shift 2
            ;;
        --build-cache-root)
            BUILD_CACHE_ROOT="${2:?--build-cache-root requires a path}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

validate_configuration() {
    validate_remote_setting "service" "$SERVICE"
    validate_remote_setting "health URL" "$HEALTH_URL"
    validate_remote_setting "install path" "$INSTALL_PATH"
    validate_remote_setting "state database" "$STATE_DB"
    validate_remote_setting "backup root" "$BACKUP_ROOT"
    validate_remote_setting "build cache root" "$BUILD_CACHE_ROOT"
    [[ "$INSTALL_PATH" == /* ]] || fail "install path must be absolute"
    [[ "$STATE_DB" == /* ]] || fail "state database must be absolute"
    [[ "$BACKUP_ROOT" == /* ]] || fail "backup root must be absolute"
    [[ "$BUILD_CACHE_ROOT" == /* ]] || fail "build cache root must be absolute"
    [[ "$HEALTH_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] ||
        fail "HUSKER_DEPLOY_HEALTH_ATTEMPTS must be a positive integer"
    [[ "$AGENT_LOG_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] ||
        fail "HUSKER_DEPLOY_AGENT_LOG_ATTEMPTS must be a positive integer"
    [[ "$STABILITY_SECONDS" =~ ^[0-9]+$ ]] ||
        fail "HUSKER_DEPLOY_STABILITY_SECONDS must be a non-negative integer"
}

cleanup_remote_staging() {
    local stage="$1"
    ssh "$DEPLOY_HOST" sudo bash -s -- "$stage" <<'REMOTE_CLEANUP'
set -eu
target="$1"
resolved="$(realpath "$target")"
test "$resolved" = "$target"
test ! -L "$target"
rm -rf -- "$target"
REMOTE_CLEANUP
}

local_deploy() {
    require_command git
    require_command ssh
    require_command scp
    validate_configuration
    [[ -n "$DEPLOY_HOST" ]] || fail "provide --host USER@HOST or HUSKER_DEPLOY_HOST"

    local repo
    repo="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "run from a Git checkout"
    cd "$repo"

    if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
        fail "tracked changes are present; commit them before deploying"
    fi

    local commit short stage archive archive_sha
    commit="$(git rev-parse --verify HEAD)"
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "HEAD did not resolve to a full commit ID"
    short="${commit:0:12}"
    stage="/tmp/husker-deploy-${short}"
    LOCAL_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/husker-deploy.XXXXXX")"
    archive="${LOCAL_TEMP_DIR}/source.tar"
    trap cleanup_local EXIT

    log "archiving exact commit $commit"
    git archive --format=tar --output="$archive" "$commit"
    archive_sha="$(sha256_file "$archive")"

    log "creating isolated staging directory on $DEPLOY_HOST"
    ssh "$DEPLOY_HOST" bash -s -- "$stage" <<'REMOTE_CREATE' ||
set -eu
stage="$1"
test ! -e "$stage"
mkdir -m 0700 "$stage"
REMOTE_CREATE
        fail "remote staging path already exists or could not be created: $stage"
    scp "$archive" "$DEPLOY_HOST:$stage/source.tar"

    ssh "$DEPLOY_HOST" bash -s -- "$stage" "$archive_sha" <<'REMOTE_PREPARE'
set -eu
stage="$1"
expected="$2"
cd "$stage"
actual="$(sha256sum source.tar | awk '{print $1}')"
if [ "$actual" != "$expected" ]; then
    echo "archive checksum mismatch: expected $expected, got $actual" >&2
    exit 1
fi
mkdir src
tar -xf source.tar -C src
REMOTE_PREPARE

    log "building, testing, and deploying on $DEPLOY_HOST"
    if ! ssh "$DEPLOY_HOST" sudo bash "$stage/src/scripts/deploy-linux.sh" \
        --remote-install --commit "$commit" --source-dir "$stage/src" \
        --service "$SERVICE" --health-url "$HEALTH_URL" \
        --install-path "$INSTALL_PATH" --state-db "$STATE_DB" \
        --backup-root "$BACKUP_ROOT" --build-cache-root "$BUILD_CACHE_ROOT"; then
        log "deployment failed; remote staging retained for diagnosis: $stage"
        return 1
    fi

    if [[ "$KEEP_STAGING" -eq 0 ]]; then
        log "removing verified remote staging directory"
        cleanup_remote_staging "$stage"
    else
        log "remote staging retained by request: $stage"
    fi

    log "deployed commit $commit to $DEPLOY_HOST"
}

artifact_has_embedded_agent() {
    local artifact="$1"
    local capabilities
    capabilities="$("$artifact" --output json capabilities)"
    grep -Eq '"embedded_agent"[[:space:]]*:[[:space:]]*true' <<<"$capabilities"
}

wait_for_health() {
    local expected_version="$1"
    local response=""
    local _attempt
    for _attempt in $(seq 1 "$HEALTH_ATTEMPTS"); do
        if response="$(curl --fail --silent --show-error "$HEALTH_URL" 2>/dev/null)" &&
            [[ "$response" == *"\"version\":\"${expected_version}\""* ]] &&
            [[ "$response" == *'"status":"ok"'* ]]; then
            printf '%s\n' "$response"
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_agent_log() {
    local pid="$1"
    local _attempt
    for _attempt in $(seq 1 "$AGENT_LOG_ATTEMPTS"); do
        if journalctl -u "$SERVICE" "_PID=$pid" --no-pager --output=cat |
            grep -Fq 'cloud-image support enabled (guest agent embedded)'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

copy_state_snapshot() {
    local destination="$1"
    local suffix current
    for suffix in "" -wal -shm; do
        current="${STATE_DB}${suffix}"
        if [[ -e "$current" ]]; then
            cp -a "$current" "$destination/husker.db${suffix}" || return 1
        fi
    done
    [[ -f "$destination/husker.db" ]]
}

ROLLBACK_ARMED=0
ROLLBACK_DIR=""
ROLLBACK_NEXT_PATH=""

rollback() {
    local status="${1:-1}"
    [[ "$status" -ne 0 ]] || status=1
    trap - ERR INT TERM
    set +e
    if [[ "$ROLLBACK_ARMED" -eq 1 ]]; then
        log "verification failed; restoring the previous binary and SQLite snapshot"
        systemctl stop "$SERVICE"
        if [[ -n "$ROLLBACK_NEXT_PATH" && -e "$ROLLBACK_NEXT_PATH" ]]; then
            rm -f -- "$ROLLBACK_NEXT_PATH"
        fi
        install -m 0755 "$ROLLBACK_DIR/husker" "$INSTALL_PATH"
        install -d -m 0700 "$ROLLBACK_DIR/failed-state"
        local suffix current saved
        for suffix in "" -wal -shm; do
            current="${STATE_DB}${suffix}"
            saved="$ROLLBACK_DIR/husker.db${suffix}"
            if [[ -e "$current" ]]; then
                mv "$current" "$ROLLBACK_DIR/failed-state/husker.db${suffix}"
            fi
            if [[ -e "$saved" ]]; then
                cp -a "$saved" "$current"
            fi
        done
        systemctl start "$SERVICE"
        local rollback_healthy=0 _attempt
        for _attempt in $(seq 1 "$HEALTH_ATTEMPTS"); do
            if curl --fail --silent --show-error "$HEALTH_URL" >/dev/null 2>&1; then
                rollback_healthy=1
                break
            fi
            sleep 1
        done
        if [[ "$rollback_healthy" -eq 1 ]]; then
            log "rollback completed and previous daemon is healthy"
        else
            log "rollback files were restored, but previous daemon health is not confirmed"
        fi
    fi
    exit "$status"
}

prepare_remote_runtime() {
    local entrypoint="$1"
    [[ "$EUID" -eq 0 ]] || fail "$entrypoint must run as root"
    [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "$entrypoint requires a full commit ID"
    validate_configuration
    export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    require_command curl
    require_command install
    require_command journalctl
    require_command mktemp
    require_command realpath
    require_command sha256sum
    require_command systemctl
}

cutover_artifact() {
    local artifact="$1"
    local short artifact_hash installed_hash version

    [[ "$artifact" == /* ]] || fail "artifact path must be absolute"
    [[ -x "$artifact" ]] || fail "deployment artifact is not executable: $artifact"
    [[ ! -L "$artifact" ]] || fail "deployment artifact must not be a symlink"
    artifact_has_embedded_agent "$artifact" ||
        fail "release artifact reports that its guest agent is not embedded"
    version="$("$artifact" --version | awk '{print $2}')"
    [[ -n "$version" ]] || fail "could not determine staged Husker version"
    artifact_hash="$(sha256_file "$artifact")"
    short="${COMMIT:0:12}"

    [[ -x "$INSTALL_PATH" ]] || fail "installed daemon not found: $INSTALL_PATH"
    [[ -f "$STATE_DB" ]] || fail "state database not found: $STATE_DB"
    systemctl is-active --quiet "$SERVICE" || fail "$SERVICE is not active before deployment"
    systemctl show "$SERVICE" -p ExecStart --value | grep -Fq "$INSTALL_PATH" ||
        fail "$SERVICE does not execute $INSTALL_PATH"
    curl --fail --silent --show-error "$HEALTH_URL" >/dev/null ||
        fail "pre-deploy health check failed: $HEALTH_URL"

    installed_hash="$(sha256_file "$INSTALL_PATH")"
    if [[ "$installed_hash" == "$artifact_hash" ]]; then
        artifact_has_embedded_agent "$INSTALL_PATH" ||
            fail "installed artifact matches by hash but lacks the embedded agent"
        log "commit $COMMIT is already installed and healthy ($artifact_hash)"
        return 0
    fi

    local backup_dir next_path manifest
    install -d -m 0700 "$BACKUP_ROOT"
    backup_dir="$(mktemp -d "${BACKUP_ROOT}/${COMMIT}.XXXXXX")"
    next_path="${INSTALL_PATH}.next-${short}"
    manifest="$backup_dir/manifest"
    chmod 0700 "$backup_dir"
    cp -a "$INSTALL_PATH" "$backup_dir/husker"

    log "stopping $SERVICE for a consistent SQLite snapshot"
    if ! systemctl stop "$SERVICE"; then
        systemctl start "$SERVICE" || true
        fail "could not stop $SERVICE"
    fi
    if systemctl is-active --quiet "$SERVICE"; then
        systemctl start "$SERVICE" || true
        fail "$SERVICE remained active after stop"
    fi
    if ! copy_state_snapshot "$backup_dir"; then
        systemctl start "$SERVICE" || true
        fail "could not snapshot stopped SQLite state"
    fi

    printf 'commit=%s\nprevious_sha256=%s\nnew_sha256=%s\nversion=%s\n' \
        "$COMMIT" "$installed_hash" "$artifact_hash" "$version" >"$manifest"
    chmod 0600 "$manifest"

    ROLLBACK_DIR="$backup_dir"
    ROLLBACK_NEXT_PATH="$next_path"
    ROLLBACK_ARMED=1
    trap 'rollback $?' ERR
    trap 'rollback 130' INT
    trap 'rollback 143' TERM

    install -m 0755 "$artifact" "$next_path"
    [[ "$(sha256_file "$next_path")" == "$artifact_hash" ]]
    artifact_has_embedded_agent "$next_path"
    mv "$next_path" "$INSTALL_PATH"
    systemctl start "$SERVICE"

    local health pid restart_count error_count
    health="$(wait_for_health "$version")"
    pid="$(systemctl show "$SERVICE" -p MainPID --value)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]]
    wait_for_agent_log "$pid"
    sleep "$STABILITY_SECONDS"
    systemctl is-active --quiet "$SERVICE"
    [[ "$(sha256_file "$INSTALL_PATH")" == "$artifact_hash" ]]
    artifact_has_embedded_agent "$INSTALL_PATH"
    health="$(wait_for_health "$version")"
    restart_count="$(systemctl show "$SERVICE" -p NRestarts --value)"
    [[ "$restart_count" == "0" ]]
    error_count="$(journalctl -u "$SERVICE" "_PID=$pid" -p err --no-pager --output=cat | wc -l)"
    [[ "$error_count" -eq 0 ]]

    ROLLBACK_ARMED=0
    ROLLBACK_NEXT_PATH=""
    trap - ERR INT TERM
    log "health=$health"
    log "installed_sha256=$artifact_hash"
    log "rollback_snapshot=$backup_dir"
    log "embedded_agent=true pid=$pid restarts=$restart_count error_logs=$error_count"
}

remote_install() {
    prepare_remote_runtime "--remote-install"
    [[ -n "$SOURCE_DIR" ]] || fail "--remote-install requires --source-dir"
    require_command cargo
    require_command diff
    require_command flock
    require_command make
    require_command rsync
    require_command stat

    local short expected_source artifact build_source
    short="${COMMIT:0:12}"
    expected_source="/tmp/husker-deploy-${short}/src"
    SOURCE_DIR="$(realpath "$SOURCE_DIR")"
    [[ "$SOURCE_DIR" == "$expected_source" ]] ||
        fail "source path does not match the commit-scoped staging directory"
    [[ ! -L "$SOURCE_DIR" ]] || fail "source staging directory must not be a symlink"
    cd "$SOURCE_DIR"

    [[ ! -L "$BUILD_CACHE_ROOT" ]] || fail "build cache root must not be a symlink"
    install -d -m 0700 "$BUILD_CACHE_ROOT"
    [[ "$(realpath "$BUILD_CACHE_ROOT")" == "$BUILD_CACHE_ROOT" ]] ||
        fail "build cache root must resolve to itself"
    [[ "$(stat -c '%u' "$BUILD_CACHE_ROOT")" == "0" ]] ||
        fail "build cache root must be owned by root"
    chmod 0700 "$BUILD_CACHE_ROOT"

    # Cargo permits parallel readers, but two deployments could otherwise race
    # while embedding or copying the same cached output. Keep compilation under
    # one root-only lock, then copy the result into this commit's private stage.
    exec 9>"$BUILD_CACHE_ROOT/deploy.lock"
    flock 9
    export CARGO_TARGET_DIR="$BUILD_CACHE_ROOT/target"

    # Keep Cargo's workspace path stable across commit-scoped deployment stages.
    # Checksums avoid touching unchanged files, so Cargo recompiles only crates
    # whose inputs actually changed. The lock makes --delete safe, and the
    # comparison proves the root-owned mirror is byte-for-byte the staged commit
    # before any committed build script executes.
    build_source="$BUILD_CACHE_ROOT/source"
    [[ ! -L "$build_source" ]] || fail "build source cache must not be a symlink"
    install -d -m 0700 "$build_source"
    [[ "$(realpath "$build_source")" == "$build_source" ]] ||
        fail "build source cache must resolve to itself"
    [[ "$(stat -c '%u' "$build_source")" == "0" ]] ||
        fail "build source cache must be owned by root"
    chmod 0700 "$build_source"
    rsync --archive --checksum --delete --no-times --omit-dir-times \
        --no-owner --no-group "$SOURCE_DIR/" "$build_source/"
    diff --brief --recursive --no-dereference "$SOURCE_DIR" "$build_source"
    cd "$build_source"

    log "running target-native state and type tests"
    cargo test -p husker-types -p husker-state --all-targets
    log "running target-native userdata orchestration tests"
    cargo test -p husker-core --test orchestration_paths userdata -- --test-threads=1
    log "building optimized deployment daemon with the guest agent embedded"
    make build-deploy-with-agent

    [[ -x "$CARGO_TARGET_DIR/deploy/husker" ]] ||
        fail "deployment build did not produce $CARGO_TARGET_DIR/deploy/husker"
    artifact="$SOURCE_DIR/husker-deploy-artifact"
    install -m 0755 "$CARGO_TARGET_DIR/deploy/husker" "$artifact"
    flock -u 9
    cutover_artifact "$artifact"
}

remote_cutover() {
    prepare_remote_runtime "--remote-cutover"
    [[ -n "$ARTIFACT" ]] || fail "--remote-cutover requires --artifact"
    cutover_artifact "$ARTIFACT"
}

case "$MODE" in
    remote) remote_install ;;
    cutover) remote_cutover ;;
    *) local_deploy ;;
esac
