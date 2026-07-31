#!/usr/bin/env bash
set -Eeuo pipefail

# First-install bootstrap for a clean Ubuntu host.
#
# The installer is resumable.  It keeps verified work under one deployment
# root in the deployment user's home directory and records the last failed
# stage.  The formal "current" entry point is created only after every
# preflight has passed, so an interrupted first install is never mistaken for
# an installed application.

umask 027

REPO_URL="${REPO_URL:-https://github.com/timberlanm/agent-analysis.git}"
BRANCH="${BRANCH:-master}"
SERVICE_NAME="${SERVICE_NAME:-soc-workbench}"
DEPLOY_USER="${DEPLOY_USER:-${SUDO_USER:-}}"
SERVICE_USER="${SERVICE_USER:-socworkbench}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:5000/health}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SOURCE="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
REQUESTED_SOURCE_MODE="${SOURCE_MODE:-}"
REQUESTED_OFFLINE_MODE="${OFFLINE_MODE:-}"
REQUESTED_LOCAL_SOURCE_DIR="${LOCAL_SOURCE_DIR:-}"
REQUESTED_WHEELHOUSE="${WHEELHOUSE:-}"
REQUESTED_OFFLINE_DEB_DIR="${OFFLINE_DEB_DIR:-}"
SOURCE_MODE="${REQUESTED_SOURCE_MODE:-local}"
OFFLINE_MODE="${REQUESTED_OFFLINE_MODE:-0}"
LOCAL_SOURCE_DIR="${LOCAL_SOURCE_DIR:-$BOOTSTRAP_SOURCE}"
WHEELHOUSE="${WHEELHOUSE:-$BOOTSTRAP_SOURCE/deploy/offline/wheels}"
OFFLINE_DEB_DIR="${OFFLINE_DEB_DIR:-$BOOTSTRAP_SOURCE/deploy/offline/debs}"

CURRENT_STEP=0
CURRENT_STEP_NAME="startup"
LAST_COMPLETED_STEP=0
TARGET_COMMIT=""
SOURCE_KIND=""
SOURCE_REFERENCE=""
FAILURE_REASON=""
FAILED_COMMAND=""
FAILED_LINE=""
SERVICE_START_ATTEMPTED=0
BOOTSTRAP_SUCCEEDED=0
LOGGING_READY=0

log() {
    printf '\n==> %s\n' "$*"
}

fail() {
    FAILURE_REASON="$*"
    printf 'bootstrap=failed: %s\n' "$*" >&2
    return 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        printf 'bootstrap=failed: run with sudo bash deploy/linux/bootstrap.sh\n' >&2
        exit 1
    fi
}

require_ubuntu_2204() {
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] ||
        fail "Ubuntu 22.04 is required"
}

run_as_deploy() {
    sudo -H -u "$DEPLOY_USER" -- "$@"
}

json_field() {
    local field="$1"
    [[ -f "$STATE_FILE" ]] || return 0
    python3 - "$STATE_FILE" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1:3]
try:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle).get(field, "")
except (OSError, ValueError):
    value = ""
if value is None:
    value = ""
print(value)
PY
}

write_state() {
    local status="$1"
    local failed_step="${2:-}"
    local error_message="${3:-}"
    local failed_command="${4:-}"
    local temporary="${STATE_FILE}.tmp"

    STATE_STATUS="$status" \
    STATE_TARGET_COMMIT="$TARGET_COMMIT" \
    STATE_SOURCE_MODE="$SOURCE_MODE" \
    STATE_SOURCE_KIND="$SOURCE_KIND" \
    STATE_SOURCE_REFERENCE="$SOURCE_REFERENCE" \
    STATE_OFFLINE_MODE="$OFFLINE_MODE" \
    STATE_LOCAL_SOURCE_DIR="$LOCAL_SOURCE_DIR" \
    STATE_WHEELHOUSE="$WHEELHOUSE" \
    STATE_OFFLINE_DEB_DIR="$OFFLINE_DEB_DIR" \
    STATE_LAST_COMPLETED="$LAST_COMPLETED_STEP" \
    STATE_CURRENT_STEP="$CURRENT_STEP" \
    STATE_CURRENT_STEP_NAME="$CURRENT_STEP_NAME" \
    STATE_FAILED_STEP="$failed_step" \
    STATE_ERROR="$error_message" \
    STATE_FAILED_COMMAND="$failed_command" \
    STATE_UPDATED_AT="$(date --iso-8601=seconds)" \
        python3 - "$temporary" <<'PY'
import json
import os
import sys

destination = sys.argv[1]
payload = {
    "status": os.environ["STATE_STATUS"],
    "target_commit": os.environ["STATE_TARGET_COMMIT"],
    "source_mode": os.environ["STATE_SOURCE_MODE"],
    "source_kind": os.environ["STATE_SOURCE_KIND"],
    "source_reference": os.environ["STATE_SOURCE_REFERENCE"],
    "offline_mode": os.environ["STATE_OFFLINE_MODE"],
    "local_source_dir": os.environ["STATE_LOCAL_SOURCE_DIR"],
    "wheelhouse": os.environ["STATE_WHEELHOUSE"],
    "offline_deb_dir": os.environ["STATE_OFFLINE_DEB_DIR"],
    "last_completed_step": int(os.environ["STATE_LAST_COMPLETED"] or 0),
    "current_step": int(os.environ["STATE_CURRENT_STEP"] or 0),
    "current_step_name": os.environ["STATE_CURRENT_STEP_NAME"],
    "failed_step": os.environ["STATE_FAILED_STEP"],
    "error": os.environ["STATE_ERROR"],
    "failed_command": os.environ["STATE_FAILED_COMMAND"],
    "updated_at": os.environ["STATE_UPDATED_AT"],
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
PY
    chmod 0640 "$temporary"
    mv -f -- "$temporary" "$STATE_FILE"
}

begin_step() {
    CURRENT_STEP="$1"
    CURRENT_STEP_NAME="$2"
    write_state "running"
    log "Step $CURRENT_STEP: $CURRENT_STEP_NAME"
}

complete_step() {
    LAST_COMPLETED_STEP="$CURRENT_STEP"
    write_state "running"
}

on_error() {
    local exit_code=$?
    FAILED_LINE="$1"
    if [[ -z "$FAILED_COMMAND" ]]; then
        FAILED_COMMAND="$BASH_COMMAND"
    fi
    return "$exit_code"
}

stop_failed_service() {
    if [[ $SERVICE_START_ATTEMPTED -eq 1 ]]; then
        {
            printf 'service_status:\n'
            systemctl status "$SERVICE_NAME" --no-pager -l || true
            printf '\nservice_journal:\n'
            journalctl -u "$SERVICE_NAME" -n 150 --no-pager -o short-precise || true
        } >>"$LAST_FAILURE_LOG" 2>&1
    fi

    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true

    if [[ -L "$CURRENT_LINK" ]]; then
        local active_target
        active_target="$(readlink -f -- "$CURRENT_LINK" || true)"
        if [[ -n "$RELEASE_DIR" && "$active_target" == "$RELEASE_DIR" ]]; then
            rm -f -- "$CURRENT_LINK"
        fi
    fi
}

on_exit() {
    local exit_code=$?
    trap - ERR EXIT

    if [[ $exit_code -eq 0 && $BOOTSTRAP_SUCCEEDED -eq 1 ]]; then
        return
    fi

    local reason="$FAILURE_REASON"
    if [[ -z "$reason" ]]; then
        reason="command failed at line ${FAILED_LINE:-unknown}"
    fi

    local safe_command="$FAILED_COMMAND"
    if [[ "$safe_command" == *PASSWORD* || "$safe_command" == *DATABASE_URL* ]]; then
        safe_command="[redacted]"
    fi

    if [[ $LOGGING_READY -eq 1 ]]; then
        {
            printf 'failed_at=%s\n' "$(date --iso-8601=seconds)"
            printf 'step=%s\n' "$CURRENT_STEP"
            printf 'step_name=%s\n' "$CURRENT_STEP_NAME"
            printf 'exit_code=%s\n' "$exit_code"
            printf 'reason=%s\n' "$reason"
            printf 'command=%s\n' "$safe_command"
        } >"$LAST_FAILURE_LOG"

        write_state \
            "failed" \
            "$CURRENT_STEP" \
            "$reason" \
            "$safe_command" || true
        stop_failed_service
        printf '\nbootstrap=failed\nstate=%s\nlog=%s\n' \
            "$STATE_FILE" "$LAST_FAILURE_LOG" >&2
        printf 'Rerun the same bootstrap command after correcting the error.\n' >&2
    fi

    exit "$exit_code"
}

safe_remove_release() {
    local target="$1"
    case "$target" in
        "$RELEASES_DIR"/*)
            rm -rf -- "$target"
            ;;
        *)
            fail "Refusing to remove unmanaged path: $target"
            ;;
    esac
}

normalize_boolean() {
    case "${1,,}" in
        1 | true | yes | on)
            printf '1\n'
            ;;
        0 | false | no | off | "")
            printf '0\n'
            ;;
        *)
            fail "Invalid boolean value: $1"
            ;;
    esac
}

validate_source_mode() {
    case "$SOURCE_MODE" in
        local | github)
            ;;
        *)
            fail "SOURCE_MODE must be local or github"
            ;;
    esac
    if [[ "$OFFLINE_MODE" == "1" && "$SOURCE_MODE" != "local" ]]; then
        fail "OFFLINE_MODE requires SOURCE_MODE=local"
    fi
}

validate_local_source() {
    local source_dir="$1"
    [[ -d "$source_dir" ]] ||
        fail "Local source directory does not exist: $source_dir"
    [[ -f "$source_dir/backend/requirements.txt" ]] ||
        fail "Local source is missing backend/requirements.txt"
    [[ -f "$source_dir/backend/requirements-linux.txt" ]] ||
        fail "Local source is missing backend/requirements-linux.txt"
    [[ -f "$source_dir/backend/requirements-dev.txt" ]] ||
        fail "Local source is missing backend/requirements-dev.txt"
    [[ -f "$source_dir/backend/data/analysis_store.db" ]] ||
        fail "Local source is missing backend/data/analysis_store.db"
    [[ -f "$source_dir/frontend/dist/index.html" ]] ||
        fail "Local source is missing frontend/dist/index.html"
    [[ -f "$source_dir/scripts/bootstrap_postgres.py" ]] ||
        fail "Local source is missing scripts/bootstrap_postgres.py"
    [[ -f "$source_dir/deploy/linux/soc-workbench.service" ]] ||
        fail "Local source is missing deploy/linux/soc-workbench.service"
}

local_source_digest() {
    local source_dir="$1"
    (
        cd "$source_dir"
        find . -type f \
            ! -path './.git/*' \
            ! -path './.pytest_cache/*' \
            ! -path './.test-tmp/*' \
            ! -path './backend/__pycache__/*' \
            ! -path './deploy/offline/*' \
            ! -path './frontend/node_modules/*' \
            ! -path './venv/*' \
            ! -name '.bootstrap-source-version' \
            ! -name '*.pyc' \
            ! -name '.env' \
            ! -name '.env.*' \
            -print0 |
            sort -z |
            xargs -0 sha256sum
    ) | sha256sum | awk '{print $1}'
}

require_offline_wheelhouse() {
    [[ "$OFFLINE_MODE" == "1" ]] || return 0
    [[ -d "$WHEELHOUSE" ]] ||
        fail "Offline Python wheelhouse does not exist: $WHEELHOUSE"
    shopt -s nullglob
    local packages=(
        "$WHEELHOUSE"/*.whl
        "$WHEELHOUSE"/*.tar.gz
        "$WHEELHOUSE"/*.zip
    )
    shopt -u nullglob
    [[ ${#packages[@]} -gt 0 ]] ||
        fail "Offline Python wheelhouse is empty: $WHEELHOUSE"
}

require_root
require_ubuntu_2204

[[ -n "$DEPLOY_USER" && "$DEPLOY_USER" != "root" ]] ||
    fail "Run through sudo from the deployment login user, or set DEPLOY_USER explicitly"
id "$DEPLOY_USER" >/dev/null 2>&1 ||
    fail "Deployment user does not exist: $DEPLOY_USER"

DEPLOY_HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
[[ -n "$DEPLOY_HOME" && "$DEPLOY_HOME" == /* ]] ||
    fail "Cannot resolve home directory for $DEPLOY_USER"

INSTALL_ROOT="${INSTALL_ROOT:-$DEPLOY_HOME/soc-workbench}"
[[ "$INSTALL_ROOT" == "$DEPLOY_HOME/"* ]] ||
    fail "INSTALL_ROOT must remain inside $DEPLOY_HOME"
[[ "$INSTALL_ROOT" != *['&|']* ]] ||
    fail "INSTALL_ROOT contains unsupported characters"

RELEASES_DIR="$INSTALL_ROOT/releases"
CURRENT_LINK="$INSTALL_ROOT/current"
CONFIG_DIR="$INSTALL_ROOT/config"
RUNTIME_DIR="$INSTALL_ROOT/runtime"
INSTALLER_DIR="$INSTALL_ROOT/installer"
BACKUP_DIR="$INSTALL_ROOT/backups"
STATE_FILE="$INSTALLER_DIR/state.json"
BOOTSTRAP_LOG="$INSTALLER_DIR/bootstrap.log"
LAST_FAILURE_LOG="$INSTALLER_DIR/bootstrap-last-failure.log"
SERVICE_ENV="$CONFIG_DIR/soc-workbench.env"
MIGRATION_ENV="$CONFIG_DIR/soc-workbench.migration.env"
RELEASE_DIR=""

install -d -o root -g root -m 0750 "$INSTALLER_DIR"
touch "$BOOTSTRAP_LOG"
chmod 0640 "$BOOTSTRAP_LOG"
exec > >(tee -a "$BOOTSTRAP_LOG") 2>&1
LOGGING_READY=1

exec 9>"/run/lock/${SERVICE_NAME}-deploy.lock"
flock -n 9 || fail "Another SOC workbench bootstrap or update is running"

PREVIOUS_STATUS="$(json_field status)"
PREVIOUS_STEP="$(json_field failed_step)"
TARGET_COMMIT="$(json_field target_commit)"
PREVIOUS_SOURCE_MODE="$(json_field source_mode)"
PREVIOUS_SOURCE_KIND="$(json_field source_kind)"
PREVIOUS_SOURCE_REFERENCE="$(json_field source_reference)"
PREVIOUS_OFFLINE_MODE="$(json_field offline_mode)"
PREVIOUS_LOCAL_SOURCE_DIR="$(json_field local_source_dir)"
PREVIOUS_WHEELHOUSE="$(json_field wheelhouse)"
PREVIOUS_OFFLINE_DEB_DIR="$(json_field offline_deb_dir)"

if [[ -n "$PREVIOUS_SOURCE_MODE" ]]; then
    if [[ -n "$REQUESTED_SOURCE_MODE" && "$REQUESTED_SOURCE_MODE" != "$PREVIOUS_SOURCE_MODE" ]]; then
        fail "Cannot change SOURCE_MODE while resuming an installation"
    fi
    SOURCE_MODE="$PREVIOUS_SOURCE_MODE"
fi
if [[ -n "$PREVIOUS_OFFLINE_MODE" ]]; then
    if [[ -n "$REQUESTED_OFFLINE_MODE" ]] &&
        [[ "$(normalize_boolean "$REQUESTED_OFFLINE_MODE")" != "$PREVIOUS_OFFLINE_MODE" ]]; then
        fail "Cannot change OFFLINE_MODE while resuming an installation"
    fi
    OFFLINE_MODE="$PREVIOUS_OFFLINE_MODE"
else
    OFFLINE_MODE="$(normalize_boolean "$OFFLINE_MODE")"
fi
SOURCE_KIND="$PREVIOUS_SOURCE_KIND"
SOURCE_REFERENCE="$PREVIOUS_SOURCE_REFERENCE"
LOCAL_SOURCE_DIR="$(readlink -m -- "$LOCAL_SOURCE_DIR")"
WHEELHOUSE="$(readlink -m -- "$WHEELHOUSE")"
OFFLINE_DEB_DIR="$(readlink -m -- "$OFFLINE_DEB_DIR")"
if [[ "$SOURCE_MODE" == "local" && -n "$PREVIOUS_LOCAL_SOURCE_DIR" ]]; then
    if [[ -n "$REQUESTED_LOCAL_SOURCE_DIR" ]] &&
        [[ "$LOCAL_SOURCE_DIR" != "$PREVIOUS_LOCAL_SOURCE_DIR" ]]; then
        fail "Cannot change LOCAL_SOURCE_DIR while resuming an installation"
    fi
    LOCAL_SOURCE_DIR="$PREVIOUS_LOCAL_SOURCE_DIR"
elif [[ -z "$REQUESTED_LOCAL_SOURCE_DIR" && -n "$SOURCE_REFERENCE" && "$SOURCE_MODE" == "local" ]]; then
    LOCAL_SOURCE_DIR="$SOURCE_REFERENCE"
fi
if [[ -n "$PREVIOUS_WHEELHOUSE" ]]; then
    if [[ -n "$REQUESTED_WHEELHOUSE" && "$WHEELHOUSE" != "$PREVIOUS_WHEELHOUSE" ]]; then
        fail "Cannot change WHEELHOUSE while resuming an installation"
    fi
    WHEELHOUSE="$PREVIOUS_WHEELHOUSE"
fi
if [[ -n "$PREVIOUS_OFFLINE_DEB_DIR" ]]; then
    if [[ -n "$REQUESTED_OFFLINE_DEB_DIR" && "$OFFLINE_DEB_DIR" != "$PREVIOUS_OFFLINE_DEB_DIR" ]]; then
        fail "Cannot change OFFLINE_DEB_DIR while resuming an installation"
    fi
    OFFLINE_DEB_DIR="$PREVIOUS_OFFLINE_DEB_DIR"
fi
validate_source_mode

if [[ "$PREVIOUS_STATUS" == "complete" ]]; then
    printf 'bootstrap=already-complete\nstate=%s\n' "$STATE_FILE"
    printf 'Use deploy/linux/update.sh for subsequent releases.\n'
    exit 2
fi

if [[ -e /opt/soc-workbench || -L /opt/soc-workbench ]]; then
    fail "Existing /opt/soc-workbench deployment detected; bootstrap is only for a clean host"
fi

if systemctl is-active --quiet "$SERVICE_NAME" && [[ -z "$PREVIOUS_STATUS" ]]; then
    fail "Existing running service detected; bootstrap is only for a clean host"
fi
if systemctl cat "$SERVICE_NAME" >/dev/null 2>&1 && [[ -z "$PREVIOUS_STATUS" ]]; then
    fail "Existing systemd service detected; bootstrap is only for a clean host"
fi

if [[ -n "$PREVIOUS_STATUS" ]]; then
    printf 'bootstrap=resume\nprevious_status=%s\nprevious_failed_step=%s\n' \
        "$PREVIOUS_STATUS" "${PREVIOUS_STEP:-unknown}"
fi

trap 'on_error "$LINENO"' ERR
trap on_exit EXIT

begin_step 10 "Validate the clean Ubuntu host"
complete_step

begin_step 20 "Install system prerequisites and prepare the single deployment root"
if [[ "$OFFLINE_MODE" == "1" ]]; then
    log "Offline mode: verify preinstalled packages and optional local debs"
    shopt -s nullglob
    OFFLINE_DEBS=("$OFFLINE_DEB_DIR"/*.deb)
    shopt -u nullglob
    if [[ ${#OFFLINE_DEBS[@]} -gt 0 ]]; then
        apt-get -o Acquire::Retries=0 --no-download install -y \
            "${OFFLINE_DEBS[@]}"
    fi

    REQUIRED_COMMANDS=(
        curl find flock openssl psql python3 readlink rsync setfacl sha256sum
        sort systemctl tee xargs
    )
    if [[ "$SOURCE_MODE" == "github" || -d "$LOCAL_SOURCE_DIR/.git" ]]; then
        REQUIRED_COMMANDS+=(git)
    fi
    MISSING_COMMANDS=()
    for required_command in "${REQUIRED_COMMANDS[@]}"; do
        command -v "$required_command" >/dev/null 2>&1 ||
            MISSING_COMMANDS+=("$required_command")
    done
    if [[ ${#MISSING_COMMANDS[@]} -gt 0 ]]; then
        fail "Offline host is missing commands: ${MISSING_COMMANDS[*]}; provide complete debs in $OFFLINE_DEB_DIR"
    fi
    python3 -m venv --help >/dev/null 2>&1 ||
        fail "python3-venv is unavailable on the offline host"
    [[ -f /etc/ssl/certs/ca-certificates.crt ]] ||
        fail "ca-certificates is unavailable on the offline host"
else
    apt-get update
    apt-get install -y \
        acl ca-certificates curl git libgl1 libglib2.0-0 openssl \
        python3 python3-pip python3-venv rsync
fi
update-ca-certificates

if ! getent group "$SERVICE_USER" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_USER"
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd \
        --system \
        --gid "$SERVICE_USER" \
        --home-dir "$RUNTIME_DIR" \
        --shell /usr/sbin/nologin \
        "$SERVICE_USER"
fi

install -d -o "$DEPLOY_USER" -g "$SERVICE_USER" -m 0750 "$INSTALL_ROOT"
install -d -o "$DEPLOY_USER" -g "$SERVICE_USER" -m 2750 "$RELEASES_DIR"
install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 \
    "$RUNTIME_DIR" \
    "$RUNTIME_DIR/data" \
    "$RUNTIME_DIR/uploads" \
    "$RUNTIME_DIR/uploads/incident" \
    "$RUNTIME_DIR/logs"
install -d -o root -g root -m 0750 "$INSTALLER_DIR" "$BACKUP_DIR"

# Grant only directory traversal through the login user's home.  Application
# content remains protected by its own owner/group modes.
setfacl -m "u:${SERVICE_USER}:--x" "$DEPLOY_HOME"
complete_step

begin_step 30 "Create and validate local configuration"
CONFIG_CREATED=0
if [[ ! -f "$SERVICE_ENV" ]]; then
    install -o root -g "$SERVICE_USER" -m 0640 \
        "$BOOTSTRAP_SOURCE/deploy/linux/soc-workbench.env.example" \
        "$SERVICE_ENV"
    sed -i "s|__INSTALL_ROOT__|$INSTALL_ROOT|g" "$SERVICE_ENV"
    CONFIG_CREATED=1
fi
if [[ ! -f "$MIGRATION_ENV" ]]; then
    install -o root -g root -m 0600 \
        "$BOOTSTRAP_SOURCE/deploy/linux/soc-workbench.migration.env.example" \
        "$MIGRATION_ENV"
    CONFIG_CREATED=1
fi

if [[ $CONFIG_CREATED -eq 1 ]]; then
    fail "Configuration templates were created under $CONFIG_DIR; fill both passwords and rerun"
fi

grep -q '<app-password>' "$SERVICE_ENV" &&
    fail "Replace <app-password> in $SERVICE_ENV"
grep -Eq '<(app|migrator)-password>' "$MIGRATION_ENV" &&
    fail "Replace password placeholders in $MIGRATION_ENV"
grep -q '__INSTALL_ROOT__' "$SERVICE_ENV" &&
    fail "Replace __INSTALL_ROOT__ in $SERVICE_ENV"

grep -Fxq "APP_DATA_DIR=$RUNTIME_DIR/data" "$SERVICE_ENV" ||
    fail "APP_DATA_DIR must be $RUNTIME_DIR/data"
grep -Fxq "INCIDENT_UPLOAD_DIR=$RUNTIME_DIR/uploads/incident" "$SERVICE_ENV" ||
    fail "INCIDENT_UPLOAD_DIR must be $RUNTIME_DIR/uploads/incident"

sudo -u "$SERVICE_USER" test -r "$SERVICE_ENV" ||
    fail "$SERVICE_USER cannot read $SERVICE_ENV"
test -r "$MIGRATION_ENV" ||
    fail "Root cannot read $MIGRATION_ENV"
complete_step

begin_step 40 "Resolve and prepare the application release"
if [[ -z "$TARGET_COMMIT" ]]; then
    if [[ "$SOURCE_MODE" == "github" ]]; then
        SOURCE_KIND="git"
        SOURCE_REFERENCE="$REPO_URL"
        TARGET_COMMIT="$(
            run_as_deploy git ls-remote "$REPO_URL" "refs/heads/$BRANCH" |
                awk 'NR == 1 {print $1}'
        )"
        [[ "$TARGET_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] ||
            fail "Cannot resolve origin/$BRANCH from $REPO_URL"
    else
        LOCAL_SOURCE_DIR="$(readlink -f -- "$LOCAL_SOURCE_DIR")"
        validate_local_source "$LOCAL_SOURCE_DIR"
        SOURCE_REFERENCE="$LOCAL_SOURCE_DIR"
        if [[ -d "$LOCAL_SOURCE_DIR/.git" ]]; then
            SOURCE_KIND="git"
            [[ -z "$(run_as_deploy git -C "$LOCAL_SOURCE_DIR" status --porcelain)" ]] ||
                fail "Local Git source is not clean; commit the release or remove .git to install a packaged directory"
            TARGET_COMMIT="$(run_as_deploy git -C "$LOCAL_SOURCE_DIR" rev-parse HEAD)"
            [[ "$TARGET_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] ||
                fail "Cannot resolve the local Git commit"
        else
            SOURCE_KIND="directory"
            TARGET_COMMIT="local-$(local_source_digest "$LOCAL_SOURCE_DIR")"
        fi
    fi
    write_state "running"
fi

if [[ -z "$SOURCE_KIND" ]]; then
    if [[ "$TARGET_COMMIT" == local-* ]]; then
        SOURCE_KIND="directory"
    else
        SOURCE_KIND="git"
    fi
fi
if [[ -z "$SOURCE_REFERENCE" && "$SOURCE_MODE" == "local" ]]; then
    SOURCE_REFERENCE="$LOCAL_SOURCE_DIR"
fi

RELEASE_DIR="$RELEASES_DIR/$TARGET_COMMIT"
RELEASE_VALID=0
if [[ "$SOURCE_KIND" == "git" && -d "$RELEASE_DIR/.git" ]]; then
    ACTUAL_COMMIT="$(run_as_deploy git -C "$RELEASE_DIR" rev-parse HEAD)"
    if [[ "$ACTUAL_COMMIT" != "$TARGET_COMMIT" ]] ||
        [[ -n "$(run_as_deploy git -C "$RELEASE_DIR" status --porcelain)" ]]; then
        log "Discard incomplete or modified bootstrap release"
        safe_remove_release "$RELEASE_DIR"
    else
        RELEASE_VALID=1
    fi
elif [[ "$SOURCE_KIND" == "directory" ]] &&
    [[ -f "$RELEASE_DIR/.bootstrap-source-version" ]] &&
    [[ "$(<"$RELEASE_DIR/.bootstrap-source-version")" == "$TARGET_COMMIT" ]]; then
    RELEASE_VALID=1
elif [[ -e "$RELEASE_DIR" ]]; then
    log "Discard incomplete application release"
    safe_remove_release "$RELEASE_DIR"
fi

if [[ $RELEASE_VALID -eq 0 ]]; then
    if [[ "$SOURCE_MODE" == "github" ]]; then
        run_as_deploy git clone \
            --branch "$BRANCH" \
            --single-branch \
            "$REPO_URL" \
            "$RELEASE_DIR"
        run_as_deploy git -C "$RELEASE_DIR" checkout --detach "$TARGET_COMMIT"
    else
        [[ -d "$SOURCE_REFERENCE" ]] ||
            fail "Local source is unavailable and the prepared release is incomplete: $SOURCE_REFERENCE"
        validate_local_source "$SOURCE_REFERENCE"
        if [[ "$SOURCE_KIND" == "git" ]]; then
            run_as_deploy git clone \
                --no-hardlinks \
                "$SOURCE_REFERENCE" \
                "$RELEASE_DIR"
            run_as_deploy git -C "$RELEASE_DIR" checkout --detach "$TARGET_COMMIT"
        else
            install -d -o "$DEPLOY_USER" -g "$SERVICE_USER" -m 2750 "$RELEASE_DIR"
            run_as_deploy rsync -a \
                --exclude='.git/' \
                --exclude='.pytest_cache/' \
                --exclude='.test-tmp/' \
                --exclude='__pycache__/' \
                --exclude='deploy/offline/' \
                --exclude='frontend/node_modules/' \
                --exclude='venv/' \
                --exclude='.bootstrap-source-version' \
                --exclude='.env' \
                --exclude='.env.*' \
                "$SOURCE_REFERENCE/" \
                "$RELEASE_DIR/"
            printf '%s\n' "$TARGET_COMMIT" |
                run_as_deploy tee "$RELEASE_DIR/.bootstrap-source-version" >/dev/null
        fi
    fi
else
    log "Reuse verified application release $TARGET_COMMIT"
fi

[[ -f "$RELEASE_DIR/frontend/dist/index.html" ]] ||
    fail "frontend/dist/index.html is not committed"
[[ -f "$RELEASE_DIR/backend/data/analysis_store.db" ]] ||
    fail "backend/data/analysis_store.db is missing"
complete_step

begin_step 50 "Create or resume the Python virtual environment"
VENV_DIR="$RELEASE_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
PIP_SOURCE_ARGS=()
if [[ "$OFFLINE_MODE" == "1" ]]; then
    PIP_SOURCE_ARGS=(--no-index --find-links "$WHEELHOUSE")
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
    if [[ -e "$VENV_DIR" ]]; then
        rm -rf -- "$VENV_DIR"
    fi
    run_as_deploy python3 -m venv "$VENV_DIR"
fi

TOOLS_MARKER="$VENV_DIR/.bootstrap-tools-ready"
if [[ ! -f "$TOOLS_MARKER" ]]; then
    require_offline_wheelhouse
    if ! run_as_deploy "$VENV_PYTHON" -m pip install \
        "${PIP_SOURCE_ARGS[@]}" \
        --upgrade pip setuptools wheel; then
        if [[ "$OFFLINE_MODE" != "1" ]]; then
            run_as_deploy "$VENV_PYTHON" -m pip config debug || true
        fi
        fail "Python packaging tools could not be installed"
    fi
    run_as_deploy touch "$TOOLS_MARKER"
fi

REQUIREMENTS_HASH="$(
    sha256sum \
        "$RELEASE_DIR/backend/requirements.txt" \
        "$RELEASE_DIR/backend/requirements-linux.txt" \
        "$RELEASE_DIR/backend/requirements-dev.txt" |
        sha256sum |
        awk '{print $1}'
)"
REQUIREMENTS_MARKER="$VENV_DIR/.bootstrap-requirements-sha256"
INSTALLED_HASH=""
[[ -f "$REQUIREMENTS_MARKER" ]] &&
    INSTALLED_HASH="$(<"$REQUIREMENTS_MARKER")"

if [[ "$INSTALLED_HASH" != "$REQUIREMENTS_HASH" ]] ||
    ! run_as_deploy "$VENV_PYTHON" -m pip check >/dev/null 2>&1; then
    require_offline_wheelhouse
    if ! run_as_deploy "$VENV_PYTHON" -m pip install \
        "${PIP_SOURCE_ARGS[@]}" \
        -r "$RELEASE_DIR/backend/requirements-linux.txt" \
        -r "$RELEASE_DIR/backend/requirements-dev.txt"; then
        if [[ "$OFFLINE_MODE" != "1" ]]; then
            run_as_deploy "$VENV_PYTHON" -m pip config debug || true
        fi
        fail "Python requirements could not be installed"
    fi
    run_as_deploy "$VENV_PYTHON" -m pip check
    printf '%s\n' "$REQUIREMENTS_HASH" |
        run_as_deploy tee "$REQUIREMENTS_MARKER" >/dev/null
else
    log "Reuse verified Python requirements"
fi

run_as_deploy "$VENV_PYTHON" "$RELEASE_DIR/scripts/verify_test_seed.py"
complete_step

begin_step 60 "Create or resume PostgreSQL schema and seed import"
id postgres >/dev/null 2>&1 ||
    fail "PostgreSQL OS account does not exist"
systemctl is-active --quiet postgresql ||
    fail "PostgreSQL service is not active"

# The postgres OS account needs temporary traversal through /home to execute
# the project-managed Python environment with peer-authenticated admin access.
setfacl -m "u:postgres:--x" \
    "$DEPLOY_HOME" "$INSTALL_ROOT" "$RELEASES_DIR" "$RELEASE_DIR"
setfacl -R -m "u:postgres:rX" "$RELEASE_DIR"

sudo /bin/bash -c '
set -Eeuo pipefail
source "$1"
: "${SOC_APP_PASSWORD:?SOC_APP_PASSWORD is required}"
: "${SOC_MIGRATOR_PASSWORD:?SOC_MIGRATOR_PASSWORD is required}"
export ADMIN_DATABASE_URL="postgresql+psycopg:///postgres?host=/var/run/postgresql"
export SOC_DATABASE_NAME="soc_platform_dev"
sudo --preserve-env=ADMIN_DATABASE_URL,SOC_DATABASE_NAME,SOC_APP_PASSWORD,SOC_MIGRATOR_PASSWORD \
  -u postgres "$2" "$3"
' bootstrap-database \
    "$MIGRATION_ENV" \
    "$VENV_PYTHON" \
    "$RELEASE_DIR/scripts/bootstrap_postgres.py"

sudo /bin/bash -c '
set -Eeuo pipefail
set -a
source "$1"
set +a
cd "$2"
"$3" scripts/import_test_seed.py \
  --source backend/data/analysis_store.db \
  --report "$4"
' bootstrap-seed \
    "$MIGRATION_ENV" \
    "$RELEASE_DIR" \
    "$VENV_PYTHON" \
    "$RUNTIME_DIR/seed-import-report.json"

setfacl -R -x "u:postgres" "$RELEASE_DIR"
setfacl -x "u:postgres" \
    "$DEPLOY_HOME" "$INSTALL_ROOT" "$RELEASES_DIR" || true
complete_step

begin_step 70 "Synchronize and verify runtime evidence"
rsync -a --checksum \
    "$RELEASE_DIR/backend/uploads/incident/" \
    "$RUNTIME_DIR/uploads/incident/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$RUNTIME_DIR"
find "$RUNTIME_DIR" -type d -exec chmod 0750 {} +
find "$RUNTIME_DIR" -type f -exec chmod 0640 {} +

chown -R "$DEPLOY_USER:$SERVICE_USER" "$RELEASE_DIR"
find "$RELEASE_DIR" -type d -exec chmod 0750 {} +
find "$RELEASE_DIR" -type f -exec chmod 0640 {} +
find "$VENV_DIR/bin" -type f -exec chmod 0750 {} +
find "$RELEASE_DIR/deploy/linux" -type f -name '*.sh' -exec chmod 0750 {} +

sudo -u "$SERVICE_USER" /bin/bash -c '
set -Eeuo pipefail
set -a
source "$1"
set +a
cd "$2"
"$3" scripts/preflight_linux.py
' bootstrap-preflight "$SERVICE_ENV" "$RELEASE_DIR" "$VENV_PYTHON"
complete_step

begin_step 80 "Install the first systemd service definition"
RENDERED_SERVICE="$INSTALLER_DIR/${SERVICE_NAME}.service"
sed \
    -e "s|__INSTALL_ROOT__|$INSTALL_ROOT|g" \
    -e "s|__SERVICE_USER__|$SERVICE_USER|g" \
    "$RELEASE_DIR/deploy/linux/soc-workbench.service" \
    >"$RENDERED_SERVICE"
chmod 0644 "$RENDERED_SERVICE"
install -o root -g root -m 0644 \
    "$RENDERED_SERVICE" \
    "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
complete_step

begin_step 90 "Activate the first release and verify service health"
if [[ -e "$CURRENT_LINK" || -L "$CURRENT_LINK" ]]; then
    if [[ ! -L "$CURRENT_LINK" ]] ||
        [[ "$(readlink -f -- "$CURRENT_LINK")" != "$RELEASE_DIR" ]]; then
        fail "Unexpected current entry exists: $CURRENT_LINK"
    fi
else
    ln -s "$RELEASE_DIR" "$CURRENT_LINK"
fi

SERVICE_START_ATTEMPTED=1
systemctl start "$SERVICE_NAME"

HEALTH_RESPONSE="$INSTALLER_DIR/health.json"
HEALTHY=0
HEALTH_DEADLINE=$((SECONDS + 60))
while ((SECONDS < HEALTH_DEADLINE)); do
    if systemctl is-active --quiet "$SERVICE_NAME" &&
        curl --fail --silent --show-error \
            --connect-timeout 2 \
            --max-time 3 \
            "$HEALTH_URL" \
            >"$HEALTH_RESPONSE"; then
        HEALTHY=1
        break
    fi
    sleep 2
done

if [[ $HEALTHY -ne 1 ]]; then
    fail "Service did not become healthy within 60 seconds"
fi

systemctl enable "$SERVICE_NAME"
complete_step

BOOTSTRAP_SUCCEEDED=1
write_state "complete"
printf '\n'
cat "$HEALTH_RESPONSE"
printf '\nbootstrap=ok\nsource_mode=%s\noffline_mode=%s\nrelease=%s\nroot=%s\nstate=%s\n' \
    "$SOURCE_MODE" "$OFFLINE_MODE" "$TARGET_COMMIT" "$INSTALL_ROOT" "$STATE_FILE"
trap - ERR EXIT
