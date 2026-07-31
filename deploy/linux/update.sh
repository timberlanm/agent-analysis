#!/usr/bin/env bash
set -Eeuo pipefail

# Update an application installed by deploy/linux/bootstrap.sh.
#
# A candidate release and its virtual environment are prepared beside the
# running release.  The current symlink is changed only after tests and the
# PostgreSQL/attachment preflight pass.  If service health fails after the
# switch, the script restores the previous symlink and systemd unit.

umask 027

REQUESTED_REPO_URL="${REPO_URL:-}"
REQUESTED_BRANCH="${BRANCH:-}"
REPO_URL="${REQUESTED_REPO_URL:-https://github.com/timberlanm/agent-analysis.git}"
BRANCH="${REQUESTED_BRANCH:-master}"
SERVICE_NAME="${SERVICE_NAME:-soc-workbench}"
DEPLOY_USER="${DEPLOY_USER:-${SUDO_USER:-}}"
REQUESTED_SERVICE_USER="${SERVICE_USER:-}"
SERVICE_USER="${SERVICE_USER:-socworkbench}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:5000/health}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
UPDATE_SOURCE="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
REQUESTED_SOURCE_MODE="${SOURCE_MODE:-}"
REQUESTED_OFFLINE_MODE="${OFFLINE_MODE:-}"
REQUESTED_LOCAL_SOURCE_DIR="${LOCAL_SOURCE_DIR:-}"
REQUESTED_WHEELHOUSE="${WHEELHOUSE:-}"
SOURCE_MODE="${REQUESTED_SOURCE_MODE:-local}"
OFFLINE_MODE="${REQUESTED_OFFLINE_MODE:-0}"
LOCAL_SOURCE_DIR="${LOCAL_SOURCE_DIR:-$UPDATE_SOURCE}"
WHEELHOUSE="${WHEELHOUSE:-$UPDATE_SOURCE/deploy/offline/wheels}"
RESET_UPDATE="${RESET_UPDATE:-0}"

CURRENT_STEP=0
CURRENT_STEP_NAME="startup"
LAST_COMPLETED_STEP=0
OLD_RELEASE=""
TARGET_RELEASE_ID=""
CANDIDATE_DIR=""
SOURCE_KIND=""
SOURCE_REFERENCE=""
FAILURE_REASON=""
FAILED_COMMAND=""
FAILED_LINE=""
ACTIVATION_STARTED=0
UPDATE_SUCCEEDED=0
LOGGING_READY=0

log() {
    printf '\n==> %s\n' "$*"
}

fail() {
    FAILURE_REASON="$*"
    printf 'update=failed: %s\n' "$*" >&2
    return 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        printf 'update=failed: run with sudo bash deploy/linux/update.sh\n' >&2
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

json_field() {
    local path="$1"
    local field="$2"
    [[ -f "$path" ]] || return 0
    python3 - "$path" "$field" <<'PY'
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

write_update_state() {
    local status="$1"
    local failed_step="${2:-}"
    local error_message="${3:-}"
    local failed_command="${4:-}"
    local temporary="${UPDATE_STATE}.tmp"

    STATE_STATUS="$status" \
    STATE_OLD_RELEASE="$OLD_RELEASE" \
    STATE_TARGET_RELEASE="$TARGET_RELEASE_ID" \
    STATE_SOURCE_MODE="$SOURCE_MODE" \
    STATE_SOURCE_KIND="$SOURCE_KIND" \
    STATE_SOURCE_REFERENCE="$SOURCE_REFERENCE" \
    STATE_OFFLINE_MODE="$OFFLINE_MODE" \
    STATE_LOCAL_SOURCE_DIR="$LOCAL_SOURCE_DIR" \
    STATE_WHEELHOUSE="$WHEELHOUSE" \
    STATE_REPO_URL="$REPO_URL" \
    STATE_BRANCH="$BRANCH" \
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
    "old_release": os.environ["STATE_OLD_RELEASE"],
    "target_release": os.environ["STATE_TARGET_RELEASE"],
    "source_mode": os.environ["STATE_SOURCE_MODE"],
    "source_kind": os.environ["STATE_SOURCE_KIND"],
    "source_reference": os.environ["STATE_SOURCE_REFERENCE"],
    "offline_mode": os.environ["STATE_OFFLINE_MODE"],
    "local_source_dir": os.environ["STATE_LOCAL_SOURCE_DIR"],
    "wheelhouse": os.environ["STATE_WHEELHOUSE"],
    "repo_url": os.environ["STATE_REPO_URL"],
    "branch": os.environ["STATE_BRANCH"],
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
    mv -f -- "$temporary" "$UPDATE_STATE"
}

begin_step() {
    CURRENT_STEP="$1"
    CURRENT_STEP_NAME="$2"
    write_update_state "running"
    log "Step $CURRENT_STEP: $CURRENT_STEP_NAME"
}

complete_step() {
    LAST_COMPLETED_STEP="$CURRENT_STEP"
    write_update_state "running"
}

on_error() {
    local exit_code=$?
    FAILED_LINE="$1"
    if [[ -z "$FAILED_COMMAND" ]]; then
        FAILED_COMMAND="$BASH_COMMAND"
    fi
    return "$exit_code"
}

switch_current() {
    local target="$1"
    local temporary_link="$INSTALL_ROOT/.current.update.$$"
    rm -f -- "$temporary_link"
    ln -s "$target" "$temporary_link"
    mv -Tf -- "$temporary_link" "$CURRENT_LINK"
}

rollback_activation() {
    [[ $ACTIVATION_STARTED -eq 1 ]] || return 0

    {
        printf '\nrollback_started_at=%s\n' "$(date --iso-8601=seconds)"
        printf 'rollback_release=%s\n' "$OLD_RELEASE"
    } >>"$LAST_FAILURE_LOG"

    switch_current "$OLD_RELEASE" >>"$LAST_FAILURE_LOG" 2>&1 || true
    if [[ -f "$SERVICE_BACKUP" ]]; then
        install -o root -g root -m 0644 \
            "$SERVICE_BACKUP" \
            "$SYSTEMD_SERVICE" >>"$LAST_FAILURE_LOG" 2>&1 || true
    fi
    systemctl daemon-reload >>"$LAST_FAILURE_LOG" 2>&1 || true
    systemctl reset-failed "$SERVICE_NAME" >>"$LAST_FAILURE_LOG" 2>&1 || true
    systemctl restart "$SERVICE_NAME" >>"$LAST_FAILURE_LOG" 2>&1 || true

    local rollback_healthy=0
    local rollback_deadline=$((SECONDS + 30))
    while ((SECONDS < rollback_deadline)); do
        if systemctl is-active --quiet "$SERVICE_NAME" &&
            curl --fail --silent --show-error \
                --connect-timeout 2 \
                --max-time 3 \
                "$HEALTH_URL" \
                >/dev/null; then
            rollback_healthy=1
            break
        fi
        sleep 2
    done
    printf 'rollback_health=%s\n' "$rollback_healthy" >>"$LAST_FAILURE_LOG"
}

on_exit() {
    local exit_code=$?
    trap - ERR EXIT

    if [[ $exit_code -eq 0 && $UPDATE_SUCCEEDED -eq 1 ]]; then
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

        rollback_activation
        write_update_state \
            "failed" \
            "$CURRENT_STEP" \
            "$reason" \
            "$safe_command" || true
        printf '\nupdate=failed\nstate=%s\nlog=%s\n' \
            "$UPDATE_STATE" "$LAST_FAILURE_LOG" >&2
        if [[ $ACTIVATION_STARTED -eq 1 ]]; then
            printf 'The previous release was restored; verify rollback_health in the failure log.\n' >&2
        else
            printf 'The running release was not changed.\n' >&2
        fi
        printf 'Correct the error and rerun update.sh to resume this candidate.\n' >&2
    fi

    exit "$exit_code"
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

validate_release_id() {
    [[ "$1" =~ ^[0-9a-fA-F]{40}$ || "$1" =~ ^local-[0-9a-f]{64}$ ]] ||
        fail "Invalid managed release identifier: $1"
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
    [[ -d "$source_dir/backend/uploads/incident" ]] ||
        fail "Local source is missing backend/uploads/incident"
    [[ -f "$source_dir/frontend/dist/index.html" ]] ||
        fail "Local source is missing frontend/dist/index.html"
    [[ -f "$source_dir/scripts/preflight_linux.py" ]] ||
        fail "Local source is missing scripts/preflight_linux.py"
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

safe_remove_candidate() {
    local target="$1"
    case "$target" in
        "$RELEASES_DIR"/*)
            [[ "$target" != "$OLD_RELEASE" ]] ||
                fail "Refusing to remove the running release"
            rm -rf -- "$target"
            ;;
        *)
            fail "Refusing to remove unmanaged path: $target"
            ;;
    esac
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
BOOTSTRAP_STATE="$INSTALLER_DIR/state.json"
UPDATE_STATE="$INSTALLER_DIR/update-state.json"
UPDATE_LOG="$INSTALLER_DIR/update.log"
LAST_FAILURE_LOG="$INSTALLER_DIR/update-last-failure.log"
HEALTH_RESPONSE="$INSTALLER_DIR/update-health.json"
SERVICE_ENV="$CONFIG_DIR/soc-workbench.env"
SYSTEMD_SERVICE="/etc/systemd/system/$SERVICE_NAME.service"
SERVICE_BACKUP="$INSTALLER_DIR/${SERVICE_NAME}.service.pre-update"
RENDERED_SERVICE="$INSTALLER_DIR/${SERVICE_NAME}.service.candidate"

[[ -d "$INSTALL_ROOT" && -d "$RELEASES_DIR" && -d "$INSTALLER_DIR" ]] ||
    fail "Home-layout installation is missing; run bootstrap.sh first"
[[ "$(json_field "$BOOTSTRAP_STATE" status)" == "complete" ]] ||
    fail "Bootstrap state is not complete: $BOOTSTRAP_STATE"
[[ -L "$CURRENT_LINK" ]] ||
    fail "Current release link is missing: $CURRENT_LINK"

OLD_RELEASE="$(readlink -f -- "$CURRENT_LINK")"
case "$OLD_RELEASE" in
    "$RELEASES_DIR"/*)
        ;;
    *)
        fail "Current release points outside the managed releases directory"
        ;;
esac

[[ -x "$OLD_RELEASE/venv/bin/python" ]] ||
    fail "Current release Python environment is missing"
[[ -f "$SERVICE_ENV" ]] ||
    fail "Runtime configuration is missing: $SERVICE_ENV"
[[ -f "$SYSTEMD_SERVICE" ]] ||
    fail "systemd service is missing: $SYSTEMD_SERVICE"

ACTUAL_SERVICE_USER="$(systemctl show "$SERVICE_NAME" -p User --value)"
[[ -n "$ACTUAL_SERVICE_USER" ]] ||
    fail "Cannot determine the systemd service user"
if [[ -n "$REQUESTED_SERVICE_USER" && "$SERVICE_USER" != "$ACTUAL_SERVICE_USER" ]]; then
    fail "SERVICE_USER does not match the installed systemd unit"
fi
SERVICE_USER="$ACTUAL_SERVICE_USER"
id "$SERVICE_USER" >/dev/null 2>&1 ||
    fail "Service user does not exist: $SERVICE_USER"

touch "$UPDATE_LOG"
chmod 0640 "$UPDATE_LOG"
exec > >(tee -a "$UPDATE_LOG") 2>&1
LOGGING_READY=1

exec 9>"/run/lock/${SERVICE_NAME}-deploy.lock"
flock -n 9 || fail "Another SOC workbench bootstrap or update is running"

PREVIOUS_STATUS="$(json_field "$UPDATE_STATE" status)"
RESET_UPDATE="$(normalize_boolean "$RESET_UPDATE")"
if [[ "$RESET_UPDATE" == "1" ]]; then
    PREVIOUS_STATUS=""
fi

if [[ "$PREVIOUS_STATUS" == "failed" || "$PREVIOUS_STATUS" == "running" ]]; then
    PREVIOUS_SOURCE_MODE="$(json_field "$UPDATE_STATE" source_mode)"
    PREVIOUS_OFFLINE_MODE="$(json_field "$UPDATE_STATE" offline_mode)"
    PREVIOUS_LOCAL_SOURCE_DIR="$(json_field "$UPDATE_STATE" local_source_dir)"
    PREVIOUS_WHEELHOUSE="$(json_field "$UPDATE_STATE" wheelhouse)"
    PREVIOUS_REPO_URL="$(json_field "$UPDATE_STATE" repo_url)"
    PREVIOUS_BRANCH="$(json_field "$UPDATE_STATE" branch)"

    if [[ -n "$REQUESTED_SOURCE_MODE" && "$REQUESTED_SOURCE_MODE" != "$PREVIOUS_SOURCE_MODE" ]]; then
        fail "Cannot change SOURCE_MODE while resuming an update"
    fi
    SOURCE_MODE="$PREVIOUS_SOURCE_MODE"
    if [[ -n "$REQUESTED_OFFLINE_MODE" ]] &&
        [[ "$(normalize_boolean "$REQUESTED_OFFLINE_MODE")" != "$PREVIOUS_OFFLINE_MODE" ]]; then
        fail "Cannot change OFFLINE_MODE while resuming an update"
    fi
    OFFLINE_MODE="$PREVIOUS_OFFLINE_MODE"

    LOCAL_SOURCE_DIR="$(readlink -m -- "$LOCAL_SOURCE_DIR")"
    WHEELHOUSE="$(readlink -m -- "$WHEELHOUSE")"
    if [[ -n "$REQUESTED_LOCAL_SOURCE_DIR" ]] &&
        [[ "$LOCAL_SOURCE_DIR" != "$PREVIOUS_LOCAL_SOURCE_DIR" ]]; then
        fail "Cannot change LOCAL_SOURCE_DIR while resuming an update"
    fi
    if [[ -n "$REQUESTED_WHEELHOUSE" && "$WHEELHOUSE" != "$PREVIOUS_WHEELHOUSE" ]]; then
        fail "Cannot change WHEELHOUSE while resuming an update"
    fi
    if [[ -n "$REQUESTED_REPO_URL" && "$REPO_URL" != "$PREVIOUS_REPO_URL" ]]; then
        fail "Cannot change REPO_URL while resuming an update"
    fi
    if [[ -n "$REQUESTED_BRANCH" && "$BRANCH" != "$PREVIOUS_BRANCH" ]]; then
        fail "Cannot change BRANCH while resuming an update"
    fi

    LOCAL_SOURCE_DIR="$PREVIOUS_LOCAL_SOURCE_DIR"
    WHEELHOUSE="$PREVIOUS_WHEELHOUSE"
    REPO_URL="$PREVIOUS_REPO_URL"
    BRANCH="$PREVIOUS_BRANCH"
    TARGET_RELEASE_ID="$(json_field "$UPDATE_STATE" target_release)"
    SOURCE_KIND="$(json_field "$UPDATE_STATE" source_kind)"
    SOURCE_REFERENCE="$(json_field "$UPDATE_STATE" source_reference)"
    printf 'update=resume\nprevious_failed_step=%s\ntarget_release=%s\n' \
        "$(json_field "$UPDATE_STATE" failed_step)" \
        "${TARGET_RELEASE_ID:-unresolved}"
else
    OFFLINE_MODE="$(normalize_boolean "$OFFLINE_MODE")"
    LOCAL_SOURCE_DIR="$(readlink -m -- "$LOCAL_SOURCE_DIR")"
    WHEELHOUSE="$(readlink -m -- "$WHEELHOUSE")"
fi
validate_source_mode

trap 'on_error "$LINENO"' ERR
trap on_exit EXIT

begin_step 10 "Validate the currently running installation"
systemctl is-active --quiet "$SERVICE_NAME" ||
    fail "Current service is not active; repair it before updating"
sudo -u "$SERVICE_USER" test -r "$SERVICE_ENV" ||
    fail "$SERVICE_USER cannot read $SERVICE_ENV"
curl --fail --silent --show-error \
    --connect-timeout 2 \
    --max-time 5 \
    "$HEALTH_URL" \
    >/dev/null ||
    fail "Current service health check failed; repair it before updating"
complete_step

begin_step 20 "Resolve the target release"
if [[ -z "$TARGET_RELEASE_ID" ]]; then
    if [[ "$SOURCE_MODE" == "github" ]]; then
        command -v git >/dev/null 2>&1 ||
            fail "git is required for SOURCE_MODE=github"
        SOURCE_KIND="git"
        SOURCE_REFERENCE="$REPO_URL"
        TARGET_RELEASE_ID="$(
            run_as_deploy git ls-remote "$REPO_URL" "refs/heads/$BRANCH" |
                awk 'NR == 1 {print $1}'
        )"
        [[ "$TARGET_RELEASE_ID" =~ ^[0-9a-fA-F]{40}$ ]] ||
            fail "Cannot resolve origin/$BRANCH from $REPO_URL"
    else
        LOCAL_SOURCE_DIR="$(readlink -f -- "$LOCAL_SOURCE_DIR")"
        validate_local_source "$LOCAL_SOURCE_DIR"
        SOURCE_REFERENCE="$LOCAL_SOURCE_DIR"
        if [[ -d "$LOCAL_SOURCE_DIR/.git" ]]; then
            command -v git >/dev/null 2>&1 ||
                fail "git is required for a local Git source"
            SOURCE_KIND="git"
            [[ -z "$(run_as_deploy git -C "$LOCAL_SOURCE_DIR" status --porcelain)" ]] ||
                fail "Local Git source is not clean; commit the release or remove .git to use a packaged directory"
            TARGET_RELEASE_ID="$(run_as_deploy git -C "$LOCAL_SOURCE_DIR" rev-parse HEAD)"
            [[ "$TARGET_RELEASE_ID" =~ ^[0-9a-fA-F]{40}$ ]] ||
                fail "Cannot resolve the local Git commit"
        else
            SOURCE_KIND="directory"
            TARGET_RELEASE_ID="local-$(local_source_digest "$LOCAL_SOURCE_DIR")"
        fi
    fi
    write_update_state "running"
fi
validate_release_id "$TARGET_RELEASE_ID"

CANDIDATE_DIR="$RELEASES_DIR/$TARGET_RELEASE_ID"
if [[ "$CANDIDATE_DIR" == "$OLD_RELEASE" ]]; then
    UPDATE_SUCCEEDED=1
    write_update_state "complete"
    printf '\nupdate=already-current\nrelease=%s\nroot=%s\n' \
        "$TARGET_RELEASE_ID" "$INSTALL_ROOT"
    trap - ERR EXIT
    exit 0
fi
complete_step

begin_step 30 "Create or reuse the candidate release"
CANDIDATE_VALID=0
if [[ "$SOURCE_KIND" == "git" && -d "$CANDIDATE_DIR/.git" ]]; then
    ACTUAL_COMMIT="$(run_as_deploy git -C "$CANDIDATE_DIR" rev-parse HEAD)"
    if [[ "$ACTUAL_COMMIT" == "$TARGET_RELEASE_ID" ]] &&
        [[ -z "$(run_as_deploy git -C "$CANDIDATE_DIR" status --porcelain)" ]]; then
        CANDIDATE_VALID=1
    else
        log "Discard incomplete or modified candidate release"
        safe_remove_candidate "$CANDIDATE_DIR"
    fi
elif [[ "$SOURCE_KIND" == "directory" ]] &&
    [[ -f "$CANDIDATE_DIR/.bootstrap-source-version" ]] &&
    [[ "$(<"$CANDIDATE_DIR/.bootstrap-source-version")" == "$TARGET_RELEASE_ID" ]]; then
    CANDIDATE_VALID=1
elif [[ -e "$CANDIDATE_DIR" ]]; then
    log "Discard incomplete candidate release"
    safe_remove_candidate "$CANDIDATE_DIR"
fi

if [[ $CANDIDATE_VALID -eq 0 ]]; then
    if [[ "$SOURCE_MODE" == "github" ]]; then
        run_as_deploy git clone \
            --branch "$BRANCH" \
            --single-branch \
            "$REPO_URL" \
            "$CANDIDATE_DIR"
        run_as_deploy git -C "$CANDIDATE_DIR" checkout --detach "$TARGET_RELEASE_ID"
    else
        [[ -d "$SOURCE_REFERENCE" ]] ||
            fail "Local source is unavailable and the candidate is incomplete: $SOURCE_REFERENCE"
        validate_local_source "$SOURCE_REFERENCE"
        if [[ "$SOURCE_KIND" == "git" ]]; then
            run_as_deploy git clone \
                --no-hardlinks \
                "$SOURCE_REFERENCE" \
                "$CANDIDATE_DIR"
            run_as_deploy git -C "$CANDIDATE_DIR" checkout --detach "$TARGET_RELEASE_ID"
        else
            install -d -o "$DEPLOY_USER" -g "$SERVICE_USER" -m 2750 "$CANDIDATE_DIR"
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
                "$CANDIDATE_DIR/"
            printf '%s\n' "$TARGET_RELEASE_ID" |
                run_as_deploy tee "$CANDIDATE_DIR/.bootstrap-source-version" >/dev/null
        fi
    fi
else
    log "Reuse verified candidate release $TARGET_RELEASE_ID"
fi

[[ -f "$CANDIDATE_DIR/frontend/dist/index.html" ]] ||
    fail "Candidate frontend/dist/index.html is missing"
[[ -f "$CANDIDATE_DIR/backend/data/analysis_store.db" ]] ||
    fail "Candidate SQLite test seed is missing"
complete_step

begin_step 40 "Build and test the candidate Python environment"
VENV_DIR="$CANDIDATE_DIR/venv"
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
        fail "Candidate Python packaging tools could not be installed"
    fi
    run_as_deploy touch "$TOOLS_MARKER"
fi

REQUIREMENTS_HASH="$(
    sha256sum \
        "$CANDIDATE_DIR/backend/requirements.txt" \
        "$CANDIDATE_DIR/backend/requirements-linux.txt" \
        "$CANDIDATE_DIR/backend/requirements-dev.txt" |
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
        -r "$CANDIDATE_DIR/backend/requirements-linux.txt" \
        -r "$CANDIDATE_DIR/backend/requirements-dev.txt"; then
        if [[ "$OFFLINE_MODE" != "1" ]]; then
            run_as_deploy "$VENV_PYTHON" -m pip config debug || true
        fi
        fail "Candidate Python requirements could not be installed"
    fi
    run_as_deploy "$VENV_PYTHON" -m pip check
    printf '%s\n' "$REQUIREMENTS_HASH" |
        run_as_deploy tee "$REQUIREMENTS_MARKER" >/dev/null
else
    log "Reuse verified candidate Python requirements"
fi

run_as_deploy "$VENV_PYTHON" "$CANDIDATE_DIR/scripts/verify_test_seed.py"
run_as_deploy "$VENV_PYTHON" -m compileall -q \
    "$CANDIDATE_DIR/backend/api" \
    "$CANDIDATE_DIR/backend/services" \
    "$CANDIDATE_DIR/backend/tests" \
    "$CANDIDATE_DIR/backend/migrations" \
    "$CANDIDATE_DIR/backend/app.py" \
    "$CANDIDATE_DIR/backend/config.py" \
    "$CANDIDATE_DIR/backend/database.py" \
    "$CANDIDATE_DIR/scripts" \
    "$CANDIDATE_DIR/wsgi.py"
run_as_deploy env APP_SKIP_LOCAL_ENV=1 \
    "$VENV_PYTHON" -m pytest \
    "$CANDIDATE_DIR/backend/tests" \
    -q \
    -p no:cacheprovider \
    --basetemp "$CANDIDATE_DIR/.test-tmp"
rm -rf -- "$CANDIDATE_DIR/.test-tmp"

chown -R "$DEPLOY_USER:$SERVICE_USER" "$CANDIDATE_DIR"
find "$CANDIDATE_DIR" -type d -exec chmod 0750 {} +
find "$CANDIDATE_DIR" -type f -exec chmod 0640 {} +
find "$VENV_DIR/bin" -type f -exec chmod 0750 {} +
find "$CANDIDATE_DIR/deploy/linux" -type f -name '*.sh' -exec chmod 0750 {} +
complete_step

begin_step 50 "Synchronize evidence and run the candidate preflight"
# Runtime uploads are shared by releases.  Content-addressed evidence is added
# without deleting or replacing files created by investigators at runtime.
rsync -a --ignore-existing \
    "$CANDIDATE_DIR/backend/uploads/incident/" \
    "$RUNTIME_DIR/uploads/incident/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$RUNTIME_DIR/uploads"
find "$RUNTIME_DIR/uploads" -type d -exec chmod 0750 {} +
find "$RUNTIME_DIR/uploads" -type f -exec chmod 0640 {} +

sudo -u "$SERVICE_USER" /bin/bash -c '
set -Eeuo pipefail
set -a
source "$1"
set +a
cd "$2"
"$3" scripts/preflight_linux.py
' update-preflight "$SERVICE_ENV" "$CANDIDATE_DIR" "$VENV_PYTHON"

sed \
    -e "s|__INSTALL_ROOT__|$INSTALL_ROOT|g" \
    -e "s|__SERVICE_USER__|$SERVICE_USER|g" \
    "$CANDIDATE_DIR/deploy/linux/soc-workbench.service" \
    >"$RENDERED_SERVICE"
chmod 0644 "$RENDERED_SERVICE"
grep -q '__INSTALL_ROOT__\|__SERVICE_USER__' "$RENDERED_SERVICE" &&
    fail "Candidate systemd template contains unresolved placeholders"
complete_step

begin_step 60 "Atomically activate the candidate and verify health"
install -o root -g root -m 0644 "$SYSTEMD_SERVICE" "$SERVICE_BACKUP"
ACTIVATION_STARTED=1
install -o root -g root -m 0644 "$RENDERED_SERVICE" "$SYSTEMD_SERVICE"
systemctl daemon-reload
switch_current "$CANDIDATE_DIR"
systemctl reset-failed "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

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
    fail "Candidate service did not become healthy within 60 seconds"
fi
complete_step

begin_step 70 "Finalize the successful update"
complete_step

write_update_state "complete"
UPDATE_SUCCEEDED=1
ACTIVATION_STARTED=0
rm -f -- "$SERVICE_BACKUP" || true
trap - ERR EXIT
printf '\n'
cat "$HEALTH_RESPONSE"
printf '\nupdate=ok\nsource_mode=%s\noffline_mode=%s\nold_release=%s\nnew_release=%s\nroot=%s\nstate=%s\n' \
    "$SOURCE_MODE" \
    "$OFFLINE_MODE" \
    "$(basename -- "$OLD_RELEASE")" \
    "$TARGET_RELEASE_ID" \
    "$INSTALL_ROOT" \
    "$UPDATE_STATE"
