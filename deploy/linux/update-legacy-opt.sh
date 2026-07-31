#!/usr/bin/env bash
set -Eeuo pipefail

# Online, forward-only updater for the existing legacy Ubuntu test environment.
#
# Expected layout:
#   /opt/soc-workbench
#   /opt/soc-workbench/venv
#   /etc/soc-workbench/soc-workbench.env
#   /var/lib/soc-workbench
#
# The running service remains online while a fixed candidate checkout is
# installed, compiled, tested and preflighted.  After activation starts there
# is deliberately no automatic rollback: a failure stops the service, records
# the exact step and preserves the target checkout for the next run to resume.
# This policy is for the current test environment only, never production.
# Database schema migrations are never automatic.

umask 027

APP_DIR="${APP_DIR:-/opt/soc-workbench}"
VENV_DIR="${VENV_DIR:-$APP_DIR/venv}"
SERVICE_ENV="${SERVICE_ENV:-/etc/soc-workbench/soc-workbench.env}"
RUNTIME_DIR="${RUNTIME_DIR:-/var/lib/soc-workbench}"
SERVICE_NAME="${SERVICE_NAME:-soc-workbench}"
REPO_URL="${REPO_URL:-https://github.com/timberlanm/agent-analysis.git}"
BRANCH="${BRANCH:-master}"
DEPLOY_USER="${DEPLOY_USER:-${SUDO_USER:-}}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:5000/health}"
START_NEW_UPDATE="${START_NEW_UPDATE:-0}"

CANDIDATE_DIR="/opt/soc-workbench-update-candidate"
STATE_DIR="${STATE_DIR:-$RUNTIME_DIR/deploy}"
STATE_FILE="$STATE_DIR/update-legacy-state.json"
UPDATE_LOG="$STATE_DIR/update-legacy.log"
FAILURE_LOG="$STATE_DIR/update-legacy-last-failure.log"
HEALTH_RESPONSE="$STATE_DIR/update-legacy-health.json"
WHEELHOUSE="$CANDIDATE_DIR/venv/.activation-wheelhouse"

CURRENT_STEP=0
CURRENT_STEP_NAME="startup"
LAST_COMPLETED_STEP=0
OLD_COMMIT=""
TARGET_COMMIT=""
SERVICE_USER=""
FAILURE_REASON=""
FAILED_COMMAND=""
FAILED_LINE=""
ACTIVATION_STARTED=0
UPDATE_SUCCEEDED=0
LOGGING_READY=0
RESUME_UPDATE=0
RECOVERY_MODE=0
PRIOR_FAILED_STEP=0

log() {
    printf '\n==> %s\n' "$*"
}

fail() {
    FAILURE_REASON="$*"
    printf 'legacy_update=failed: %s\n' "$*" >&2
    return 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        printf 'legacy_update=failed: run with sudo bash deploy/linux/update-legacy-opt.sh\n' >&2
        exit 1
    fi
}

require_ubuntu_2204() {
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] ||
        fail "Ubuntu 22.04 is required"
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

run_as_deploy() {
    sudo -H -u "$DEPLOY_USER" -- "$@"
}

json_field() {
    local path="$1"
    local field="$2"
    [[ -f "$path" ]] || return 0
    python3 - "$path" "$field" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle).get(sys.argv[2], "")
except (OSError, ValueError, TypeError):
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
    STATE_OLD_COMMIT="$OLD_COMMIT" \
    STATE_TARGET_COMMIT="$TARGET_COMMIT" \
    STATE_CURRENT_STEP="$CURRENT_STEP" \
    STATE_CURRENT_STEP_NAME="$CURRENT_STEP_NAME" \
    STATE_LAST_COMPLETED="$LAST_COMPLETED_STEP" \
    STATE_FAILED_STEP="$failed_step" \
    STATE_ERROR="$error_message" \
    STATE_FAILED_COMMAND="$failed_command" \
    STATE_ACTIVATION_STARTED="$ACTIVATION_STARTED" \
    STATE_UPDATED_AT="$(date --iso-8601=seconds)" \
        python3 - "$temporary" <<'PY'
import json
import os
import sys

destination = sys.argv[1]
payload = {
    "status": os.environ["STATE_STATUS"],
    "old_commit": os.environ["STATE_OLD_COMMIT"],
    "target_commit": os.environ["STATE_TARGET_COMMIT"],
    "current_step": int(os.environ["STATE_CURRENT_STEP"] or 0),
    "current_step_name": os.environ["STATE_CURRENT_STEP_NAME"],
    "last_completed_step": int(os.environ["STATE_LAST_COMPLETED"] or 0),
    "failed_step": os.environ["STATE_FAILED_STEP"],
    "error": os.environ["STATE_ERROR"],
    "failed_command": os.environ["STATE_FAILED_COMMAND"],
    "activation_started": os.environ["STATE_ACTIVATION_STARTED"] == "1",
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
    if ((CURRENT_STEP > LAST_COMPLETED_STEP)); then
        LAST_COMPLETED_STEP="$CURRENT_STEP"
    fi
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

wait_for_health() {
    local timeout_seconds="$1"
    local output_path="${2:-/dev/null}"
    local deadline=$((SECONDS + timeout_seconds))

    while ((SECONDS < deadline)); do
        if systemctl is-active --quiet "$SERVICE_NAME" &&
            curl --fail --silent --show-error \
                --connect-timeout 2 \
                --max-time 3 \
                "$HEALTH_URL" \
                >"$output_path"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

safe_remove_candidate() {
    [[ "$CANDIDATE_DIR" == "/opt/soc-workbench-update-candidate" ]] ||
        fail "Refusing to remove a nonstandard candidate path"
    [[ "$CANDIDATE_DIR" != "$APP_DIR" ]] ||
        fail "Candidate directory must differ from APP_DIR"
    [[ ! -e "$CANDIDATE_DIR" ]] || rm -rf -- "$CANDIDATE_DIR"
}

safe_remove_wheelhouse() {
    [[ "$WHEELHOUSE" == "$CANDIDATE_DIR/venv/.activation-wheelhouse" ]] ||
        fail "Refusing to remove a nonstandard wheelhouse path"
    [[ "$WHEELHOUSE" == "/opt/soc-workbench-update-candidate/"* ]] ||
        fail "Wheelhouse must remain inside the fixed candidate directory"
    [[ ! -e "$WHEELHOUSE" ]] || rm -rf -- "$WHEELHOUSE"
}

candidate_is_clean_target() {
    [[ -d "$CANDIDATE_DIR/.git" ]] || return 1
    [[ "$(run_as_deploy git -C "$CANDIDATE_DIR" rev-parse HEAD 2>/dev/null)" == "$TARGET_COMMIT" ]] ||
        return 1
    [[ -z "$(run_as_deploy git -c core.filemode=false -C "$CANDIDATE_DIR" status --porcelain)" ]] ||
        return 1
}

wheelhouse_is_ready() {
    [[ -d "$WHEELHOUSE" ]] || return 1
    [[ -n "$(find "$WHEELHOUSE" -maxdepth 1 -type f -print -quit)" ]]
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
            printf 'activation_started=%s\n' "$ACTIVATION_STARTED"
            printf 'old_commit=%s\n' "$OLD_COMMIT"
            printf 'target_commit=%s\n' "$TARGET_COMMIT"
        } >"$FAILURE_LOG"

        if [[ $ACTIVATION_STARTED -eq 1 ]]; then
            {
                printf '\nservice_status_before_stop:\n'
                systemctl status "$SERVICE_NAME" --no-pager -l || true
                printf '\nservice_journal:\n'
                journalctl -u "$SERVICE_NAME" -n 150 --no-pager -o short-precise || true
                printf '\nfailed_target_head=%s\n' \
                    "$(run_as_deploy git -C "$APP_DIR" rev-parse HEAD 2>/dev/null || true)"
                systemctl stop "$SERVICE_NAME" || true
            } >>"$FAILURE_LOG" 2>&1
        fi

        write_state \
            "failed" \
            "$CURRENT_STEP" \
            "$reason" \
            "$safe_command" || true

        printf '\nlegacy_update=failed\nstate=%s\nlog=%s\n' \
            "$STATE_FILE" "$FAILURE_LOG" >&2
        if [[ $ACTIVATION_STARTED -eq 1 ]]; then
            printf 'Automatic rollback is disabled for this test environment.\n' >&2
            printf 'The service was stopped and the target checkout was preserved.\n' >&2
            printf 'Correct the problem and rerun the same command to resume.\n' >&2
        elif [[ $LAST_COMPLETED_STEP -ge 60 ]]; then
            printf 'The target service passed its health check and remains online.\n' >&2
            printf 'Only final temporary-resource cleanup is incomplete; rerun the same command.\n' >&2
        else
            printf 'The running checkout and service were not changed.\n' >&2
            printf 'Correct the problem and rerun the same command to resume the candidate.\n' >&2
        fi
        printf 'After publishing a replacement commit, set START_NEW_UPDATE=1 once to select it.\n' >&2
    fi

    exit "$exit_code"
}

require_root
require_ubuntu_2204
START_NEW_UPDATE="$(normalize_boolean "$START_NEW_UPDATE")"

[[ "$APP_DIR" == "/opt/soc-workbench" ]] ||
    fail "This script only supports APP_DIR=/opt/soc-workbench"
[[ "$RUNTIME_DIR" == "/var/lib/soc-workbench" ]] ||
    fail "This script only supports RUNTIME_DIR=/var/lib/soc-workbench"
[[ "$SERVICE_ENV" == "/etc/soc-workbench/soc-workbench.env" ]] ||
    fail "This script only supports the legacy /etc runtime configuration"
[[ -n "$DEPLOY_USER" && "$DEPLOY_USER" != "root" ]] ||
    fail "Run through sudo from the deployment login user, or set DEPLOY_USER explicitly"
id "$DEPLOY_USER" >/dev/null 2>&1 ||
    fail "Deployment user does not exist: $DEPLOY_USER"

[[ -d "$APP_DIR/.git" ]] ||
    fail "$APP_DIR is not a Git checkout; this updater requires the repaired Git-based test environment"
[[ ! -L "$APP_DIR" ]] ||
    fail "$APP_DIR is already a symlink; use the Home-layout update.sh"
[[ -x "$VENV_DIR/bin/python" ]] ||
    fail "Current Python virtual environment is missing: $VENV_DIR"
[[ -f "$SERVICE_ENV" ]] ||
    fail "Runtime configuration is missing: $SERVICE_ENV"
[[ -d "$RUNTIME_DIR/uploads/incident" ]] ||
    fail "Runtime attachment directory is missing"

SERVICE_USER="$(systemctl show "$SERVICE_NAME" -p User --value)"
[[ -n "$SERVICE_USER" ]] ||
    fail "Cannot determine the installed systemd service user"
id "$SERVICE_USER" >/dev/null 2>&1 ||
    fail "Service user does not exist: $SERVICE_USER"

EXEC_START="$(systemctl show "$SERVICE_NAME" -p ExecStart --value)"
[[ "$EXEC_START" == *"$VENV_DIR/"* ]] ||
    fail "The systemd service does not use the expected legacy venv: $VENV_DIR"

install -d -o root -g root -m 0750 "$STATE_DIR"
touch "$UPDATE_LOG"
chmod 0640 "$UPDATE_LOG"
exec > >(tee -a "$UPDATE_LOG") 2>&1
LOGGING_READY=1

exec 9>"/run/lock/${SERVICE_NAME}-deploy.lock"
flock -n 9 || fail "Another SOC workbench bootstrap or update is running"

trap 'on_error "$LINENO"' ERR
trap on_exit EXIT

CURRENT_HEAD="$(run_as_deploy git -C "$APP_DIR" rev-parse HEAD)"
[[ "$CURRENT_HEAD" =~ ^[0-9a-fA-F]{40}$ ]] ||
    fail "Cannot resolve the current Git commit"
[[ -z "$(run_as_deploy git -c core.filemode=false -C "$APP_DIR" status --porcelain)" ]] ||
    fail "$APP_DIR contains local changes; publish from Windows or clean the test checkout first"

PRIOR_STATUS="$(json_field "$STATE_FILE" status)"
PRIOR_TARGET="$(json_field "$STATE_FILE" target_commit)"
PRIOR_OLD="$(json_field "$STATE_FILE" old_commit)"
PRIOR_LAST_COMPLETED="$(json_field "$STATE_FILE" last_completed_step)"
PRIOR_FAILED_STEP="$(json_field "$STATE_FILE" failed_step)"
PRIOR_ACTIVATION_STARTED="$(json_field "$STATE_FILE" activation_started)"
[[ "$PRIOR_LAST_COMPLETED" =~ ^[0-9]+$ ]] || PRIOR_LAST_COMPLETED=0
[[ "$PRIOR_FAILED_STEP" =~ ^[0-9]+$ ]] || PRIOR_FAILED_STEP=0

if [[ "$PRIOR_STATUS" =~ ^(failed|running)$ ]] &&
    [[ "$PRIOR_TARGET" =~ ^[0-9a-fA-F]{40}$ ]] &&
    [[ "$START_NEW_UPDATE" -eq 0 ]]; then
    RESUME_UPDATE=1
    TARGET_COMMIT="$PRIOR_TARGET"
    OLD_COMMIT="$PRIOR_OLD"
    LAST_COMPLETED_STEP="$PRIOR_LAST_COMPLETED"
    printf 'legacy_update=resume\ntarget_commit=%s\nprevious_failed_step=%s\n' \
        "$TARGET_COMMIT" "$PRIOR_FAILED_STEP"
elif [[ "$PRIOR_STATUS" =~ ^(failed|running)$ ]] &&
    [[ "$START_NEW_UPDATE" -eq 1 ]]; then
    RECOVERY_MODE=1
    OLD_COMMIT="$CURRENT_HEAD"
    LAST_COMPLETED_STEP=0
    safe_remove_candidate
    safe_remove_wheelhouse
    printf 'legacy_update=new-target-requested\nprevious_target=%s\n' \
        "${PRIOR_TARGET:-unknown}"
else
    OLD_COMMIT="$CURRENT_HEAD"
fi

[[ "$OLD_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] || OLD_COMMIT="$CURRENT_HEAD"

begin_step 10 "Validate the legacy test environment"
sudo -u "$SERVICE_USER" test -r "$SERVICE_ENV" ||
    fail "$SERVICE_USER cannot read $SERVICE_ENV"

if [[ $RESUME_UPDATE -eq 1 &&
    ($PRIOR_FAILED_STEP -ge 60 || "$PRIOR_ACTIVATION_STARTED" == "True" || "$PRIOR_ACTIVATION_STARTED" == "true") ]] ||
    [[ $RECOVERY_MODE -eq 1 ]]; then
    [[ "$CURRENT_HEAD" == "$TARGET_COMMIT" ||
        "$CURRENT_HEAD" == "$OLD_COMMIT" ||
        $RECOVERY_MODE -eq 1 ]] ||
        fail "The failed activation checkout changed unexpectedly: $CURRENT_HEAD"
    log "Activation recovery mode: an inactive service is allowed"
else
    systemctl is-active --quiet "$SERVICE_NAME" ||
        fail "Current service is not active; repair it or resume the failed activation state"
    curl --fail --silent --show-error \
        --connect-timeout 2 \
        --max-time 5 \
        "$HEALTH_URL" \
        >/dev/null ||
        fail "Current service health check failed"
fi
complete_step

begin_step 20 "Resolve and fetch the GitHub target"
if [[ $RESUME_UPDATE -eq 1 ]]; then
    log "Reuse the recorded immutable target $TARGET_COMMIT"
    if ! run_as_deploy git -C "$APP_DIR" cat-file -e "${TARGET_COMMIT}^{commit}" 2>/dev/null; then
        run_as_deploy git -C "$APP_DIR" fetch origin "$BRANCH"
    fi
else
    TARGET_COMMIT="$(
        run_as_deploy git ls-remote "$REPO_URL" "refs/heads/$BRANCH" |
            awk 'NR == 1 {print $1}'
    )"
    [[ "$TARGET_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] ||
        fail "Cannot resolve origin/$BRANCH from $REPO_URL"
    run_as_deploy git -C "$APP_DIR" fetch origin "$BRANCH"
fi
run_as_deploy git -C "$APP_DIR" cat-file -e "${TARGET_COMMIT}^{commit}"

if [[ "$TARGET_COMMIT" == "$CURRENT_HEAD" ]] &&
    systemctl is-active --quiet "$SERVICE_NAME" &&
    curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
        "$HEALTH_URL" >/dev/null; then
    safe_remove_candidate
    safe_remove_wheelhouse
    CURRENT_STEP=70
    CURRENT_STEP_NAME="already current"
    LAST_COMPLETED_STEP=70
    write_state "complete"
    UPDATE_SUCCEEDED=1
    printf '\nlegacy_update=already-current\ncommit=%s\n' "$CURRENT_HEAD"
    trap - ERR EXIT
    exit 0
fi
complete_step

begin_step 30 "Create or reuse the fixed candidate checkout"
if candidate_is_clean_target; then
    log "Reuse candidate commit $TARGET_COMMIT"
else
    if [[ -e "$CANDIDATE_DIR" ]]; then
        log "Discard the stale or incomplete fixed candidate directory"
        safe_remove_candidate
    fi
    safe_remove_wheelhouse
    LAST_COMPLETED_STEP=20
    install -d -o "$DEPLOY_USER" -g "$SERVICE_USER" -m 0750 "$CANDIDATE_DIR"
    run_as_deploy git clone \
        --branch "$BRANCH" \
        --single-branch \
        "$REPO_URL" \
        "$CANDIDATE_DIR"
    run_as_deploy git -C "$CANDIDATE_DIR" checkout --detach "$TARGET_COMMIT"
fi

[[ -f "$CANDIDATE_DIR/frontend/dist/index.html" ]] ||
    fail "Candidate frontend/dist/index.html is missing"
[[ -f "$CANDIDATE_DIR/backend/data/analysis_store.db" ]] ||
    fail "Candidate SQLite test seed is missing"
[[ -d "$CANDIDATE_DIR/backend/uploads/incident" ]] ||
    fail "Candidate test evidence directory is missing"
complete_step

CANDIDATE_VENV="$CANDIDATE_DIR/venv"
CANDIDATE_PYTHON="$CANDIDATE_VENV/bin/python"

if [[ $LAST_COMPLETED_STEP -ge 40 ]] &&
    [[ -x "$CANDIDATE_PYTHON" ]] &&
    wheelhouse_is_ready; then
    log "Step 40 already completed for $TARGET_COMMIT; reuse candidate dependencies and wheelhouse"
else
    begin_step 40 "Install, compile and test the candidate"
    if [[ ! -x "$CANDIDATE_PYTHON" ]]; then
        if [[ -e "$CANDIDATE_VENV" ]]; then
            rm -rf -- "$CANDIDATE_VENV"
        fi
        run_as_deploy python3 -m venv "$CANDIDATE_VENV"
    fi

    if ! run_as_deploy "$CANDIDATE_PYTHON" -m pip install \
        --upgrade pip setuptools wheel; then
        run_as_deploy "$CANDIDATE_PYTHON" -m pip config debug || true
        fail "Candidate Python packaging tools could not be installed"
    fi
    if ! run_as_deploy "$CANDIDATE_PYTHON" -m pip install \
        -r "$CANDIDATE_DIR/backend/requirements-linux.txt" \
        -r "$CANDIDATE_DIR/backend/requirements-dev.txt"; then
        run_as_deploy "$CANDIDATE_PYTHON" -m pip config debug || true
        fail "Candidate Python requirements could not be installed"
    fi
    run_as_deploy "$CANDIDATE_PYTHON" -m pip check
    run_as_deploy "$CANDIDATE_PYTHON" "$CANDIDATE_DIR/scripts/verify_test_seed.py"

    run_as_deploy "$CANDIDATE_PYTHON" -m compileall -q \
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
        "$CANDIDATE_PYTHON" -m pytest \
        "$CANDIDATE_DIR/backend/tests" \
        -q \
        -p no:cacheprovider \
        --basetemp "$CANDIDATE_DIR/.test-tmp"
    rm -rf -- "$CANDIDATE_DIR/.test-tmp"

    safe_remove_wheelhouse
    install -d -o "$DEPLOY_USER" -g "$SERVICE_USER" -m 0750 "$WHEELHOUSE"
    if ! run_as_deploy "$CANDIDATE_PYTHON" -m pip download \
        --dest "$WHEELHOUSE" \
        pip setuptools wheel \
        -r "$CANDIDATE_DIR/backend/requirements-linux.txt" \
        -r "$CANDIDATE_DIR/backend/requirements-dev.txt"; then
        run_as_deploy "$CANDIDATE_PYTHON" -m pip config debug || true
        fail "Could not prepare the offline activation wheelhouse"
    fi
    wheelhouse_is_ready ||
        fail "Activation wheelhouse is empty"

    chown -R "$DEPLOY_USER:$SERVICE_USER" "$CANDIDATE_DIR" "$WHEELHOUSE"
    find "$CANDIDATE_DIR" -type d -exec chmod 0750 {} +
    find "$CANDIDATE_DIR" -type f -exec chmod 0640 {} +
    find "$CANDIDATE_VENV/bin" -type f -exec chmod 0750 {} +
    find "$WHEELHOUSE" -type d -exec chmod 0750 {} +
    find "$WHEELHOUSE" -type f -exec chmod 0640 {} +
    complete_step
fi

if [[ $LAST_COMPLETED_STEP -ge 50 ]]; then
    log "Step 50 already completed for $TARGET_COMMIT; reuse the candidate preflight result"
else
    begin_step 50 "Preflight the candidate against current PostgreSQL and attachments"
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
' legacy-update-preflight \
        "$SERVICE_ENV" \
        "$CANDIDATE_DIR" \
        "$CANDIDATE_PYTHON"
    complete_step
fi

CURRENT_HEAD="$(run_as_deploy git -C "$APP_DIR" rev-parse HEAD)"
if [[ $LAST_COMPLETED_STEP -ge 60 ]] &&
    [[ "$CURRENT_HEAD" == "$TARGET_COMMIT" ]] &&
    wait_for_health 5 "$HEALTH_RESPONSE"; then
    log "Step 60 already completed; the target service is healthy"
else
    begin_step 60 "Apply the verified target without automatic rollback"
    wheelhouse_is_ready ||
        fail "Activation wheelhouse is missing; rerun candidate preparation"

    CURRENT_HEAD="$(run_as_deploy git -C "$APP_DIR" rev-parse HEAD)"
    [[ -z "$(run_as_deploy git -c core.filemode=false -C "$APP_DIR" status --porcelain)" ]] ||
        fail "$APP_DIR became dirty before activation"

    ACTIVATION_STARTED=1
    write_state "running"
    systemctl stop "$SERVICE_NAME"

    if [[ "$CURRENT_HEAD" != "$TARGET_COMMIT" ]]; then
        run_as_deploy git -c core.filemode=false -C "$APP_DIR" \
            checkout --detach "$TARGET_COMMIT"
    else
        log "The formal checkout already uses target $TARGET_COMMIT"
    fi

    if ! run_as_deploy "$VENV_DIR/bin/python" -m pip install \
        --no-index \
        --find-links "$WHEELHOUSE" \
        --upgrade pip setuptools wheel; then
        fail "Current legacy venv packaging tools could not be updated from the prepared wheelhouse"
    fi
    if ! run_as_deploy "$VENV_DIR/bin/python" -m pip install \
        --no-index \
        --find-links "$WHEELHOUSE" \
        -r "$APP_DIR/backend/requirements-linux.txt" \
        -r "$APP_DIR/backend/requirements-dev.txt"; then
        fail "Current legacy venv requirements could not be updated from the prepared wheelhouse"
    fi
    run_as_deploy "$VENV_DIR/bin/python" -m pip check

    chown -R "$DEPLOY_USER:$SERVICE_USER" "$APP_DIR"
    find "$APP_DIR" -type d -exec chmod 0750 {} +
    find "$APP_DIR" -type f -exec chmod 0640 {} +
    find "$VENV_DIR/bin" -type f -exec chmod 0750 {} +

    sudo -u "$SERVICE_USER" /bin/bash -c '
set -Eeuo pipefail
set -a
source "$1"
set +a
cd "$2"
"$3" scripts/preflight_linux.py
' legacy-live-preflight \
        "$SERVICE_ENV" \
        "$APP_DIR" \
        "$VENV_DIR/bin/python"

    systemctl reset-failed "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    wait_for_health 60 "$HEALTH_RESPONSE" ||
        fail "Updated legacy service did not become healthy within 60 seconds"
    complete_step
    ACTIVATION_STARTED=0
    write_state "running"
fi

begin_step 70 "Finalize and remove fixed temporary resources"
safe_remove_candidate
safe_remove_wheelhouse
rm -f -- "$HEALTH_RESPONSE" || true
complete_step
write_state "complete"
UPDATE_SUCCEEDED=1
trap - ERR EXIT

printf '\nlegacy_update=ok\nold_commit=%s\nnew_commit=%s\napp_dir=%s\nstate=%s\n' \
    "$OLD_COMMIT" "$TARGET_COMMIT" "$APP_DIR" "$STATE_FILE"
