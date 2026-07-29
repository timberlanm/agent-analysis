#!/usr/bin/env bash
set -Eeuo pipefail

BRANCH="${BRANCH:-master}"
APP_DIR="${APP_DIR:-/opt/soc-workbench}"
SERVICE_NAME="${SERVICE_NAME:-soc-workbench}"
SERVICE_ENV="${SERVICE_ENV:-/etc/soc-workbench/soc-workbench.env}"
RUNTIME_DIR="${RUNTIME_DIR:-/var/lib/soc-workbench}"
SERVICE_USER="${SERVICE_USER:-socworkbench}"
OLD_COMMIT=""
PULLED=0

log() {
    printf '\n==> %s\n' "$*"
}

fail() {
    printf 'update=failed: %s\n' "$*" >&2
    exit 1
}

rollback() {
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        return
    fi
    if [[ $PULLED -eq 1 && -n "$OLD_COMMIT" ]]; then
        printf '\nUpdate failed; restoring commit %s\n' "$OLD_COMMIT" >&2
        git -C "$APP_DIR" reset --hard "$OLD_COMMIT" || true
        "$APP_DIR/venv/bin/python" -m pip install \
            -r "$APP_DIR/backend/requirements-linux.txt" \
            -r "$APP_DIR/backend/requirements-dev.txt" || true
        sudo systemctl restart "$SERVICE_NAME" || true
    fi
    exit "$exit_code"
}
trap rollback EXIT

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ -d "$APP_DIR/.git" ]] || fail "$APP_DIR is not a Git checkout; run bootstrap.sh"
[[ -f "$SERVICE_ENV" ]] || fail "Missing $SERVICE_ENV"
[[ -x "$APP_DIR/venv/bin/python" ]] || fail "Missing Python virtual environment"
[[ -z "$(git -C "$APP_DIR" status --porcelain)" ]] ||
    fail "Linux checkout contains local changes; change code in Windows and publish first"

OLD_COMMIT="$(git -C "$APP_DIR" rev-parse HEAD)"

log "Pull origin/$BRANCH"
git -C "$APP_DIR" fetch origin "$BRANCH"
git -C "$APP_DIR" checkout "$BRANCH"
git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
PULLED=1
NEW_COMMIT="$(git -C "$APP_DIR" rev-parse HEAD)"

[[ -f "$APP_DIR/frontend/dist/index.html" ]] ||
    fail "Committed frontend/dist/index.html is missing"
[[ -f "$APP_DIR/backend/data/analysis_store.db" ]] ||
    fail "Committed SQLite test seed is missing"

log "Install Python requirements without upgrading satisfied packages"
"$APP_DIR/venv/bin/python" -m pip install \
    -r "$APP_DIR/backend/requirements-linux.txt" \
    -r "$APP_DIR/backend/requirements-dev.txt"
"$APP_DIR/venv/bin/python" -m pip check
"$APP_DIR/venv/bin/python" "$APP_DIR/scripts/verify_test_seed.py"

log "Compile and test backend"
cd "$APP_DIR"
"$APP_DIR/venv/bin/python" -m compileall -q \
    backend/api \
    backend/services \
    backend/tests \
    backend/migrations \
    backend/app.py \
    backend/config.py \
    backend/database.py \
    scripts \
    wsgi.py
APP_SKIP_LOCAL_ENV=1 "$APP_DIR/venv/bin/python" -m pytest backend/tests -q

log "Synchronize committed test images, attachments, and logs"
sudo rsync -a --checksum \
    "$APP_DIR/backend/uploads/incident/" \
    "$RUNTIME_DIR/uploads/incident/"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$RUNTIME_DIR/uploads"
sudo find "$RUNTIME_DIR/uploads" -type d -exec chmod 0750 {} +
sudo find "$RUNTIME_DIR/uploads" -type f -exec chmod 0640 {} +

log "Run PostgreSQL and attachment preflight"
sudo -u "$SERVICE_USER" /bin/bash -c "
set -a
source '$SERVICE_ENV'
set +a
cd '$APP_DIR'
'$APP_DIR/venv/bin/python' scripts/preflight_linux.py
"

log "Restart service"
sudo systemctl restart "$SERVICE_NAME"
sudo systemctl is-active --quiet "$SERVICE_NAME"
curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    "http://127.0.0.1:5000/health"
printf '\n'

printf 'update=ok\nold_commit=%s\nnew_commit=%s\n' "$OLD_COMMIT" "$NEW_COMMIT"
trap - EXIT
