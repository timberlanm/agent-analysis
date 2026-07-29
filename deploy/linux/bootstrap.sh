#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/timberlanm/agent-analysis.git}"
BRANCH="${BRANCH:-master}"
APP_DIR="${APP_DIR:-/opt/soc-workbench}"
SERVICE_NAME="${SERVICE_NAME:-soc-workbench}"
SERVICE_ENV="${SERVICE_ENV:-/etc/soc-workbench/soc-workbench.env}"
MIGRATION_ENV="${MIGRATION_ENV:-/etc/soc-workbench/soc-workbench.migration.env}"
RUNTIME_DIR="${RUNTIME_DIR:-/var/lib/soc-workbench}"
DEPLOY_USER="${DEPLOY_USER:-${SUDO_USER:-hacker}}"
SERVICE_USER="${SERVICE_USER:-socworkbench}"
BACKUP_DIR=""
NEW_CLONE=0

log() {
    printf '\n==> %s\n' "$*"
}

fail() {
    printf 'bootstrap=failed: %s\n' "$*" >&2
    exit 1
}

require_ubuntu_2204() {
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] ||
        fail "Ubuntu 22.04 is required"
}

run_as_deploy() {
    if [[ "$(id -un)" == "$DEPLOY_USER" ]]; then
        "$@"
    else
        sudo -u "$DEPLOY_USER" -- "$@"
    fi
}

restore_previous_install() {
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        return
    fi
    printf '\nBootstrap failed; attempting to restore the previous application directory.\n' >&2
    sudo systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
    if [[ $NEW_CLONE -eq 1 && -d "$APP_DIR" ]]; then
        sudo mv "$APP_DIR" "${APP_DIR}.failed.$(date +%Y%m%d_%H%M%S)" || true
    fi
    if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
        sudo mv "$BACKUP_DIR" "$APP_DIR" || true
        sudo systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}
trap restore_previous_install EXIT

require_ubuntu_2204
id "$DEPLOY_USER" >/dev/null 2>&1 || fail "Deployment user does not exist: $DEPLOY_USER"

log "Install Linux runtime prerequisites (Node.js is not required)"
sudo apt-get update
sudo apt-get install -y \
    git python3 python3-venv python3-pip rsync curl libgl1 libglib2.0-0

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    sudo useradd \
        --system \
        --home-dir "$RUNTIME_DIR" \
        --shell /usr/sbin/nologin \
        "$SERVICE_USER"
fi

sudo install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 \
    "$RUNTIME_DIR/data" \
    "$RUNTIME_DIR/uploads/incident"
sudo install -d -o root -g "$SERVICE_USER" -m 0750 /etc/soc-workbench

[[ -f "$SERVICE_ENV" ]] ||
    fail "Create $SERVICE_ENV from deploy/linux/soc-workbench.env.example first"
[[ -f "$MIGRATION_ENV" ]] ||
    fail "Create $MIGRATION_ENV from deploy/linux/soc-workbench.migration.env.example first"

sudo systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true

if [[ -d "$APP_DIR/.git" ]]; then
    log "Reuse existing Git checkout"
    [[ -z "$(run_as_deploy git -C "$APP_DIR" status --porcelain)" ]] ||
        fail "$APP_DIR contains uncommitted Linux-side changes"
    run_as_deploy git -C "$APP_DIR" fetch origin "$BRANCH"
    run_as_deploy git -C "$APP_DIR" checkout "$BRANCH"
    run_as_deploy git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
else
    if [[ -e "$APP_DIR" ]]; then
        BACKUP_DIR="${APP_DIR}.before-git.$(date +%Y%m%d_%H%M%S)"
        log "Move current non-Git deployment to $BACKUP_DIR"
        sudo mv "$APP_DIR" "$BACKUP_DIR"
    fi
    log "Clone $REPO_URL ($BRANCH)"
    sudo install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 0755 "$APP_DIR"
    run_as_deploy git clone --branch "$BRANCH" --single-branch "$REPO_URL" "$APP_DIR"
    NEW_CLONE=1
fi

[[ -f "$APP_DIR/frontend/dist/index.html" ]] ||
    fail "frontend/dist/index.html is not committed; publish from Windows first"
[[ -f "$APP_DIR/backend/data/analysis_store.db" ]] ||
    fail "backend/data/analysis_store.db is missing"

log "Create Python virtual environment and install incremental requirements"
if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
    run_as_deploy python3 -m venv "$APP_DIR/venv"
fi
run_as_deploy "$APP_DIR/venv/bin/python" -m pip install --upgrade pip setuptools wheel
run_as_deploy "$APP_DIR/venv/bin/python" -m pip install \
    -r "$APP_DIR/backend/requirements-linux.txt" \
    -r "$APP_DIR/backend/requirements-dev.txt"
run_as_deploy "$APP_DIR/venv/bin/python" -m pip check
run_as_deploy "$APP_DIR/venv/bin/python" \
    "$APP_DIR/scripts/verify_test_seed.py"

DATABASE_READY="$(
    sudo -u postgres psql -d postgres -tAc \
        "SELECT CASE WHEN
           EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_app')
           AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_migrator')
           AND EXISTS (SELECT 1 FROM pg_database WHERE datname = 'soc_platform_dev')
         THEN 1 ELSE 0 END"
)"
if [[ "${DATABASE_READY//[[:space:]]/}" != "1" ]]; then
    log "Create local PostgreSQL roles and database"
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
        "$APP_DIR/venv/bin/python" \
        "$APP_DIR/scripts/bootstrap_postgres.py"
fi

log "Synchronize committed test images, attachments, and logs"
sudo rsync -a --checksum \
    "$APP_DIR/backend/uploads/incident/" \
    "$RUNTIME_DIR/uploads/incident/"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$RUNTIME_DIR"
sudo find "$RUNTIME_DIR" -type d -exec chmod 0750 {} +
sudo find "$RUNTIME_DIR" -type f -exec chmod 0640 {} +

log "Initialize an empty PostgreSQL database from the committed SQLite seed"
sudo /bin/bash -c "
set -a
source '$MIGRATION_ENV'
set +a
cd '$APP_DIR'
'$APP_DIR/venv/bin/python' scripts/import_test_seed.py \
  --source backend/data/analysis_store.db \
  --report '$RUNTIME_DIR/seed-import-report.json'
"

log "Install systemd service"
sudo install -o root -g root -m 0644 \
    "$APP_DIR/deploy/linux/soc-workbench.service" \
    "/etc/systemd/system/$SERVICE_NAME.service"
sudo systemctl daemon-reload

# Keep source readable by the service without granting it write permission.
sudo chown -R "$DEPLOY_USER:$SERVICE_USER" "$APP_DIR"
sudo find "$APP_DIR" -type d -exec chmod 0750 {} +
sudo find "$APP_DIR" -type f -exec chmod 0640 {} +
sudo find "$APP_DIR/venv/bin" -type f -exec chmod 0750 {} +
sudo find "$APP_DIR/deploy/linux" -type f -name '*.sh' -exec chmod 0750 {} +

log "Run Linux preflight as the service account"
sudo -u "$SERVICE_USER" /bin/bash -c "
set -a
source '$SERVICE_ENV'
set +a
cd '$APP_DIR'
'$APP_DIR/venv/bin/python' scripts/preflight_linux.py
"

log "Start service and verify health"
sudo systemctl enable --now "$SERVICE_NAME"
curl --fail --silent --show-error --retry 10 --retry-delay 2 \
    "http://127.0.0.1:5000/health"
printf '\n'

COMMIT="$(run_as_deploy git -C "$APP_DIR" rev-parse HEAD)"
printf 'bootstrap=ok\nbranch=%s\ncommit=%s\n' "$BRANCH" "$COMMIT"
trap - EXIT
