from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "deploy" / "linux" / "bootstrap.sh"
UPDATE = ROOT / "deploy" / "linux" / "update.sh"
LEGACY_UPDATE = ROOT / "deploy" / "linux" / "update-legacy-opt.sh"
SERVICE = ROOT / "deploy" / "linux" / "soc-workbench.service"
SERVICE_ENV = ROOT / "deploy" / "linux" / "soc-workbench.env.example"


def test_bootstrap_is_resumable_and_does_not_use_legacy_backups():
    script = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'DEPLOY_USER="${DEPLOY_USER:-${SUDO_USER:-}}"' in script
    assert 'INSTALL_ROOT="${INSTALL_ROOT:-$DEPLOY_HOME/soc-workbench}"' in script
    assert 'STATE_FILE="$INSTALLER_DIR/state.json"' in script
    assert "bootstrap=resume" in script
    assert 'write_state "complete"' in script
    assert "before-git" not in script
    assert ".failed." not in script
    assert "rollback-tree" not in script


def test_bootstrap_supports_local_github_and_fully_offline_sources():
    script = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'SOURCE_MODE="${REQUESTED_SOURCE_MODE:-local}"' in script
    assert "local | github" in script
    assert 'OFFLINE_MODE="${REQUESTED_OFFLINE_MODE:-0}"' in script
    assert 'apt-get update' in script
    assert 'apt-get -o Acquire::Retries=0 --no-download install -y' in script
    assert 'PIP_SOURCE_ARGS=(--no-index --find-links "$WHEELHOUSE")' in script
    assert 'run_as_deploy git ls-remote "$REPO_URL"' in script
    assert 'LOCAL_SOURCE_DIR="${LOCAL_SOURCE_DIR:-$BOOTSTRAP_SOURCE}"' in script
    assert '"source_mode": os.environ["STATE_SOURCE_MODE"]' in script
    assert '"offline_mode": os.environ["STATE_OFFLINE_MODE"]' in script
    assert '"local_source_dir": os.environ["STATE_LOCAL_SOURCE_DIR"]' in script
    assert '"wheelhouse": os.environ["STATE_WHEELHOUSE"]' in script
    assert '"offline_deb_dir": os.environ["STATE_OFFLINE_DEB_DIR"]' in script
    assert "SUDO_USER:-hacker" not in script


def test_bootstrap_activates_only_after_application_preflight():
    script = BOOTSTRAP.read_text(encoding="utf-8")

    preflight = script.index("scripts/preflight_linux.py")
    activation = script.index('ln -s "$RELEASE_DIR" "$CURRENT_LINK"')
    health_guard = script.index("if [[ $HEALTHY -ne 1 ]]")
    enable_service = script.index('systemctl enable "$SERVICE_NAME"')

    assert preflight < activation
    assert activation < health_guard < enable_service


def test_home_layout_templates_are_renderable():
    service = SERVICE.read_text(encoding="utf-8")
    rendered = service.replace(
        "__INSTALL_ROOT__", "/home/analyst/soc-workbench"
    ).replace("__SERVICE_USER__", "socworkbench")

    assert "__INSTALL_ROOT__" not in rendered
    assert "__SERVICE_USER__" not in rendered
    assert (
        "WorkingDirectory=/home/analyst/soc-workbench/current" in rendered
    )
    assert (
        "ExecStart=/home/analyst/soc-workbench/current/venv/bin/python "
        "-m gunicorn"
    ) in rendered

    environment = SERVICE_ENV.read_text(encoding="utf-8").replace(
        "__INSTALL_ROOT__", "/home/analyst/soc-workbench"
    )
    assert (
        "APP_DATA_DIR=/home/analyst/soc-workbench/runtime/data" in environment
    )
    assert (
        "INCIDENT_UPLOAD_DIR="
        "/home/analyst/soc-workbench/runtime/uploads/incident"
    ) in environment


def test_update_targets_only_a_completed_home_layout_installation():
    script = UPDATE.read_text(encoding="utf-8")

    assert 'DEPLOY_USER="${DEPLOY_USER:-${SUDO_USER:-}}"' in script
    assert 'INSTALL_ROOT="${INSTALL_ROOT:-$DEPLOY_HOME/soc-workbench}"' in script
    assert 'BOOTSTRAP_STATE="$INSTALLER_DIR/state.json"' in script
    assert (
        '[[ "$(json_field "$BOOTSTRAP_STATE" status)" == "complete" ]]'
        in script
    )
    assert 'CURRENT_LINK="$INSTALL_ROOT/current"' in script
    assert "/opt/soc-workbench" not in script
    assert "git reset --hard" not in script
    assert "git pull" not in script
    assert 'systemctl stop "$SERVICE_NAME"' not in script
    assert ".failed." not in script
    assert "before-git" not in script


def test_update_supports_local_github_offline_and_resume():
    script = UPDATE.read_text(encoding="utf-8")

    assert 'SOURCE_MODE="${REQUESTED_SOURCE_MODE:-local}"' in script
    assert "local | github" in script
    assert 'OFFLINE_MODE="${REQUESTED_OFFLINE_MODE:-0}"' in script
    assert 'PIP_SOURCE_ARGS=(--no-index --find-links "$WHEELHOUSE")' in script
    assert 'run_as_deploy git ls-remote "$REPO_URL"' in script
    assert "update=resume" in script
    assert 'UPDATE_STATE="$INSTALLER_DIR/update-state.json"' in script
    assert '"local_source_dir": os.environ["STATE_LOCAL_SOURCE_DIR"]' in script
    assert '"wheelhouse": os.environ["STATE_WHEELHOUSE"]' in script
    assert "SUDO_USER:-hacker" not in script


def test_update_preflights_before_atomic_switch_and_rolls_back_health_failure():
    script = UPDATE.read_text(encoding="utf-8")

    test_candidate = script.index('-m pytest')
    preflight = script.index("scripts/preflight_linux.py", test_candidate)
    activate = script.index('switch_current "$CANDIDATE_DIR"')
    restart = script.index('systemctl restart "$SERVICE_NAME"', activate)
    health_guard = script.index("if [[ $HEALTHY -ne 1 ]]")

    assert test_candidate < preflight < activate < restart < health_guard
    assert 'switch_current "$OLD_RELEASE"' in script
    assert 'rsync -a --ignore-existing' in script
    assert "git reset --hard" not in script
    assert "alembic upgrade" not in script


def test_legacy_updater_is_isolated_to_the_current_opt_test_layout():
    script = LEGACY_UPDATE.read_text(encoding="utf-8")

    assert 'APP_DIR="${APP_DIR:-/opt/soc-workbench}"' in script
    assert (
        'SERVICE_ENV="${SERVICE_ENV:-/etc/soc-workbench/'
        'soc-workbench.env}"'
    ) in script
    assert 'RUNTIME_DIR="${RUNTIME_DIR:-/var/lib/soc-workbench}"' in script
    assert 'CANDIDATE_DIR="/opt/soc-workbench-update-candidate"' in script
    assert 'run_as_deploy git ls-remote "$REPO_URL"' in script
    assert 'STATE_FILE="$STATE_DIR/update-legacy-state.json"' in script
    assert 'DEPLOY_GROUP="$(id -gn "$DEPLOY_USER")"' in script
    assert (
        'install -d -o root -g "$DEPLOY_GROUP" -m 0750 "$STATE_DIR"'
        in script
    )
    assert 'install -d -o root -g root -m 0750 "$STATE_DIR"' not in script
    assert "git reset --hard" not in script
    assert "before-git" not in script
    assert ".failed." not in script
    assert "alembic upgrade" not in script


def test_legacy_updater_validates_candidate_before_forward_only_activation():
    script = LEGACY_UPDATE.read_text(encoding="utf-8")

    candidate_test = script.index("-m pytest")
    wheelhouse = script.index("-m pip download", candidate_test)
    candidate_preflight = script.index(
        "scripts/preflight_linux.py", candidate_test
    )
    maintenance_stop = script.index(
        'systemctl stop "$SERVICE_NAME"', candidate_preflight
    )
    live_checkout = script.index(
        'git -C "$APP_DIR" checkout --detach "$TARGET_COMMIT"'
    )

    assert candidate_test < wheelhouse < candidate_preflight < maintenance_stop
    assert maintenance_stop < live_checkout
    assert 'git -C "$APP_DIR" checkout --detach "$OLD_COMMIT"' not in script
    assert "rollback_legacy_checkout" not in script
    assert "Automatic rollback is disabled" in script
    assert "legacy_update=resume" in script
    assert 'START_NEW_UPDATE="${START_NEW_UPDATE:-0}"' in script
    assert 'safe_remove_candidate' in script
    assert 'safe_remove_wheelhouse' in script
    assert 'wait_for_health 60 "$HEALTH_RESPONSE"' in script
