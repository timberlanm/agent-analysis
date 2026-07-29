"""Validate a Linux deployment before starting the systemd service."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _check_writable_directory(path: Path, label: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    probe = path / ".soc-workbench-write-test"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise RuntimeError(f"{label} is not writable: {path}: {exc}") from exc


def main() -> int:
    if platform.system() != "Linux":
        raise RuntimeError("This preflight is intended to run on Linux")

    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    from backend.database import (
        _get_engine,
        is_postgresql,
        validate_runtime_database,
    )
    from backend.services.incident_service import DATA_DIR, UPLOAD_BASE

    validate_runtime_database()
    if not is_postgresql():
        raise RuntimeError("Linux deployment must use PostgreSQL")

    frontend_index = ROOT / "frontend" / "dist" / "index.html"
    if not frontend_index.is_file():
        raise RuntimeError(
            f"Frontend build is missing: {frontend_index}. Run npm run build."
        )

    _check_writable_directory(Path(DATA_DIR), "APP_DATA_DIR")
    _check_writable_directory(Path(UPLOAD_BASE), "INCIDENT_UPLOAD_DIR")

    alembic_config = Config(str(ROOT / "alembic.ini"))
    code_revision = ScriptDirectory.from_config(
        alembic_config
    ).get_current_head()

    with _get_engine().connect() as connection:
        identity = connection.execute(
            text(
                "SELECT current_database() AS database_name, "
                "current_user AS database_user"
            )
        ).mappings().one()
        migration = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        alert_count = int(
            connection.execute(text("SELECT count(*) FROM alerts")).scalar_one()
        )
        attachment_count = int(
            connection.execute(
                text("SELECT count(*) FROM attachments")
            ).scalar_one()
        )
        attachment_paths = connection.execute(
            text("SELECT rel_path FROM attachments ORDER BY rel_path")
        ).scalars()
        missing = [
            rel_path
            for rel_path in attachment_paths
            if not (Path(UPLOAD_BASE) / rel_path).is_file()
        ]

    expected_database = os.environ.get(
        "EXPECTED_DATABASE_NAME", "soc_platform_dev"
    )
    expected_user = os.environ.get("EXPECTED_DATABASE_USER", "soc_app")
    if identity["database_name"] != expected_database:
        raise RuntimeError(
            f"Unexpected database: {identity['database_name']} "
            f"(expected {expected_database})"
        )
    if identity["database_user"] != expected_user:
        raise RuntimeError(
            f"Unexpected database user: {identity['database_user']} "
            f"(expected {expected_user})"
        )
    if migration != code_revision:
        raise RuntimeError(
            f"Database revision {migration} does not match code head "
            f"{code_revision}; run the approved Alembic migration first"
        )

    attachment_files = sum(
        1 for path in Path(UPLOAD_BASE).rglob("*") if path.is_file()
    )
    print(f"platform=Linux ({platform.release()})")
    print(f"database={identity['database_name']}")
    print(f"database_user={identity['database_user']}")
    print(f"alembic_revision={migration}")
    print(f"code_alembic_head={code_revision}")
    print(f"app_data_dir={DATA_DIR}")
    print(f"incident_upload_dir={UPLOAD_BASE}")
    print(f"alerts={alert_count}")
    print(f"attachment_records={attachment_count}")
    print(f"attachment_files={attachment_files}")
    print(f"missing_attachments={len(missing)}")
    if missing:
        for path in missing[:20]:
            print(f"  missing: {path}")
        raise RuntimeError("Attachment files referenced by PostgreSQL are missing")

    print("preflight=ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"preflight=failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
