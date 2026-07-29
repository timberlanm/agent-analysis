"""Verify migrated data, runtime privileges, audit integrity and attachments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "backend" / "data" / "analysis_store.db"
DEFAULT_UPLOADS = ROOT / "backend" / "uploads" / "incident"

TABLES = [
    "roles",
    "permissions",
    "users",
    "role_permissions",
    "user_roles",
    "api_tokens",
    "auth_meta",
    "alerts",
    "entities",
    "attachments",
    "notes",
    "assignment_logs",
    "escalation_records",
    "subtasks",
    "audit_logs",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--uploads", type=Path, default=DEFAULT_UPLOADS)
    parser.add_argument(
        "--app-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL URL using the runtime soc_app role",
    )
    return parser.parse_args()


def audit_hash(*parts: Any) -> str:
    canonical = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    previous = ""
    checked = 0
    skipped = 0
    for row in rows:
        if not row["entry_hash"]:
            skipped += 1
            continue
        expected = audit_hash(
            previous,
            row["id"],
            row["actor"],
            row["actor_user_id"],
            row["action"],
            row["target_type"],
            row["target_id"],
            row["before_data"],
            row["after_data"],
            row["created_at"],
        )
        if (row["prev_hash"] or "") != previous or row["entry_hash"] != expected:
            return {
                "ok": False,
                "checked": checked,
                "skipped_legacy": skipped,
                "broken_at": row["id"],
            }
        previous = row["entry_hash"]
        checked += 1
    return {
        "ok": True,
        "checked": checked,
        "skipped_legacy": skipped,
        "broken_at": None,
    }


def main() -> int:
    args = parse_args()
    if not args.app_url:
        raise RuntimeError("--app-url or DATABASE_URL is required")
    if make_url(args.app_url).get_backend_name() != "postgresql":
        raise RuntimeError("The verification target must be PostgreSQL")

    source = sqlite3.connect(
        f"file:{args.source.resolve().as_posix()}?mode=ro", uri=True
    )
    source.row_factory = sqlite3.Row
    source_counts = {
        table: int(source.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
        for table in TABLES
    }
    source_sessions = int(source.execute("SELECT count(*) FROM sessions").fetchone()[0])
    source.close()

    engine = create_engine(args.app_url, pool_pre_ping=True)
    report: dict[str, Any] = {}
    try:
        with engine.connect() as connection:
            server = connection.execute(
                text(
                    "SELECT current_setting('server_version') AS version, "
                    "current_database() AS database, current_user AS role, "
                    "inet_server_addr()::text AS server_address, "
                    "inet_server_port() AS server_port"
                )
            ).mappings().one()
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            alert_numbers = dict(
                connection.execute(
                    text(
                        """
                        SELECT
                          count(*) AS alerts,
                          count(DISTINCT alert_no) AS unique_numbers,
                          count(*) FILTER (
                            WHERE alert_no IS NULL OR alert_no = ''
                          ) AS missing_numbers,
                          min(alert_no) AS first_number,
                          max(alert_no) AS last_number
                        FROM alerts
                        """
                    )
                ).mappings().one()
            )
            alert_number_sequence = dict(
                connection.execute(
                    text(
                        "SELECT name, value FROM app_sequences "
                        "WHERE name = 'alert_number'"
                    )
                ).mappings().one()
            )
            target_counts = {
                table: int(
                    connection.execute(
                        text(f'SELECT count(*) FROM "{table}"')
                    ).scalar_one()
                )
                for table in TABLES
            }
            target_sessions = int(
                connection.execute(text("SELECT count(*) FROM sessions")).scalar_one()
            )
            audit_rows = [
                dict(row)
                for row in connection.execute(
                    text("SELECT * FROM audit_logs ORDER BY audit_seq")
                ).mappings()
            ]

            privileges = connection.execute(
                text(
                    """
                    SELECT
                      has_schema_privilege(current_user, 'public', 'USAGE') AS schema_usage,
                      has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
                      has_table_privilege(current_user, 'alerts', 'SELECT') AS alert_select,
                      has_table_privilege(current_user, 'alerts', 'INSERT') AS alert_insert,
                      has_table_privilege(current_user, 'alerts', 'UPDATE') AS alert_update,
                      has_table_privilege(current_user, 'alerts', 'DELETE') AS alert_delete
                    """
                )
            ).mappings().one()

            # Exercise runtime DML and the audit identity sequence, then roll
            # back so verification leaves migrated data unchanged.
            transaction = connection.begin_nested()
            probe_id = "verify_postgres_probe"
            connection.execute(
                text(
                    """
                    INSERT INTO alerts
                    (id, alert_no, title, source_category, severity, status, round,
                     version, created_at, updated_at)
                    VALUES
                    (:id, 'SOC-20000101-999999999', 'migration verification',
                     'other', 'info', 'pending',
                     1, 1, :now, :now)
                    """
                ),
                {"id": probe_id, "now": "2000-01-01T00:00:00+00:00"},
            )
            connection.execute(
                text("UPDATE alerts SET status = 'investigating' WHERE id = :id"),
                {"id": probe_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO audit_logs
                    (id, actor, action, target_type, target_id, before_data,
                     after_data, created_at, prev_hash, entry_hash)
                    VALUES
                    ('verify_audit_probe', 'verification', 'verify', 'alert',
                     :id, '{}', '{}', '2000-01-01T00:00:00+00:00', '', '')
                    """
                ),
                {"id": probe_id},
            )
            connection.execute(
                text("DELETE FROM alerts WHERE id = :id"), {"id": probe_id}
            )
            transaction.rollback()

        attachment_rows = []
        with engine.connect() as connection:
            attachment_rows = [
                dict(row)
                for row in connection.execute(
                    text("SELECT id, rel_path, size FROM attachments")
                ).mappings()
            ]
    finally:
        engine.dispose()

    missing_files = []
    size_mismatches = []
    for attachment in attachment_rows:
        path = args.uploads / attachment["rel_path"]
        if not path.is_file():
            missing_files.append(
                {"id": attachment["id"], "path": str(path)}
            )
        elif path.stat().st_size != int(attachment["size"]):
            size_mismatches.append(
                {
                    "id": attachment["id"],
                    "path": str(path),
                    "database_size": int(attachment["size"]),
                    "file_size": path.stat().st_size,
                }
            )

    count_matches = {
        table: {
            "source": source_counts[table],
            "target": target_counts[table],
            "match": source_counts[table] == target_counts[table],
        }
        for table in TABLES
    }
    privilege_values = dict(privileges)
    privilege_ok = (
        privilege_values["schema_usage"]
        and not privilege_values["schema_create"]
        and all(
            privilege_values[name]
            for name in ("alert_select", "alert_insert", "alert_update", "alert_delete")
        )
    )
    audit = verify_audit(audit_rows)
    report = {
        "server": dict(server),
        "alembic_revision": revision,
        "alert_numbers": {
            **alert_numbers,
            "sequence": alert_number_sequence,
            "ok": (
                alert_numbers["alerts"] == alert_numbers["unique_numbers"]
                and alert_numbers["missing_numbers"] == 0
                and alert_number_sequence["value"] >= alert_numbers["alerts"]
            ),
        },
        "counts": count_matches,
        "sessions": {
            "source": source_sessions,
            "target": target_sessions,
            "match": target_sessions == 0,
        },
        "runtime_privileges": {
            **privilege_values,
            "match": privilege_ok,
        },
        "runtime_dml_probe": {"ok": True, "rolled_back": True},
        "audit_chain": audit,
        "attachments": {
            "database_records": len(attachment_rows),
            "missing_files": missing_files,
            "size_mismatches": size_mismatches,
            "ok": not missing_files and not size_mismatches,
        },
    }
    report["ok"] = (
        all(item["match"] for item in count_matches.values())
        and report["sessions"]["match"]
        and privilege_ok
        and audit["ok"]
        and report["alert_numbers"]["ok"]
        and report["attachments"]["ok"]
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        raise
