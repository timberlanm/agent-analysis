"""Migrate the incident analysis SQLite database to PostgreSQL.

The source database is always opened read-only.  The target must be empty so
that reruns cannot silently hide duplicate or partially imported data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection, Engine, make_url


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "backend" / "data" / "analysis_store.db"

TABLE_ORDER = [
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

# Sessions are deliberately invalidated at cutover.  Users must log in again.
SKIPPED_TABLES = ["sessions"]

PRIMARY_KEYS = {
    "roles": ("id",),
    "permissions": ("code",),
    "users": ("id",),
    "role_permissions": ("role_code", "permission_code"),
    "user_roles": ("user_id", "role_id"),
    "api_tokens": ("id",),
    "auth_meta": ("key",),
    "alerts": ("id",),
    "entities": ("id",),
    "attachments": ("id",),
    "notes": ("id",),
    "assignment_logs": ("id",),
    "escalation_records": ("id",),
    "subtasks": ("id",),
    "audit_logs": ("id",),
}

JSON_COLUMNS = {
    "alerts": ("handlers", "raw_content", "normalized_fields"),
    "audit_logs": ("before_data", "after_data"),
    "api_tokens": ("scopes",),
}

ORPHAN_CHECKS = {
    "attachments.alert_id": """
        SELECT count(*) FROM attachments child
        LEFT JOIN alerts parent ON parent.id = child.alert_id
        WHERE child.alert_id IS NOT NULL AND parent.id IS NULL
    """,
    "entities.alert_id": """
        SELECT count(*) FROM entities child
        LEFT JOIN alerts parent ON parent.id = child.alert_id
        WHERE parent.id IS NULL
    """,
    "notes.alert_id": """
        SELECT count(*) FROM notes child
        LEFT JOIN alerts parent ON parent.id = child.alert_id
        WHERE parent.id IS NULL
    """,
    "assignment_logs.alert_id": """
        SELECT count(*) FROM assignment_logs child
        LEFT JOIN alerts parent ON parent.id = child.alert_id
        WHERE parent.id IS NULL
    """,
    "escalation_records.alert_id": """
        SELECT count(*) FROM escalation_records child
        LEFT JOIN alerts parent ON parent.id = child.alert_id
        WHERE parent.id IS NULL
    """,
    "subtasks.alert_id": """
        SELECT count(*) FROM subtasks child
        LEFT JOIN alerts parent ON parent.id = child.alert_id
        WHERE parent.id IS NULL
    """,
    "user_roles.user_id": """
        SELECT count(*) FROM user_roles child
        LEFT JOIN users parent ON parent.id = child.user_id
        WHERE parent.id IS NULL
    """,
    "user_roles.role_id": """
        SELECT count(*) FROM user_roles child
        LEFT JOIN roles parent ON parent.id = child.role_id
        WHERE parent.id IS NULL
    """,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--target-url",
        default=os.environ.get("MIGRATION_DATABASE_URL", ""),
        help="SQLAlchemy PostgreSQL URL; defaults to MIGRATION_DATABASE_URL",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspect and validate the SQLite source without writing PostgreSQL",
    )
    parser.add_argument(
        "--skip-schema-upgrade",
        action="store_true",
        help="Do not run Alembic upgrade before importing",
    )
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def sqlite_connection(path: Path) -> sqlite3.Connection:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"SQLite source does not exist: {resolved}")
    connection = sqlite3.connect(f"file:{resolved.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def sqlite_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def source_rows(
    connection: sqlite3.Connection, table: str
) -> list[dict[str, Any]]:
    if table == "audit_logs":
        rows = connection.execute(
            "SELECT rowid AS audit_seq, * FROM audit_logs ORDER BY rowid"
        ).fetchall()
    else:
        rows = connection.execute(f'SELECT * FROM "{table}"').fetchall()
    return [dict(row) for row in rows]


def key_digest(rows: list[dict[str, Any]], columns: tuple[str, ...]) -> str:
    values = [
        "\x1f".join("" if row.get(column) is None else str(row[column]) for column in columns)
        for row in rows
    ]
    canonical = "\n".join(sorted(values))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_json(rows_by_table: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for table, columns in JSON_COLUMNS.items():
        for row in rows_by_table.get(table, []):
            for column in columns:
                value = row.get(column)
                if value in (None, ""):
                    continue
                try:
                    json.loads(value)
                except (TypeError, json.JSONDecodeError) as exc:
                    failures.append(
                        {
                            "table": table,
                            "column": column,
                            "id": row.get("id"),
                            "error": str(exc),
                        }
                    )
    return failures


def upgrade_schema(target_url: str) -> None:
    previous = os.environ.get("MIGRATION_DATABASE_URL")
    os.environ["MIGRATION_DATABASE_URL"] = target_url
    try:
        configuration = Config(str(ROOT / "alembic.ini"))
        command.upgrade(configuration, "head")
    finally:
        if previous is None:
            os.environ.pop("MIGRATION_DATABASE_URL", None)
        else:
            os.environ["MIGRATION_DATABASE_URL"] = previous


def require_empty_target(connection: Connection) -> None:
    non_empty = {}
    for table in TABLE_ORDER + SKIPPED_TABLES:
        count = connection.execute(
            text(f'SELECT count(*) FROM "{table}"')
        ).scalar_one()
        if count:
            non_empty[table] = int(count)
    if non_empty:
        raise RuntimeError(
            "Target database is not empty; refusing a partial/duplicate import: "
            + json.dumps(non_empty, ensure_ascii=False)
        )


def _format_import_alert_no(sequence_value: int, created_at: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        if not parsed.tzinfo:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        parsed = datetime.now(timezone.utc)
    china_time = parsed.astimezone(timezone(timedelta(hours=8)))
    return f"SOC-{china_time:%Y%m%d}-{sequence_value:06d}"


def insert_rows(
    connection: Connection,
    engine: Engine,
    table: str,
    rows: list[dict[str, Any]],
) -> None:
    if not rows:
        return

    target_columns = {
        column["name"] for column in inspect(connection).get_columns(table)
    }
    rows_to_insert = rows
    if table == "alerts" and "alert_no" in target_columns:
        ordered = sorted(
            rows,
            key=lambda row: (str(row.get("created_at") or ""), str(row.get("id") or "")),
        )
        generated = {
            row["id"]: _format_import_alert_no(index, row.get("created_at"))
            for index, row in enumerate(ordered, start=1)
        }
        rows_to_insert = [
            {
                **row,
                "alert_no": row.get("alert_no") or generated[row["id"]],
            }
            for row in rows
        ]

    columns = [column for column in rows_to_insert[0] if column in target_columns]
    preparer = engine.dialect.identifier_preparer
    table_sql = preparer.quote(table)
    column_sql = ", ".join(preparer.quote(column) for column in columns)
    value_sql = ", ".join(f":{column}" for column in columns)
    statement = text(
        f"INSERT INTO {table_sql} ({column_sql}) VALUES ({value_sql})"
    )
    connection.execute(
        statement,
        [{column: row.get(column) for column in columns} for row in rows_to_insert],
    )
    if table == "alerts" and "alert_no" in target_columns:
        connection.execute(
            text(
                "UPDATE app_sequences SET value = GREATEST(value, :value) "
                "WHERE name = 'alert_number'"
            ),
            {"value": len(rows_to_insert)},
        )


def reset_audit_identity(connection: Connection) -> None:
    connection.execute(
        text(
            """
            SELECT setval(
                pg_get_serial_sequence('audit_logs', 'audit_seq'),
                COALESCE((SELECT max(audit_seq) FROM audit_logs), 1),
                EXISTS (SELECT 1 FROM audit_logs)
            )
            """
        )
    )


def target_rows(connection: Connection, table: str) -> list[dict[str, Any]]:
    keys = PRIMARY_KEYS[table]
    order_sql = ", ".join(f'"{column}"' for column in keys)
    result = connection.execute(
        text(f'SELECT * FROM "{table}" ORDER BY {order_sql}')
    )
    return [dict(row._mapping) for row in result]


def verify_target(
    connection: Connection,
    source: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    counts = {}
    key_digests = {}
    for table in TABLE_ORDER:
        rows = target_rows(connection, table)
        source_count = len(source[table])
        target_count = len(rows)
        counts[table] = {
            "source": source_count,
            "target": target_count,
            "match": source_count == target_count,
        }
        source_digest = key_digest(source[table], PRIMARY_KEYS[table])
        target_digest = key_digest(rows, PRIMARY_KEYS[table])
        key_digests[table] = {
            "source": source_digest,
            "target": target_digest,
            "match": source_digest == target_digest,
        }

    session_count = int(
        connection.execute(text("SELECT count(*) FROM sessions")).scalar_one()
    )
    orphan_counts = {
        name: int(connection.execute(text(query)).scalar_one())
        for name, query in ORPHAN_CHECKS.items()
    }
    return {
        "counts": counts,
        "key_digests": key_digests,
        "sessions": {
            "source": "deliberately skipped",
            "target": session_count,
            "match": session_count == 0,
        },
        "orphans": orphan_counts,
        "ok": (
            all(item["match"] for item in counts.values())
            and all(item["match"] for item in key_digests.values())
            and session_count == 0
            and all(count == 0 for count in orphan_counts.values())
        ),
    }


def write_report(report: dict[str, Any], destination: Path | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    with sqlite_connection(args.source) as source_connection:
        available = sqlite_tables(source_connection)
        missing = [table for table in TABLE_ORDER + SKIPPED_TABLES if table not in available]
        if missing:
            raise RuntimeError(f"SQLite source is missing tables: {missing}")
        rows_by_table = {
            table: source_rows(source_connection, table) for table in TABLE_ORDER
        }
        skipped_counts = {
            table: source_connection.execute(
                f'SELECT count(*) FROM "{table}"'
            ).fetchone()[0]
            for table in SKIPPED_TABLES
        }

    json_failures = validate_json(rows_by_table)
    source_report = {
        "source": str(args.source.resolve()),
        "counts": {table: len(rows) for table, rows in rows_by_table.items()},
        "skipped": skipped_counts,
        "json_failures": json_failures,
    }
    if json_failures:
        write_report({"ok": False, **source_report}, args.report)
        return 2
    if args.dry_run:
        write_report({"ok": True, "mode": "dry-run", **source_report}, args.report)
        return 0

    if not args.target_url:
        raise RuntimeError("--target-url or MIGRATION_DATABASE_URL is required")
    target_url = make_url(args.target_url)
    if target_url.get_backend_name() != "postgresql":
        raise RuntimeError("The migration target must be PostgreSQL")

    if not args.skip_schema_upgrade:
        upgrade_schema(args.target_url)

    engine = create_engine(args.target_url, pool_pre_ping=True)
    try:
        with engine.begin() as target_connection:
            require_empty_target(target_connection)
            for table in TABLE_ORDER:
                insert_rows(
                    target_connection,
                    engine,
                    table,
                    rows_by_table[table],
                )
            reset_audit_identity(target_connection)
            verification = verify_target(target_connection, rows_by_table)
            if not verification["ok"]:
                raise RuntimeError(
                    "PostgreSQL verification failed; transaction will roll back: "
                    + json.dumps(verification, ensure_ascii=False)
                )
    finally:
        engine.dispose()

    report = {
        "ok": True,
        "mode": "migrate",
        "source": source_report,
        "target": target_url.render_as_string(hide_password=True),
        "verification": verification,
    }
    write_report(report, args.report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        raise
