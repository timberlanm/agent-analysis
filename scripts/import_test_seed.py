"""Initialize an empty PostgreSQL test database from the committed SQLite seed."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "backend" / "data" / "analysis_store.db"
sys.path.insert(0, str(ROOT))

from scripts.migrate_sqlite_to_postgres import (  # noqa: E402
    SKIPPED_TABLES,
    TABLE_ORDER,
    upgrade_schema,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--target-url",
        default=os.environ.get("MIGRATION_DATABASE_URL", ""),
    )
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def table_counts(target_url: str) -> dict[str, int]:
    engine = create_engine(target_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            return {
                table: int(
                    connection.execute(
                        text(f'SELECT count(*) FROM "{table}"')
                    ).scalar_one()
                )
                for table in TABLE_ORDER + SKIPPED_TABLES
            }
    finally:
        engine.dispose()


def write_report(report: dict, destination: Path | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    if not args.source.is_file():
        raise FileNotFoundError(f"SQLite seed does not exist: {args.source}")
    if not args.target_url:
        raise RuntimeError("MIGRATION_DATABASE_URL or --target-url is required")

    target = make_url(args.target_url)
    if target.get_backend_name() != "postgresql":
        raise RuntimeError("The seed target must be PostgreSQL")

    # This is safe on an empty database and brings an existing database to the
    # schema expected by the seed importer.
    upgrade_schema(args.target_url)
    before = table_counts(args.target_url)
    non_empty = {table: count for table, count in before.items() if count}
    if non_empty:
        write_report(
            {
                "ok": True,
                "mode": "skip-existing-database",
                "target": target.render_as_string(hide_password=True),
                "counts": before,
            },
            args.report,
        )
        return 0

    environment = os.environ.copy()
    environment["MIGRATION_DATABASE_URL"] = args.target_url
    command = [
        sys.executable,
        str(ROOT / "scripts" / "migrate_sqlite_to_postgres.py"),
        "--source",
        str(args.source),
        "--skip-schema-upgrade",
    ]
    if args.report:
        command.extend(["--report", str(args.report)])
    result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    if result.returncode != 0:
        return result.returncode

    after = table_counts(args.target_url)
    if after.get("alerts", 0) == 0:
        raise RuntimeError("Seed import completed without any alerts")
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "seed-import-complete",
                "alerts": after.get("alerts", 0),
                "attachments": after.get("attachments", 0),
                "users": after.get("users", 0),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"seed-import=failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
