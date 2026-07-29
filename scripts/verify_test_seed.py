"""Verify that the committed SQLite queue and evidence files form one seed."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "backend" / "data" / "analysis_store.db",
    )
    parser.add_argument(
        "--uploads",
        type=Path,
        default=ROOT / "backend" / "uploads" / "incident",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database = args.database.resolve()
    uploads = args.uploads.resolve()
    if not database.is_file():
        raise FileNotFoundError(f"SQLite seed is missing: {database}")
    if not uploads.is_dir():
        raise FileNotFoundError(f"Evidence directory is missing: {uploads}")

    connection = sqlite3.connect(
        f"file:{database.as_posix()}?mode=ro",
        uri=True,
    )
    try:
        alert_count = int(
            connection.execute("SELECT count(*) FROM alerts").fetchone()[0]
        )
        attachment_paths = [
            str(row[0] or "").replace("\\", "/").lstrip("/")
            for row in connection.execute(
                "SELECT rel_path FROM attachments ORDER BY rel_path"
            ).fetchall()
        ]
    finally:
        connection.close()

    missing: list[str] = []
    invalid: list[str] = []
    for relative_path in attachment_paths:
        candidate = (uploads / relative_path).resolve()
        try:
            candidate.relative_to(uploads)
        except ValueError:
            invalid.append(relative_path)
            continue
        if not candidate.is_file():
            missing.append(relative_path)

    physical_count = sum(
        1 for path in uploads.rglob("*") if path.is_file()
    )
    print(f"seed_alerts={alert_count}")
    print(f"seed_attachment_records={len(attachment_paths)}")
    print(f"seed_attachment_files={physical_count}")
    print(f"seed_missing_attachments={len(missing)}")
    print(f"seed_invalid_paths={len(invalid)}")

    if invalid:
        for path in invalid[:20]:
            print(f"  invalid: {path}")
    if missing:
        for path in missing[:20]:
            print(f"  missing: {path}")
    if invalid or missing:
        raise RuntimeError("SQLite seed and committed evidence are incomplete")
    if alert_count == 0:
        raise RuntimeError("SQLite seed contains no alerts")

    print("seed_verification=ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"seed_verification=failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
