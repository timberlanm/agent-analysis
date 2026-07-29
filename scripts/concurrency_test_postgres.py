"""Run concurrent transactions through the application's PostgreSQL pool."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROBE_ID = "postgres_concurrency_probe"
WORKERS = int(os.environ.get("CONCURRENCY_TEST_WORKERS", "30"))


def main() -> int:
    if not os.environ.get("DATABASE_URL", ""):
        raise RuntimeError("DATABASE_URL is required")

    from backend.database import connect_postgresql, dispose_engine
    from backend.services.incident_service import _next_alert_no

    with connect_postgresql() as connection:
        connection.execute("DELETE FROM alerts WHERE id = ?", (PROBE_ID,))
        probe_alert_no = _next_alert_no(
            connection, "2000-01-01T00:00:00+00:00"
        )
        connection.execute(
            """
            INSERT INTO alerts
            (id, alert_no, title, source_category, severity, status, round, version,
             created_at, updated_at)
            VALUES (?, ?, ?, 'other', 'info', 'pending', 1, 1, ?, ?)
            """,
            (
                PROBE_ID,
                probe_alert_no,
                "PostgreSQL concurrency probe",
                "2000-01-01T00:00:00+00:00",
                "2000-01-01T00:00:00+00:00",
            ),
        )

    def increment(index: int) -> int:
        with connect_postgresql() as connection:
            result = connection.execute(
                "UPDATE alerts SET version = version + 1, updated_by = ? "
                "WHERE id = ?",
                (f"worker-{index}", PROBE_ID),
            )
            if result.rowcount != 1:
                raise RuntimeError(f"worker {index} updated {result.rowcount} rows")
            row = connection.execute(
                "SELECT count(*) AS c FROM alerts"
            ).fetchone()
            return int(row["c"])

    started = time.perf_counter()
    failures = []
    completed = 0
    number_failures = []
    generated_numbers = []
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(increment, index) for index in range(WORKERS)]
            for future in as_completed(futures):
                try:
                    future.result()
                    completed += 1
                except Exception as exc:
                    failures.append(str(exc))

        with connect_postgresql() as connection:
            row = connection.execute(
                "SELECT version FROM alerts WHERE id = ?", (PROBE_ID,)
            ).fetchone()
            final_version = int(row["version"]) if row else None

        def create_numbered_probe(index: int) -> str:
            probe_id = f"postgres_number_probe_{index}"
            with connect_postgresql() as connection:
                alert_no = _next_alert_no(
                    connection, "2000-01-01T00:00:00+00:00"
                )
                connection.execute(
                    """
                    INSERT INTO alerts
                    (id, alert_no, title, source_category, severity, status,
                     round, version, created_at, updated_at)
                    VALUES (?, ?, ?, 'other', 'info', 'pending', 1, 1, ?, ?)
                    """,
                    (
                        probe_id,
                        alert_no,
                        f"Alert number concurrency probe {index}",
                        "2000-01-01T00:00:00+00:00",
                        "2000-01-01T00:00:00+00:00",
                    ),
                )
                return alert_no

        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [
                executor.submit(create_numbered_probe, index)
                for index in range(WORKERS)
            ]
            for future in as_completed(futures):
                try:
                    generated_numbers.append(future.result())
                except Exception as exc:
                    number_failures.append(str(exc))
    finally:
        with connect_postgresql() as connection:
            connection.execute("DELETE FROM alerts WHERE id = ?", (PROBE_ID,))
            connection.execute(
                "DELETE FROM alerts WHERE id LIKE ?",
                ("postgres_number_probe_%",),
            )
        dispose_engine()

    elapsed = round(time.perf_counter() - started, 3)
    number_format_ok = all(
        re.fullmatch(r"SOC-\d{8}-\d{6,}", number)
        for number in generated_numbers
    )
    number_unique = len(set(generated_numbers)) == WORKERS
    result = {
        "ok": (
            not failures
            and completed == WORKERS
            and final_version == WORKERS + 1
            and not number_failures
            and number_unique
            and number_format_ok
        ),
        "workers": WORKERS,
        "completed": completed,
        "failures": failures,
        "initial_version": 1,
        "final_version": final_version,
        "expected_version": WORKERS + 1,
        "elapsed_seconds": elapsed,
        "probe_removed": True,
        "alert_numbers": {
            "generated": len(generated_numbers),
            "unique": number_unique,
            "format_ok": number_format_ok,
            "failures": number_failures,
        },
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
