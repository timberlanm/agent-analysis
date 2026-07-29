"""Exercise Flask authentication and alert CRUD against PostgreSQL.

The script creates a temporary platform administrator, performs API requests,
and removes all probe rows (including appended audit entries) afterwards.
"""

from __future__ import annotations

import json
import io
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, text


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

USERNAME = "pg_migration_probe"
PASSWORD = "MigrationProbe!2026"


def csrf_from_response(response) -> str:
    for value in response.headers.getlist("Set-Cookie"):
        if value.startswith("csrf_token="):
            return value.split(";", 1)[0].split("=", 1)[1]
    return ""


def assert_response(response, expected: int = 200):
    body = response.get_json(silent=True)
    if response.status_code != expected:
        raise AssertionError(
            f"{response.request.method} {response.request.path}: "
            f"expected {expected}, got {response.status_code}, body={body}"
        )
    return body


def main() -> int:
    app_url = os.environ.get("DATABASE_URL", "")
    migrator_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url or not migrator_url:
        raise RuntimeError("DATABASE_URL and MIGRATION_DATABASE_URL are required")

    admin_engine = create_engine(migrator_url, pool_pre_ping=True)
    with admin_engine.begin() as connection:
        stale_start = connection.execute(
            text(
                """
                SELECT min(audit_seq)
                FROM audit_logs
                WHERE actor = :username
                   OR target_id IN (
                     SELECT id FROM users WHERE username = :username
                   )
                   OR (
                     actor = 'migration-verifier'
                     AND after_data LIKE :username_pattern
                   )
                """
            ),
            {
                "username": USERNAME,
                "username_pattern": f"%{USERNAME}%",
            },
        ).scalar_one()
        if stale_start is not None:
            stale_tail = connection.execute(
                text(
                    """
                    SELECT audit_seq, actor, target_id, after_data
                    FROM audit_logs
                    WHERE audit_seq >= :stale_start
                    ORDER BY audit_seq
                    """
                ),
                {"stale_start": stale_start},
            ).mappings()
            stale_tail = list(stale_tail)
            stale_user_ids = {
                row[0]
                for row in connection.execute(
                    text("SELECT id FROM users WHERE username = :username"),
                    {"username": USERNAME},
                )
            }
            probe_only = all(
                row["actor"] == USERNAME
                or row["target_id"] in stale_user_ids
                or (
                    row["actor"] == "migration-verifier"
                    and USERNAME in (row["after_data"] or "")
                )
                for row in stale_tail
            )
            if not probe_only:
                raise RuntimeError(
                    "A stale smoke-test audit tail contains unrelated activity; "
                    "refusing automatic cleanup"
                )
            connection.execute(
                text("DELETE FROM audit_logs WHERE audit_seq >= :stale_start"),
                {"stale_start": stale_start},
            )
            previous_sequence = int(stale_start) - 1
            connection.execute(
                text(
                    """
                    SELECT setval(
                      pg_get_serial_sequence('audit_logs', 'audit_seq'),
                      GREATEST(:sequence, 1),
                      :sequence > 0
                    )
                    """
                ),
                {"sequence": previous_sequence},
            )
        connection.execute(
            text("DELETE FROM alerts WHERE created_by = :username"),
            {"username": USERNAME},
        )
        connection.execute(
            text("DELETE FROM users WHERE username = :username"),
            {"username": USERNAME},
        )
        baseline = dict(
            connection.execute(
                text(
                    """
                    SELECT
                      (SELECT count(*) FROM users) AS users,
                      (SELECT count(*) FROM alerts) AS alerts,
                      (SELECT count(*) FROM audit_logs) AS audit_logs,
                      COALESCE((SELECT max(audit_seq) FROM audit_logs), 0) AS audit_seq
                    """
                )
            ).mappings().one()
        )

    probe = {}
    attachment_path = None
    try:
        from backend.app import create_app
        from backend.services import auth_service

        auth_service.create_user(
            USERNAME,
            PASSWORD,
            "PostgreSQL Migration Probe",
            ["admin"],
            actor="migration-verifier",
            must_change=False,
        )

        app = create_app(serve_frontend=False)
        client = app.test_client()

        login = client.post(
            "/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
        )
        login_body = assert_response(login)
        csrf = csrf_from_response(login)
        if not csrf:
            raise AssertionError("login did not issue a CSRF token")
        headers = {"X-CSRF-Token": csrf}

        me = assert_response(client.get("/api/auth/me"))
        listing = assert_response(client.get("/api/incident/alerts?limit=5"))
        created = assert_response(
            client.post(
                "/api/incident/alerts",
                headers=headers,
                json={
                    "title": "PostgreSQL migration smoke test",
                    "source_category": "other",
                    "severity": "info",
                },
            )
        )
        alert_id = created["data"]["id"]
        alert_no = created["data"]["alert_no"]
        searched = assert_response(
            client.get(f"/api/incident/alerts?keyword={alert_no}")
        )

        updated = assert_response(
            client.put(
                f"/api/incident/alerts/{alert_id}",
                headers=headers,
                json={"description": "updated through PostgreSQL adapter"},
            )
        )
        note = assert_response(
            client.post(
                f"/api/incident/alerts/{alert_id}/notes",
                headers=headers,
                json={"content": "PostgreSQL note probe"},
            )
        )
        attachment = assert_response(
            client.post(
                f"/api/incident/alerts/{alert_id}/attachments",
                headers=headers,
                data={
                    "file": (
                        io.BytesIO(b"postgres attachment smoke test\n"),
                        "postgres-smoke.txt",
                    )
                },
                content_type="multipart/form-data",
            )
        )["data"]["attachments"][0]
        from backend.services import incident_service

        attachment_path = incident_service.resolve_file_path(attachment["rel_path"])
        downloaded = client.get(attachment["url"])
        if downloaded.status_code != 200:
            raise AssertionError(
                f"attachment download failed: {downloaded.status_code}, "
                f"body={downloaded.get_json(silent=True)}"
            )
        if downloaded.data != b"postgres attachment smoke test\n":
            raise AssertionError("downloaded attachment content mismatch")
        downloaded.close()
        detail = assert_response(client.get(f"/api/incident/alerts/{alert_id}"))
        deleted = assert_response(
            client.delete(
                f"/api/incident/alerts/{alert_id}",
                headers=headers,
            )
        )

        probe = {
            "login": login_body["success"],
            "me": me["data"]["username"],
            "list_count": listing["data"]["count"],
            "created_alert": alert_id,
            "alert_no": alert_no,
            "search_match": searched["data"]["alerts"][0]["id"] == alert_id,
            "updated_description": updated["data"]["description"],
            "note_id": note["data"]["id"],
            "attachment_download": downloaded.status_code == 200,
            "detail_id": detail["data"]["id"],
            "deleted": deleted["success"],
        }
    finally:
        if attachment_path and attachment_path.is_file():
            try:
                attachment_path.unlink()
            except PermissionError:
                pass
        # Remove all probe state and restore the original audit sequence so the
        # migration verification remains repeatable and data-neutral.
        with admin_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM alerts WHERE created_by = :username"),
                {"username": USERNAME},
            )
            connection.execute(
                text("DELETE FROM users WHERE username = :username"),
                {"username": USERNAME},
            )
            connection.execute(
                text("DELETE FROM audit_logs WHERE audit_seq > :sequence"),
                {"sequence": baseline["audit_seq"]},
            )
            connection.execute(
                text(
                    """
                    SELECT setval(
                      pg_get_serial_sequence('audit_logs', 'audit_seq'),
                      GREATEST(:sequence, 1),
                      :sequence > 0
                    )
                    """
                ),
                {"sequence": baseline["audit_seq"]},
            )
            after = dict(
                connection.execute(
                    text(
                        """
                        SELECT
                          (SELECT count(*) FROM users) AS users,
                          (SELECT count(*) FROM alerts) AS alerts,
                          (SELECT count(*) FROM audit_logs) AS audit_logs
                        """
                    )
                ).mappings().one()
            )
        admin_engine.dispose()

    cleanup_ok = all(
        after[name] == baseline[name] for name in ("users", "alerts", "audit_logs")
    )
    result = {
        "ok": cleanup_ok,
        "probe": probe,
        "baseline": baseline,
        "after_cleanup": after,
        "cleanup_ok": cleanup_ok,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"smoke test failed: {exc}", file=sys.stderr)
        raise
