"""Print non-secret PostgreSQL instance, database, role and HBA diagnostics."""

from __future__ import annotations

import json
import os
import sys

import psycopg
from sqlalchemy.engine import make_url


def main() -> int:
    raw_url = os.environ.get("ADMIN_DATABASE_URL", "")
    if not raw_url:
        raise RuntimeError("ADMIN_DATABASE_URL is required")
    url = make_url(raw_url).set(drivername="postgresql", database="soc_platform_dev")
    dsn = url.render_as_string(hide_password=False)

    with psycopg.connect(dsn) as connection:
        settings = {
            name: connection.execute(
                "SELECT current_setting(%s)", (name,)
            ).fetchone()[0]
            for name in (
                "server_version",
                "server_encoding",
                "TimeZone",
                "password_encryption",
                "listen_addresses",
                "port",
                "ssl",
                "max_connections",
                "shared_buffers",
                "work_mem",
                "maintenance_work_mem",
                "effective_cache_size",
            )
        }
        roles = [
            {
                "name": row[0],
                "superuser": row[1],
                "create_database": row[2],
                "create_role": row[3],
                "login": row[4],
                "connection_limit": row[5],
            }
            for row in connection.execute(
                """
                SELECT rolname, rolsuper, rolcreatedb, rolcreaterole,
                       rolcanlogin, rolconnlimit
                FROM pg_roles
                WHERE rolname IN ('postgres', 'soc_migrator', 'soc_app')
                ORDER BY rolname
                """
            )
        ]
        database = connection.execute(
            """
            SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding),
                   datcollate, datctype, pg_database_size(datname)
            FROM pg_database WHERE datname = current_database()
            """
        ).fetchone()
        hba = [
            {
                "rule_number": row[0],
                "type": row[1],
                "database": row[2],
                "users": row[3],
                "address": row[4],
                "method": row[5],
                "error": row[6],
            }
            for row in connection.execute(
                """
                SELECT rule_number, type, database, user_name, address,
                       auth_method, error
                FROM pg_hba_file_rules
                ORDER BY rule_number NULLS LAST
                """
            )
        ]
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]

    print(
        json.dumps(
            {
                "settings": settings,
                "database": {
                    "name": database[0],
                    "owner": database[1],
                    "encoding": database[2],
                    "collation": database[3],
                    "ctype": database[4],
                    "size_bytes": database[5],
                },
                "roles": roles,
                "hba_rules": hba,
                "alembic_revision": revision,
            },
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"inspection failed: {exc}", file=sys.stderr)
        raise
