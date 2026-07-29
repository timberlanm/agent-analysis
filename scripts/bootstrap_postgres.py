"""Create the development PostgreSQL database and least-privilege roles.

Required environment variables:

    ADMIN_DATABASE_URL
    SOC_MIGRATOR_PASSWORD
    SOC_APP_PASSWORD

The script is idempotent and may be rerun after a VM restart.
"""

from __future__ import annotations

import os
import sys

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


DATABASE_NAME = os.environ.get("SOC_DATABASE_NAME", "soc_platform_dev")
MIGRATOR_ROLE = os.environ.get("SOC_MIGRATOR_ROLE", "soc_migrator")
APP_ROLE = os.environ.get("SOC_APP_ROLE", "soc_app")


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def psycopg_dsn(url_value: str, database: str | None = None) -> str:
    url = make_url(url_value)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("ADMIN_DATABASE_URL must be a PostgreSQL URL")
    if database is not None:
        url = url.set(database=database)
    # psycopg accepts postgresql:// but not SQLAlchemy's +psycopg driver marker.
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def ensure_role(
    connection: psycopg.Connection,
    role: str,
    password: str,
    connection_limit: int,
) -> None:
    exists = connection.execute(
        "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
    ).fetchone()
    role_identifier = sql.Identifier(role)
    if not exists:
        connection.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION CONNECTION LIMIT {}"
            ).format(role_identifier, sql.Literal(connection_limit))
        )
    # ALTER ROLE is a utility statement; PostgreSQL does not accept a bound
    # parameter in the PASSWORD clause, so quote the controlled value through
    # psycopg's SQL composition API.
    connection.execute(
        sql.SQL("ALTER ROLE {} PASSWORD {}").format(
            role_identifier,
            sql.Literal(password),
        )
    )


def main() -> int:
    admin_url = required("ADMIN_DATABASE_URL")
    migrator_password = required("SOC_MIGRATOR_PASSWORD")
    app_password = required("SOC_APP_PASSWORD")

    admin_dsn = psycopg_dsn(admin_url, "postgres")
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        version = connection.execute(
            "SELECT current_setting('server_version'), current_user, "
            "inet_server_addr(), inet_server_port(), inet_client_addr()"
        ).fetchone()
        print(
            "connected:",
            {
                "server_version": version[0],
                "current_user": version[1],
                "server_address": str(version[2]),
                "server_port": version[3],
                "client_address": str(version[4]),
            },
        )
        ensure_role(connection, MIGRATOR_ROLE, migrator_password, 5)
        ensure_role(connection, APP_ROLE, app_password, 40)

        database_exists = connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (DATABASE_NAME,)
        ).fetchone()
        if not database_exists:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER {} ENCODING 'UTF8' TEMPLATE template0").format(
                    sql.Identifier(DATABASE_NAME),
                    sql.Identifier(MIGRATOR_ROLE),
                )
            )
        else:
            connection.execute(
                sql.SQL("ALTER DATABASE {} OWNER TO {}").format(
                    sql.Identifier(DATABASE_NAME),
                    sql.Identifier(MIGRATOR_ROLE),
                )
            )

    target_dsn = psycopg_dsn(admin_url, DATABASE_NAME)
    with psycopg.connect(target_dsn) as connection:
        connection.execute(
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(
                sql.Identifier(DATABASE_NAME)
            )
        )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(
                sql.Identifier(DATABASE_NAME),
                sql.Identifier(MIGRATOR_ROLE),
                sql.Identifier(APP_ROLE),
            )
        )
        connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        connection.execute(
            sql.SQL("GRANT ALL ON SCHEMA public TO {}").format(
                sql.Identifier(MIGRATOR_ROLE)
            )
        )
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                sql.Identifier(APP_ROLE)
            )
        )
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
            ).format(
                sql.Identifier(MIGRATOR_ROLE),
                sql.Identifier(APP_ROLE),
            )
        )
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                "GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {}"
            ).format(
                sql.Identifier(MIGRATOR_ROLE),
                sql.Identifier(APP_ROLE),
            )
        )
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
                "GRANT EXECUTE ON FUNCTIONS TO {}"
            ).format(
                sql.Identifier(MIGRATOR_ROLE),
                sql.Identifier(APP_ROLE),
            )
        )
        # Also repair privileges when the script is rerun after tables already
        # exist; default privileges only affect objects created in the future.
        connection.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE "
                "ON ALL TABLES IN SCHEMA public TO {}"
            ).format(sql.Identifier(APP_ROLE))
        )
        connection.execute(
            sql.SQL(
                "GRANT USAGE, SELECT, UPDATE "
                "ON ALL SEQUENCES IN SCHEMA public TO {}"
            ).format(sql.Identifier(APP_ROLE))
        )

    print(
        "ready:",
        {
            "database": DATABASE_NAME,
            "migrator_role": MIGRATOR_ROLE,
            "app_role": APP_ROLE,
        },
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        raise
