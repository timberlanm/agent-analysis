"""Database connection compatibility layer.

The application historically used ``sqlite3.Connection`` directly.  During
the PostgreSQL migration we keep that public shape small and stable while
moving connection pooling and transaction management to SQLAlchemy.

SQLite remains available for isolated legacy tests and for reading the source
database during migration.  Setting ``DATABASE_URL`` selects PostgreSQL.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


def postgresql_required() -> bool:
    """Return whether this process is forbidden from falling back to SQLite."""

    return os.environ.get("REQUIRE_POSTGRESQL", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def is_postgresql() -> bool:
    value = database_url().lower()
    return value.startswith("postgresql://") or value.startswith("postgresql+")


def validate_runtime_database() -> None:
    """Fail fast when a PostgreSQL-only deployment is misconfigured."""

    if not postgresql_required():
        return
    url = database_url()
    if not url:
        raise RuntimeError(
            "REQUIRE_POSTGRESQL is enabled but DATABASE_URL is empty"
        )
    if not is_postgresql():
        raise RuntimeError(
            "REQUIRE_POSTGRESQL is enabled but DATABASE_URL is not a "
            "PostgreSQL URL"
        )


class CompatRow(dict):
    """Dictionary row that also supports SQLite-style numeric indexing."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


def _compat_row(row: Any) -> CompatRow | None:
    if row is None:
        return None
    mapping = getattr(row, "_mapping", row)
    return CompatRow(dict(mapping))


class ResultAdapter:
    def __init__(self, result: Any):
        self._result = result

    @property
    def rowcount(self) -> int:
        return int(self._result.rowcount)

    def fetchone(self) -> CompatRow | None:
        return _compat_row(self._result.fetchone())

    def fetchall(self) -> list[CompatRow]:
        return [_compat_row(row) for row in self._result.fetchall()]

    def __iter__(self) -> Iterator[CompatRow]:
        for row in self._result:
            converted = _compat_row(row)
            if converted is not None:
                yield converted


_ENGINE = None


def _get_engine():
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE

    try:
        from sqlalchemy import create_engine
    except ImportError as exc:  # pragma: no cover - deployment guard
        raise RuntimeError(
            "PostgreSQL mode requires SQLAlchemy and psycopg. "
            "Install backend/requirements.txt first."
        ) from exc

    url = database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is required for PostgreSQL mode")

    _ENGINE = create_engine(
        url,
        pool_pre_ping=True,
        pool_size=int(os.environ.get("DB_POOL_SIZE", "5")),
        max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "5")),
        pool_timeout=int(os.environ.get("DB_POOL_TIMEOUT", "10")),
        pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", "1800")),
    )
    return _ENGINE


def dispose_engine() -> None:
    """Dispose pooled connections, primarily for tests and process shutdown."""

    global _ENGINE
    if _ENGINE is not None:
        _ENGINE.dispose()
        _ENGINE = None


def _replace_qmark_parameters(
    sql: str, parameters: Sequence[Any]
) -> tuple[str, dict[str, Any]]:
    """Convert SQLite qmark binds into SQLAlchemy named binds.

    The scanner deliberately ignores question marks inside SQL string
    literals.  Existing application SQL only uses positional parameters.
    """

    output: list[str] = []
    values: dict[str, Any] = {}
    parameter_index = 0
    in_string = False
    index = 0

    while index < len(sql):
        char = sql[index]
        if char == "'":
            output.append(char)
            if in_string and index + 1 < len(sql) and sql[index + 1] == "'":
                output.append("'")
                index += 2
                continue
            in_string = not in_string
            index += 1
            continue
        if char == "?" and not in_string:
            if parameter_index >= len(parameters):
                raise ValueError("SQL contains more placeholders than parameters")
            name = f"p{parameter_index}"
            output.append(f":{name}")
            values[name] = parameters[parameter_index]
            parameter_index += 1
        else:
            output.append(char)
        index += 1

    if parameter_index != len(parameters):
        raise ValueError("SQL contains fewer placeholders than parameters")
    return "".join(output), values


def _translate_sql(sql: str) -> str:
    translated = sql.strip()

    # SQLite's implicit rowid is replaced by the explicit PostgreSQL identity
    # column created for the audit log.
    translated = re.sub(r"\browid\b", "audit_seq", translated, flags=re.I)

    # Preserve the existing case-insensitive user-facing filtering semantics.
    translated = re.sub(r"\bLIKE\b", "ILIKE", translated, flags=re.I)

    if re.search(r"^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+auth_meta\b", translated, re.I):
        translated = re.sub(
            r"^\s*INSERT\s+OR\s+REPLACE\s+INTO",
            "INSERT INTO",
            translated,
            count=1,
            flags=re.I,
        )
        translated += " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
    elif re.search(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\b", translated, re.I):
        translated = re.sub(
            r"^\s*INSERT\s+OR\s+IGNORE\s+INTO",
            "INSERT INTO",
            translated,
            count=1,
            flags=re.I,
        )
        translated += " ON CONFLICT DO NOTHING"

    return translated


class PostgresConnection:
    """Small adapter implementing the sqlite3 methods used by the services."""

    def __init__(self):
        self._connection = _get_engine().connect()
        self._transaction = self._connection.begin()
        self._closed = False

    def __enter__(self) -> "PostgresConnection":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            if exc_type is None:
                self._transaction.commit()
            else:
                self._transaction.rollback()
        finally:
            self.close()
        return False

    def execute(
        self,
        sql: str,
        parameters: Sequence[Any] | Mapping[str, Any] = (),
    ) -> ResultAdapter:
        from sqlalchemy import text

        pragma_match = re.match(
            r"^\s*PRAGMA\s+table_info\(([^)]+)\)\s*$", sql, flags=re.I
        )
        if pragma_match:
            table_name = pragma_match.group(1).strip().strip("\"'")
            result = self._connection.execute(
                text(
                    "SELECT column_name AS name "
                    "FROM information_schema.columns "
                    "WHERE table_schema = current_schema() "
                    "AND table_name = :table_name "
                    "ORDER BY ordinal_position"
                ),
                {"table_name": table_name},
            )
            return ResultAdapter(result)

        translated = _translate_sql(sql)
        if isinstance(parameters, Mapping):
            bound_sql = translated
            bound_parameters = dict(parameters)
        else:
            bound_sql, bound_parameters = _replace_qmark_parameters(
                translated, tuple(parameters)
            )
        return ResultAdapter(
            self._connection.execute(text(bound_sql), bound_parameters)
        )

    def executescript(self, script: str) -> None:
        # PostgreSQL schema changes are exclusively managed by Alembic.  This
        # intentionally prevents the runtime application role from requiring
        # CREATE/ALTER privileges merely because legacy SQLite initialization
        # calls are still present in the services.
        return None

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True


def connect_postgresql() -> PostgresConnection:
    if not is_postgresql():
        raise RuntimeError("connect_postgresql() called without a PostgreSQL URL")
    return PostgresConnection()
