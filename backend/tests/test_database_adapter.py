import pytest

from backend.database import (
    _replace_qmark_parameters,
    _translate_sql,
    postgresql_required,
    validate_runtime_database,
)


def test_qmark_translation_ignores_string_literals():
    sql, values = _replace_qmark_parameters(
        "SELECT '?' AS literal, id FROM alerts WHERE id = ? AND status = ?",
        ("alt_1", "pending"),
    )
    assert sql == (
        "SELECT '?' AS literal, id FROM alerts "
        "WHERE id = :p0 AND status = :p1"
    )
    assert values == {"p0": "alt_1", "p1": "pending"}


def test_sqlite_upsert_and_audit_order_translation():
    ignored = _translate_sql(
        "INSERT OR IGNORE INTO entities (id) VALUES (?)"
    )
    assert ignored == (
        "INSERT INTO entities (id) VALUES (?) ON CONFLICT DO NOTHING"
    )

    replaced = _translate_sql(
        "INSERT OR REPLACE INTO auth_meta (key, value) VALUES ('v', ?)"
    )
    assert replaced.endswith(
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
    )

    audit = _translate_sql(
        "SELECT * FROM audit_logs ORDER BY rowid DESC"
    )
    assert "audit_seq DESC" in audit


def test_like_becomes_case_insensitive_for_postgresql():
    assert _translate_sql("title LIKE ?") == "title ILIKE ?"


def test_postgresql_requirement_is_opt_in(monkeypatch):
    monkeypatch.delenv("REQUIRE_POSTGRESQL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert postgresql_required() is False
    validate_runtime_database()


def test_required_postgresql_rejects_missing_or_wrong_url(monkeypatch):
    monkeypatch.setenv("REQUIRE_POSTGRESQL", "true")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL is empty"):
        validate_runtime_database()

    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/wrong.db")
    with pytest.raises(RuntimeError, match="not a PostgreSQL URL"):
        validate_runtime_database()

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://soc_app:password@127.0.0.1/soc_platform_dev",
    )
    validate_runtime_database()
