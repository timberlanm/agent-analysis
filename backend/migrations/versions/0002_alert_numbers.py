"""Add stable, user-facing alert numbers.

Revision ID: 0002_alert_numbers
Revises: 0001_postgresql_baseline
"""

from alembic import op


revision = "0002_alert_numbers"
down_revision = "0001_postgresql_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE app_sequences (
            name TEXT PRIMARY KEY,
            value BIGINT NOT NULL
        );

        ALTER TABLE alerts ADD COLUMN alert_no TEXT;

        WITH numbered AS (
            SELECT
                id,
                row_number() OVER (ORDER BY created_at, id) AS sequence_value,
                CASE
                    WHEN created_at ~ '^\\d{4}-\\d{2}-\\d{2}'
                    THEN replace(substring(created_at FROM 1 FOR 10), '-', '')
                    ELSE to_char(current_timestamp AT TIME ZONE 'Asia/Shanghai', 'YYYYMMDD')
                END AS created_date
            FROM alerts
        )
        UPDATE alerts AS alert
        SET alert_no = (
            'SOC-' || numbered.created_date || '-' ||
            lpad(numbered.sequence_value::text, 6, '0')
        )
        FROM numbered
        WHERE alert.id = numbered.id;

        INSERT INTO app_sequences (name, value)
        VALUES ('alert_number', (SELECT count(*) FROM alerts));

        ALTER TABLE alerts ALTER COLUMN alert_no SET NOT NULL;
        CREATE UNIQUE INDEX idx_alerts_alert_no ON alerts(alert_no);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS idx_alerts_alert_no;
        ALTER TABLE alerts DROP COLUMN IF EXISTS alert_no;
        DROP TABLE IF EXISTS app_sequences;
        """
    )
