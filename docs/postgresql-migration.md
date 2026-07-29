# PostgreSQL development migration

This stage migrates the authoritative application data from SQLite to
PostgreSQL. Elasticsearch is intentionally out of scope.

## Inputs

- PostgreSQL: `192.168.50.132:5432`
- PostgreSQL major version: 16
- Database: `soc_platform_dev`
- Migration role: `soc_migrator`
- Runtime role: `soc_app`
- SQLite source: `backend/data/analysis_store.db`

Do not commit real passwords. Set them in the current shell before invoking
the commands below.

## 1. Bootstrap roles and database

PowerShell:

```powershell
$env:ADMIN_DATABASE_URL = "postgresql+psycopg://postgres:<admin-password>@192.168.50.132:5432/postgres"
$env:SOC_MIGRATOR_PASSWORD = "<migrator-password>"
$env:SOC_APP_PASSWORD = "<app-password>"
python scripts/bootstrap_postgres.py
```

## 2. Migrate and verify

```powershell
$env:MIGRATION_DATABASE_URL = "postgresql+psycopg://soc_migrator:<migrator-password>@192.168.50.132:5432/soc_platform_dev"
python scripts/migrate_sqlite_to_postgres.py --report migration-report.json
```

The target database must be empty. The migration runs in one PostgreSQL
transaction and rolls back if counts, primary-key digests, or foreign-key
checks fail. Existing sessions are deliberately not imported.

## 3. Verify runtime privileges and data

```powershell
$env:DATABASE_URL = "postgresql+psycopg://soc_app:<app-password>@192.168.50.132:5432/soc_platform_dev"
python scripts/verify_postgres_migration.py
```

## 4. Start the backend on PostgreSQL

The normal development setup stores the runtime variables in the gitignored
project-root file `.env.postgres.local`:

```dotenv
DATABASE_URL=postgresql+psycopg://soc_app:<app-password>@192.168.50.132:5432/soc_platform_dev
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=5
DB_POOL_TIMEOUT=10
DB_POOL_RECYCLE=1800
INCIDENT_UPLOAD_DIR=D:\analysis\agent-analysis\agent-analysis\backend\uploads\incident
```

Both launch methods load this file:

```powershell
.\start.bat
python backend\app.py
```

An explicitly set process variable has higher priority than the local file,
so a one-off connection can be selected without editing it:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://soc_app:<app-password>@192.168.50.132:5432/soc_platform_dev"
python backend/app.py
```

Rollback is configuration-only while the SQLite backup remains unchanged:
stop the backend, rename `.env.postgres.local`, unset `DATABASE_URL`, and
restart it.

## 5. Applied follow-up migrations

- `0002_alert_numbers`: adds immutable user-facing alert numbers, backfills
  existing alerts, and creates the concurrency-safe `app_sequences` counter.

The attachment binary files are not stored in PostgreSQL. The database stores
paths relative to `INCIDENT_UPLOAD_DIR`, so the attachment directory must be
backed up and deployed together with the application.
