"""
DB Migration — Add missing columns to the licenses table in PostgreSQL.
Run once: python migrate.py
Requires: DB_HOST, DB_NAME, DB_USER, DB_PASS environment variables (or edit below).
"""

import psycopg2, os

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "qr_gen1")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = os.environ.get("DB_PASS", "20071224")      # set via env, don't hardcode!

MIGRATIONS = [
    # Make sure the core table exists
    """
    CREATE TABLE IF NOT EXISTS licenses (
        license_key  TEXT PRIMARY KEY,
        expiry_date  TIMESTAMP,
        max_devices  INTEGER NOT NULL DEFAULT 1,
        devices      JSONB   NOT NULL DEFAULT '[]'::jsonb,
        is_active    BOOLEAN NOT NULL DEFAULT TRUE,
        note         TEXT    DEFAULT '',
        created_at   TIMESTAMP NOT NULL DEFAULT NOW()
    )
    """,
    # Add columns that may be missing from older installs (safe: IF NOT EXISTS)
    "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS is_active  BOOLEAN   NOT NULL DEFAULT TRUE",
    "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS note       TEXT      DEFAULT ''",
    "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()",
    # Migrate old device_id column → devices JSONB array
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='licenses' AND column_name='device_id'
        ) AND NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='licenses' AND column_name='devices'
        ) THEN
            ALTER TABLE licenses ADD COLUMN devices JSONB NOT NULL DEFAULT '[]'::jsonb;
            UPDATE licenses
               SET devices = CASE
                               WHEN device_id IS NOT NULL
                               THEN jsonb_build_array(device_id)
                               ELSE '[]'::jsonb
                             END;
        END IF;
    END $$;
    """,
    # New plans table
    """
    CREATE TABLE IF NOT EXISTS plans (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        features JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    # Add plan_id to licenses
    "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL",
    # New dynamic_qrs table for synced/embedded content
    """
    CREATE TABLE IF NOT EXISTS dynamic_qrs (
        short_code TEXT PRIMARY KEY,
        content_type TEXT NOT NULL,
        content_data TEXT NOT NULL,
        title TEXT DEFAULT '',
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NULL,
        expiry_date TIMESTAMP DEFAULT NULL,
        scan_count INTEGER NOT NULL DEFAULT 0,
        last_scanned_at TIMESTAMP DEFAULT NULL,
        time_based_content TEXT DEFAULT NULL,
        created_by_user TEXT DEFAULT '',
        server_settings TEXT NOT NULL DEFAULT '{}'
    )
    """,
    # Index for fast lookup
    "CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses (license_key)",
    "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS features JSONB NOT NULL DEFAULT '{}'::jsonb",
    "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS qr_scan_count INTEGER NOT NULL DEFAULT 0",
    # Dynamic QR ownership, lifecycle, and advanced server settings
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NULL",
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS expiry_date TIMESTAMP DEFAULT NULL",
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS scan_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP DEFAULT NULL",
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS time_based_content TEXT DEFAULT NULL",
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS created_by_user TEXT DEFAULT ''",
    "ALTER TABLE dynamic_qrs ADD COLUMN IF NOT EXISTS server_settings TEXT NOT NULL DEFAULT '{}'",
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='dynamic_qrs' AND column_name='license_key'
        ) THEN
            UPDATE dynamic_qrs
               SET created_by_user = COALESCE(NULLIF(created_by_user, ''), license_key)
             WHERE COALESCE(created_by_user, '') = '';
        END IF;
    END $$;
    """,
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='dynamic_qrs' AND column_name='expire_at'
        ) THEN
            UPDATE dynamic_qrs
               SET expiry_date = COALESCE(expiry_date, expire_at)
             WHERE expire_at IS NOT NULL;
        END IF;
    END $$;
    """,
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='dynamic_qrs' AND column_name='time_schedules'
        ) THEN
            UPDATE dynamic_qrs
               SET time_based_content = COALESCE(time_based_content, time_schedules)
             WHERE time_schedules IS NOT NULL;
        END IF;
    END $$;
    """,
    "CREATE INDEX IF NOT EXISTS idx_dynamic_qrs_owner ON dynamic_qrs (created_by_user)",
    "ALTER TABLE dynamic_qrs DROP COLUMN IF EXISTS time_schedules",
    "ALTER TABLE dynamic_qrs DROP COLUMN IF EXISTS expire_at",
    "ALTER TABLE dynamic_qrs DROP COLUMN IF EXISTS license_key",
]


def run():
    print("[migrate] Connecting to DB…")
    conn = psycopg2.connect(
        host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS
    )
    cur = conn.cursor()

    for i, sql in enumerate(MIGRATIONS, 1):
        try:
            cur.execute(sql)
            conn.commit()
            print(f"[migrate] Step {i} — OK")
        except Exception as exc:
            conn.rollback()
            print(f"[migrate] Step {i} — FAILED: {exc}")

    conn.close()
    print("[migrate] Done.")


if __name__ == "__main__":
    run()
