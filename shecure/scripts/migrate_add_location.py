"""
migrate_add_location.py
=======================
Adds the `location` column to `access_logs` if it doesn't exist yet.

Runs directly via psycopg2 — does NOT import create_app() — so it cannot
crash due to missing env vars, seed failures, or any other app-startup issue.
Safe to run multiple times.
"""

import os
import sys

database_url = os.environ.get("DATABASE_URL", "")
if not database_url:
    print("[migrate] WARNING: DATABASE_URL not set — skipping migration.")
    sys.exit(0)

# Railway sometimes uses postgres:// — normalise to postgresql://
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

try:
    import psycopg2
except ImportError:
    print("[migrate] psycopg2 not available — skipping migration.")
    sys.exit(0)

try:
    conn = psycopg2.connect(database_url)
    conn.autocommit = False
    cur = conn.cursor()

    # Check if column already exists
    cur.execute("""
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'access_logs' AND column_name = 'location'
    """)
    exists = cur.fetchone() is not None

    if exists:
        print("[migrate] 'location' column already exists — nothing to do.")
    else:
        cur.execute("ALTER TABLE access_logs ADD COLUMN location VARCHAR(200)")
        conn.commit()
        print("[migrate] 'location' column added to access_logs successfully.")

    cur.close()
    conn.close()
    sys.exit(0)

except Exception as e:
    print(f"[migrate] ERROR: {e}")
    # Exit 0 so gunicorn still starts — the app handles missing column gracefully
    sys.exit(0)
