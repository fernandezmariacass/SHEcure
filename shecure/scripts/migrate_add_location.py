"""
migrate_add_location.py
=======================
One-time migration: adds the `location` column to the `access_logs` table.

Run once after deploying the geo-location feature:

    cd shecure/
    python scripts/migrate_add_location.py

Safe to run multiple times — it checks whether the column already exists
before issuing the ALTER TABLE.
"""

import os
import sys

# Make sure the app package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from sqlalchemy import text, inspect

app = create_app()

with app.app_context():
    inspector = inspect(db.engine)
    cols = [c["name"] for c in inspector.get_columns("access_logs")]

    if "location" in cols:
        print("[migrate] 'location' column already exists — nothing to do.")
    else:
        with db.engine.connect() as conn:
            conn.execute(text(
                "ALTER TABLE access_logs ADD COLUMN location VARCHAR(200)"
            ))
            conn.commit()
        print("[migrate] 'location' column added to access_logs successfully.")
