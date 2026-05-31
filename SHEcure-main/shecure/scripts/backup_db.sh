#!/bin/bash
# SHEcure Database Backup Script
# Saves a pg_dump of the Railway PostgreSQL database with a timestamped filename.
# Store backups in a separate location (e.g. email, Google Drive, S3).

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="shecure_backup_${DATE}.sql"

echo "[backup] Starting backup at ${DATE}..."

pg_dump "$DATABASE_URL" > "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "[backup] Backup saved: ${BACKUP_FILE}"
    echo "[backup] Size: $(du -sh $BACKUP_FILE | cut -f1)"
else
    echo "[backup] ERROR: pg_dump failed!"
    exit 1
fi
