#!/usr/bin/env python3
import sqlite3
import os

EXTRA_DB_PATH = "extra.db"

# SQL schema for extra.db
SCHEMA = """
CREATE TABLE IF NOT EXISTS backup_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    added_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
"""

def init_extra_db():
    # Create db file if missing
    first_time = not os.path.exists(EXTRA_DB_PATH)
    conn = sqlite3.connect(EXTRA_DB_PATH)
    try:
        cur = conn.cursor()
        cur.executescript(SCHEMA)
        conn.commit()
        if first_time:
            print(f"Created new {EXTRA_DB_PATH} with backup_emails table.")
        else:
            print(f"Verified {EXTRA_DB_PATH} has backup_emails table.")
    finally:
        conn.close()

if __name__ == "__main__":
    init_extra_db()
