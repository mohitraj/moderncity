# patch_add_tables.py
import sqlite3
DB_PATH = 'maintenance.db'
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'editor'
)''')
c.execute('''CREATE TABLE IF NOT EXISTS expenditures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month TEXT NOT NULL,
    date TEXT,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    reason TEXT,
    created_by TEXT
)''')
conn.commit()
conn.close()
print("Patched DB with users and expenditures tables.")
