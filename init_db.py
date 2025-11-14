import sqlite3
import os

DB_PATH = 'maintenance.db'
MONTHS = [('2025-08', 'August 2025'), ('2025-09', 'September 2025'), ('2025-10', 'October 2025'), ('2025-11', 'November 2025'), ('2025-12', 'December 2025')]
TOTAL_HOUSES = 60

def init_db_once():
    if os.path.exists(DB_PATH):
        print("Database already exists.")
        #return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS additions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month TEXT NOT NULL,
    date TEXT,
    amount INTEGER NOT NULL,
    type TEXT,
    reason TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
    )
    ''')
    conn.commit()
    for mkey, _ in MONTHS:
        for house in range(1, TOTAL_HOUSES+1):
            c.execute('INSERT INTO records (house_number, month, date_paid, amount) VALUES (?, ?, ?, ?)', (house, mkey, None, None))
    conn.commit()
    conn.close()
    print("Database created and seeded.")
"""
def expend():
    #import sqlite3
    #DB_PATH = 'maintenance.db'
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
"""
def main():
    init_db_once()
    expend()
if __name__ == '__main__':
    init_db_once()

