#!/usr/bin/env python3
"""
Script to add 2026 month records to the maintenance database.
Run this after updating the MONTHS list in app.py
"""

import sqlite3

DB_PATH = 'maintenance.db'
TOTAL_HOUSES = 60

# New months to add for 2026
NEW_MONTHS_2026 = [
    '2026-01',
    '2026-02',
    '2026-03',
    '2026-04',
    '2026-05',
    '2026-06',
    '2026-07',
    '2026-08',
    '2026-09',
    '2026-10',
    '2026-11',
    '2026-12'
]

def add_2026_months():
    """Add records for all houses for each month in 2026"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if records table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='records'")
    if not cursor.fetchone():
        print("Error: 'records' table not found in database!")
        conn.close()
        return
    
    total_inserted = 0
    already_exists = 0
    
    for month in NEW_MONTHS_2026:
        print(f"\nProcessing month: {month}")
        
        for house in range(1, TOTAL_HOUSES + 1):
            # Check if record already exists
            cursor.execute(
                'SELECT id FROM records WHERE house_number = ? AND month = ?',
                (house, month)
            )
            
            if cursor.fetchone():
                already_exists += 1
                continue
            
            # Insert new record with NULL date_paid and amount
            try:
                cursor.execute(
                    'INSERT INTO records (house_number, month, date_paid, amount) VALUES (?, ?, NULL, NULL)',
                    (house, month)
                )
                total_inserted += 1
            except sqlite3.Error as e:
                print(f"Error inserting record for house {house}, month {month}: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"\n{'='*60}")
    print(f"Database update complete!")
    print(f"Total records inserted: {total_inserted}")
    print(f"Records already existed: {already_exists}")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    print("=" * 60)
    print("Adding 2026 month records to maintenance database")
    print("=" * 60)
    
    response = input("\nThis will add records for Jan-Dec 2026. Continue? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        add_2026_months()
        print("Done! You can now use the 2026 months in your application.")
    else:
        print("Operation cancelled.")