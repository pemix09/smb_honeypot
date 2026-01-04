import sqlite3
import csv
import os
import sys

# Paths inside the container (mapped in docker-compose)
DB_FILE = "/app/data/honeypot.db"
CSV_FILE = "/app/data/dataset.csv"

def export_to_csv():
    print(f"🔄 Starting data export...")
    print(f"   Database: {DB_FILE}")
    print(f"   Destination: {CSV_FILE}")

    # Check if the database exists
    if not os.path.exists(DB_FILE):
        print(f"❌ Error: Database file {DB_FILE} not found.")
        print("   Make sure the honeypot (Rust) is running and has received some packets.")
        sys.exit(1)

    try:
        # Database connection
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Fetch all logs
        cursor.execute("SELECT * FROM logs ORDER BY id ASC")
        rows = cursor.fetchall()

        if not rows:
            print("ℹ️  The database is empty. No records to export.")
            conn.close()
            return

        # Fetch column names
        column_names = [description[0] for description in cursor.description]

        # Save to CSV (overwrites existing file)
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(column_names) # Headers
            writer.writerows(rows)        # Data

        print(f"✅ Success! Exported {len(rows)} rows.")
        print(f"   File ready: data/dataset.csv")

        conn.close()

    except sqlite3.Error as e:
        print(f"❌ SQLite Error: {e}")
    except IOError as e:
        print(f"❌ File Write Error: {e}")

if __name__ == "__main__":
    export_to_csv()