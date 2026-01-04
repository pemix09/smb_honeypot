import sqlite3
import csv
import os
import sys

# Ścieżki wewnątrz kontenera (zmapowane w docker-compose)
DB_FILE = "/app/data/honeypot.db"
CSV_FILE = "/app/data/dataset.csv"

def export_to_csv():
    print(f"🔄 Rozpoczynam eksport danych...")
    print(f"   Baza: {DB_FILE}")
    print(f"   Cel:  {CSV_FILE}")

    # Sprawdzenie czy baza istnieje
    if not os.path.exists(DB_FILE):
        print(f"❌ Błąd: Nie znaleziono pliku bazy danych {DB_FILE}.")
        print("   Upewnij się, że honeypot (Rust) działa i odebrał jakieś pakiety.")
        sys.exit(1)

    try:
        # Połączenie z bazą
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Pobieramy wszystkie logi
        cursor.execute("SELECT * FROM logs ORDER BY id ASC")
        rows = cursor.fetchall()

        if not rows:
            print("ℹ️  Baza danych jest pusta. Brak rekordów do eksportu.")
            conn.close()
            return

        # Pobieramy nazwy kolumn
        column_names = [description[0] for description in cursor.description]

        # Zapisujemy do CSV (nadpisujemy stary plik)
        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(column_names) # Nagłówki
            writer.writerows(rows)        # Dane

        print(f"✅ Sukces! Wyeksportowano {len(rows)} wierszy.")
        print(f"   Plik gotowy: data/dataset.csv")

        conn.close()

    except sqlite3.Error as e:
        print(f"❌ Błąd SQLite: {e}")
    except IOError as e:
        print(f"❌ Błąd zapisu pliku: {e}")

if __name__ == "__main__":
    export_to_csv()