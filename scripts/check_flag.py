#!/usr/bin/env python3
import subprocess
import os
import sqlite3
import argparse

def query_db(db_path):
    if not os.path.exists(db_path):
        print(f'\n[!] Baza danych nie znaleziona: {db_path}')
        return
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print('\n' + '='*60)
    print(' RAPORT PROXY: OSTATNIE ZAREJESTROWANE AKCJE')
    print('='*60)
    
    # Pobieramy ostatnie logi, sprawdzając czy są powiązane z flagą
    query = """
        SELECT timestamp, src_ip, event_type, classification, details 
        FROM logs 
        ORDER BY id DESC LIMIT 15
    """
    cur.execute(query)
    for row in cur.fetchall():
        ts, ip, ev_type, cls, det = row
        color = "!" if "flag" in str(det).lower() else "*"
        print(f"[{ts}] {ip} | {ev_type} | {cls}")
        if det and det != '{}':
            print(f"    [{color}] Details: {det}")

    conn.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('ip', nargs='?', default='127.0.0.1')
    p.add_argument('--port', type=int, default=4445) # Domyślnie 4445 dla macOS
    p.add_argument('--share', default='share')
    p.add_argument('--db', default='./data/honeypot.db')
    args = p.parse_args()

    print(f"[*] Rozpoczynam test za pomocą smbclient na {args.ip}:{args.port}...")

    # Przygotowanie polecenia smbclient
    # -p: port, -U: użytkownik (guest%guest), -c: komenda do wykonania
    smb_cmd = [
        "smbclient",
        f"//{args.ip}/{args.share}",
        "-p", str(args.port),
        "-U", "guest%guest",
        "-c", "get FLAG.txt downloaded_FLAG.txt"
    ]

    try:
        # Uruchomienie smbclient
        result = subprocess.run(smb_cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print("[+] SUKCES: smbclient pomyślnie pobrał plik.")
            if os.path.exists("downloaded_FLAG.txt"):
                with open("downloaded_FLAG.txt", "r") as f:
                    print(f"\n--- TREŚĆ FLAGI ---\n{f.read()}\n-------------------")
        else:
            print("[-] BŁĄD smbclient:")
            print(result.stderr)
            
    except FileNotFoundError:
        print("[!] BŁĄD: smbclient nie jest zainstalowany na tym systemie.")
    except Exception as e:
        print(f"[-] Wystąpił nieoczekiwany błąd: {e}")

    # Wyświetlenie logów z bazy danych
    query_db(args.db)

if __name__ == "__main__":
    main()