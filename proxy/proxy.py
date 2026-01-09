import asyncio
import base64
import sqlite3
import json
import os
import time
import re
from datetime import datetime
from enum import Enum

# --- Configuration ---
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "445")) 
TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1") 
TARGET_PORT = int(os.getenv("TARGET_PORT", "44445"))
DB_PATH = os.getenv("DB_PATH", "honeypot.db")

# FIX: Inicjalizacja jako None. Prawdziwa kolejka powstanie w main()
log_queue = None

class TrafficDirection(str, Enum):
    CLIENT_TO_SERVER = "clientToServer"
    SERVER_TO_CLIENT = "serverToClient"

# --- Global State ---
CONNECTION_HISTORY = {}
LOGIN_FAILURE_HISTORY = {}

# Constants
HISTORY_WINDOW = 60
BRUTE_FORCE_THRESHOLD = 10
SCANNING_THRESHOLD = 20

# --- Database Management ---
def init_db():
    try:
        # Upewnij się, że katalog istnieje
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                day TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                event_type TEXT,
                raw TEXT,
                parsed TEXT,
                classification TEXT,
                confidence REAL,
                details TEXT,
                headers TEXT
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS daily_summary (
                day TEXT PRIMARY KEY,
                total_events INTEGER,
                by_class TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print(f"[*] Database initialized at {DB_PATH}")
    except Exception as e:
        print(f"[!] DB Init Error: {e}")

async def log_worker():
    while True:
        # Tutaj log_queue już będzie zainicjalizowane w main
        record = await log_queue.get()
        try:
            await asyncio.to_thread(sync_save, record)
        except Exception as e:
            print(f"[!] Log Worker Error: {e}")
        finally:
            log_queue.task_done()

def update_daily_summary(cur, day_str):
    """
    Recalculates summary for the given day based on logs and updates daily_summary table.
    """
    # 1. Pobierz ogólną liczbę zdarzeń oraz czas pierwszego i ostatniego zdarzenia
    cur.execute('''
        SELECT COUNT(*), MIN(timestamp), MAX(timestamp) 
        FROM logs 
        WHERE day = ?
    ''', (day_str,))
    row = cur.fetchone()
    total_events = row[0]
    first_seen = row[1]
    last_seen = row[2]

    # 2. Pobierz podział na klasy ataków
    cur.execute('''
        SELECT classification, COUNT(*) 
        FROM logs 
        WHERE day = ? 
        GROUP BY classification
    ''', (day_str,))
    
    stats = dict(cur.fetchall())
    by_class_json = json.dumps(stats)

    # 3. Wstaw lub Nadpisz (Upsert) w tabeli daily_summary
    cur.execute('''
        INSERT OR REPLACE INTO daily_summary 
        (day, total_events, by_class, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
    ''', (day_str, total_events, by_class_json, first_seen, last_seen))

def sync_save(rec):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        day_str = rec['ts'][:10] 
        
        # A. Insert log
        cur.execute('''INSERT INTO logs 
            (timestamp, day, src_ip, src_port, dst_port, protocol, 
             event_type, raw, parsed, classification, confidence, details, headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (rec['ts'], day_str, rec['ip'], rec['port'], TARGET_PORT, 'SMB',
             rec['type'], rec['raw'], rec['parsed'], rec['class'], rec['conf'], rec['det'], rec['headers']))
        
        # B. Update Summary
        update_daily_summary(cur, day_str)

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Save Error: {e}")

def update_connection_metrics(ip):
    now = time.time()
    if ip not in CONNECTION_HISTORY:
        CONNECTION_HISTORY[ip] = []
    CONNECTION_HISTORY[ip].append(now)
    CONNECTION_HISTORY[ip] = [t for t in CONNECTION_HISTORY[ip] if now - t < HISTORY_WINDOW]
    return len(CONNECTION_HISTORY[ip])

def analyze_traffic(data, direction: TrafficDirection, ip):
    details = {}
    cls = "benign"
    conf = 0.0
    decoded_str = ""
    
    try:
        decoded_str = data.decode('utf-8', errors='ignore').lower()
        
        if direction == TrafficDirection.CLIENT_TO_SERVER:
            if any(p in decoded_str for p in ["union select", "drop table", "' or '1'='1"]):
                details["pattern"] = "SQL keyword detected"
                return "sql_injection", 0.95, details
            if any(p in decoded_str for p in ["cmd.exe", "/bin/sh", "powershell"]):
                details["pattern"] = "Shell command detected"
                return "command_injection", 1.0, details
            if ".exe" in decoded_str or "mz" in decoded_str[:5]:
                details["pattern"] = "Binary executable header"
                return "file_upload_malicious", 0.8, details

        elif direction == TrafficDirection.SERVER_TO_CLIENT:
            if b"\x6d\x00\x00\xc0" in data: 
                current_fails = LOGIN_FAILURE_HISTORY.get(ip, 0) + 1
                LOGIN_FAILURE_HISTORY[ip] = current_fails
                details["failed_logins"] = current_fails
                if current_fails >= 5: return "brute_force", 1.0, details
                else: return "auth_failed", 0.5, details

    except Exception as e:
        return "unknown", 0.0, {"error": str(e)}
    
    return cls, conf, details

async def forward(reader, writer, ip, port, direction: TrafficDirection):
    try:
        while True:
            data = await reader.read(65536)
            if not data: break
            writer.write(data)
            await writer.drain()
            try:
                cls, conf, det = analyze_traffic(data, direction, ip)
                parsed = data.decode('utf-8', errors='ignore')
                if not parsed.isprintable() or len(parsed) < 5: parsed = f"HEX: {data.hex()[:20]}..."
                
                if log_queue:
                    log_queue.put_nowait({
                        'ts': datetime.utcnow().isoformat() + 'Z', 'ip': ip, 'port': port, 
                        'type': f'data_{direction.value}', 
                        'raw': base64.b64encode(data).decode('ascii'), 'parsed': parsed,
                        'class': cls, 'conf': conf, 'det': json.dumps(det), 'headers': '{}'
                    })
            except Exception as e: pass
    except: pass 
    finally:
        try: writer.close(); await writer.wait_closed()
        except: pass

async def handle_client(c_reader, c_writer):
    peer = c_writer.get_extra_info('peername')
    ip, port = peer if peer else ("unknown", 0)
    conn_count = update_connection_metrics(ip)
    vol_class = "scanning" if conn_count >= SCANNING_THRESHOLD else "benign"
    
    if log_queue:
        log_queue.put_nowait({
            'ts': datetime.utcnow().isoformat() + 'Z', 'ip': ip, 'port': port, 'type': 'connection_open', 
            'raw': '', 'parsed': 'New TCP Connection',
            'class': vol_class, 'conf': 0.0, 'det': json.dumps({"count": conn_count}), 'headers': '{}'
        })

    try:
        s_reader, s_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        await asyncio.gather(
            forward(c_reader, s_writer, ip, port, TrafficDirection.CLIENT_TO_SERVER),
            forward(s_reader, c_writer, ip, port, TrafficDirection.SERVER_TO_CLIENT),
            return_exceptions=True
        )
    except Exception as e:
        print(f"[!] Handle Client Error ({ip}): {e}")
    finally:
        try: c_writer.close(); await c_writer.wait_closed()
        except: pass

async def main():
    # --- FIX CRITICAL: Initialize Queue inside the loop ---
    global log_queue
    log_queue = asyncio.Queue()
    
    print(f"[*] Initializing SMB Honeypot Proxy...")
    init_db()
    
    # Uruchom workera
    asyncio.create_task(log_worker())
    
    try:
        server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
        print(f"[*] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[*] Forwarding to -> {TARGET_HOST}:{TARGET_PORT}")
        
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"[!] Server Startup Error: {e}")

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass