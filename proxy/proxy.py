import asyncio
import base64
import sqlite3
import json
import os
import time
import re
from datetime import datetime
from enum import Enum

# --- [DEMO POINT 1] Configuration ---
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "445")) 
TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1") # Changed to localhost for easier testing
TARGET_PORT = int(os.getenv("TARGET_PORT", "44445")) # Port of the dummy target
DB_PATH = os.getenv("DB_PATH", "honeypot.db")

log_queue = asyncio.Queue()

# --- [DEMO POINT 2] Enum Implementation ---
# Using Enums ensures type safety and consistency in the database
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
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # --- [DEMO POINT 7] Database Schema ---
        cur.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                day TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                event_type TEXT, -- This will hold our Enum values
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
        record = await log_queue.get()
        try:
            await asyncio.to_thread(sync_save, record)
        except Exception as e:
            print(f"[!] Log Worker Error: {e}")
        finally:
            log_queue.task_done()

def sync_save(rec):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        day_str = rec['ts'][:10] 
        cur.execute('''INSERT INTO logs 
            (timestamp, day, src_ip, src_port, dst_port, protocol, 
             event_type, raw, parsed, classification, confidence, details, headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (rec['ts'], day_str, rec['ip'], rec['port'], TARGET_PORT, 'SMB', 
             rec['type'], rec['raw'], rec['parsed'], rec['class'], rec['conf'], rec['det'], rec['headers']))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Save Error: {e}")

# --- [DEMO POINT 4] Volumetric Analysis (Scanning) ---
def update_connection_metrics(ip):
    now = time.time()
    if ip not in CONNECTION_HISTORY:
        CONNECTION_HISTORY[ip] = []
    CONNECTION_HISTORY[ip].append(now)
    # Keep only timestamps from the last 60 seconds
    CONNECTION_HISTORY[ip] = [t for t in CONNECTION_HISTORY[ip] if now - t < HISTORY_WINDOW]
    return len(CONNECTION_HISTORY[ip])

# --- [DEMO POINT 3] DPI (Deep Packet Inspection) ---
def analyze_traffic(data, direction: TrafficDirection, ip):
    details = {}
    cls = "benign"
    conf = 0.0
    decoded_str = ""
    
    try:
        decoded_str = data.decode('utf-8', errors='ignore').lower()
        
        # --- [DEMO POINT 3A] Client -> Server Attacks ---
        if direction == TrafficDirection.CLIENT_TO_SERVER:
            
            # SQL Injection Detection
            sql_patterns = ["union select", "drop table", "' or '1'='1", "information_schema"]
            if any(p in decoded_str for p in sql_patterns):
                details["pattern"] = "SQL keyword detected"
                return "sql_injection", 0.95, details

            # Command Injection (RCE) Detection
            cmd_patterns = ["cmd.exe", "/bin/sh", "/bin/bash", "powershell"]
            if any(p in decoded_str for p in cmd_patterns):
                details["pattern"] = "Shell command detected"
                return "command_injection", 1.0, details

            # Malicious File Header Detection (MZ = .exe)
            if ".exe" in decoded_str or "mz" in decoded_str[:5]:
                details["pattern"] = "Binary executable header"
                return "file_upload_malicious", 0.8, details

        # --- [DEMO POINT 3B] Server -> Client Responses ---
        elif direction == TrafficDirection.SERVER_TO_CLIENT:
            # Login Failure Confirmation
            if b"\x6d\x00\x00\xc0" in data: # STATUS_LOGON_FAILURE
                current_fails = LOGIN_FAILURE_HISTORY.get(ip, 0) + 1
                LOGIN_FAILURE_HISTORY[ip] = current_fails
                details["failed_logins"] = current_fails
                if current_fails >= 5:
                     return "brute_force", 1.0, details
                else:
                     return "auth_failed", 0.5, details

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
            
            # --- [DEMO POINT 6] Async Logging ---
            try:
                cls, conf, det = analyze_traffic(data, direction, ip)
                parsed_content = data.decode('utf-8', errors='ignore')
                if len(parsed_content) < 5 or not parsed_content.isprintable():
                     parsed_content = f"HEX: {data.hex()[:50]}..."

                # We use direction.value to store 'clientToServer' in DB
                log_queue.put_nowait({
                    'ts': datetime.utcnow().isoformat() + 'Z',
                    'ip': ip, 'port': port, 
                    'type': f'data_{direction.value}', 
                    'raw': base64.b64encode(data).decode('ascii'),
                    'parsed': parsed_content,
                    'class': cls, 'conf': conf, 'det': json.dumps(det), 'headers': '{}'
                })
            except Exception: pass
    except Exception: pass 
    finally:
        try: writer.close(); await writer.wait_closed()
        except: pass

async def handle_client(c_reader, c_writer):
    peer = c_writer.get_extra_info('peername')
    ip, port = peer if peer else ("unknown", 0)
    
    # Volumetric Check
    conn_count = update_connection_metrics(ip)
    vol_class = "scanning" if conn_count >= SCANNING_THRESHOLD else "benign"
    
    # Log Connection Open
    log_queue.put_nowait({
        'ts': datetime.utcnow().isoformat() + 'Z',
        'ip': ip, 'port': port, 'type': 'connection_open', 
        'raw': '', 'parsed': 'New TCP Connection',
        'class': vol_class, 'conf': 0.0, 'det': json.dumps({"count": conn_count}), 'headers': '{}'
    })

    try:
        # --- [DEMO POINT 5] Proxy Connection Setup ---
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
    print(f"[*] Initializing SMB Honeypot Proxy...")
    init_db()
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