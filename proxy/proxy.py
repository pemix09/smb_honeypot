import asyncio
import base64
import sqlite3
import json
import os
import time
from datetime import datetime

# --- Configuration ---
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "445")) # Default SMB port
TARGET_HOST = os.getenv("TARGET_HOST", "vuln_smb") # Vulnerable container hostname
TARGET_PORT = int(os.getenv("TARGET_PORT", "445"))
DB_PATH = os.getenv("DB_PATH", "/app/data/honeypot.db")

# Queue for asynchronous logging to prevent I/O blocking
log_queue = asyncio.Queue()

# --- Volumetric Attack Detection (Stateful) ---
# Dictionary to track connection timestamps per IP: { "192.168.1.5": [ts1, ts2, ...] }
CONNECTION_HISTORY = {}
HISTORY_WINDOW = 60  # seconds
BRUTE_FORCE_THRESHOLD = 10
SCANNING_THRESHOLD = 20

def init_db():
    """
    Initializes the SQLite database with the schema required by the assignment.
    Creates 'logs' and 'daily_summary' tables.
    """
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Table: logs (Strictly following the assignment schema)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                day TEXT,                 -- Required: YYYY-MM-DD for aggregation
                src_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                event_type TEXT,
                raw TEXT,
                parsed TEXT,              -- Required: Normalized text
                classification TEXT,      -- Required: Specific attack tags
                confidence REAL,
                details TEXT,
                headers TEXT              -- Required: JSON headers (even for non-HTTP)
            )
        ''')

        # Table: daily_summary (Required by assignment)
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
        print(f"[!] Critical Database Init Error: {e}")

async def log_worker():
    """
    Background worker that consumes log records from the queue and writes them to SQLite.
    This ensures that database latency does not slow down network traffic.
    """
    while True:
        record = await log_queue.get()
        try:
            await asyncio.to_thread(sync_save, record)
        except Exception as e:
            print(f"[!] Log Worker Error: {e}")
        finally:
            log_queue.task_done()

def sync_save(rec):
    """
    Synchronous function to perform the actual SQL INSERT.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        
        # Extract YYYY-MM-DD from timestamp for the 'day' column
        day_str = rec['ts'][:10] 
        
        cur.execute('''INSERT INTO logs 
            (timestamp, day, src_ip, src_port, dst_port, protocol, 
             event_type, raw, parsed, classification, confidence, details, headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (
                rec['ts'], 
                day_str, 
                rec['ip'], 
                rec['port'], 
                TARGET_PORT, 
                'SMB',           # Protocol
                rec['type'],     # event_type
                rec['raw'],      # raw base64 payload
                rec['parsed'],   # parsed text
                rec['class'],    # classification
                rec['conf'],     # confidence
                rec['det'],      # details JSON
                rec['headers']   # headers JSON
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] SQLite Sync Save Error: {e}")

def check_volumetric_anomalies(ip):
    """
    Checks for Brute Force or Scanning attempts based on connection frequency.
    Implements a sliding window counter.
    """
    now = time.time()
    
    # Initialize history for new IP
    if ip not in CONNECTION_HISTORY:
        CONNECTION_HISTORY[ip] = []
    
    # Add current connection timestamp
    CONNECTION_HISTORY[ip].append(now)
    
    # Prune timestamps older than the window (60s)
    CONNECTION_HISTORY[ip] = [t for t in CONNECTION_HISTORY[ip] if now - t < HISTORY_WINDOW]
    
    count = len(CONNECTION_HISTORY[ip])
    
    # Classification logic based on thresholds
    if count >= SCANNING_THRESHOLD:
        return "scanning", 0.8, {"connection_count_60s": count}
    elif count >= BRUTE_FORCE_THRESHOLD:
        return "brute_force", 0.9, {"connection_count_60s": count}
    
    return "benign", 0.0, {}

def analyze_payload(data):
    """
    Analyzes raw payload content to detect specific attack patterns.
    Maps findings to required classification tags: sql_injection, command_injection, etc.
    """
    try:
        # SMB is binary, but exploits often contain readable strings.
        # We use errors='ignore' to extract whatever text is possible.
        decoded_str = data.decode('utf-8', errors='ignore').lower()
        
        # 1. Check for SQL Injection
        sql_patterns = ["union select", "drop table", "' or '1'='1", "information_schema"]
        if any(p in decoded_str for p in sql_patterns):
            return "sql_injection", 0.95, {"pattern": "SQL keyword detected"}

        # 2. Check for Command Injection / RCE
        cmd_patterns = ["cmd.exe", "/bin/sh", "/bin/bash", "powershell", "wget ", "curl "]
        if any(p in decoded_str for p in cmd_patterns):
            return "command_injection", 1.0, {"pattern": "Shell command detected"}

        # 3. Check for Malicious File Upload (based on extensions or headers)
        if ".exe" in decoded_str or "mz" in decoded_str[:5]: # MZ is the header for Windows executables
            return "file_upload_malicious", 0.7, {"pattern": "Binary executable header"}
        
        # 4. Check for path traversal / sensitive files
        if "/etc/passwd" in decoded_str or "c:\\windows" in decoded_str:
            return "command_injection", 0.8, {"pattern": "Sensitive path access"}

        # 5. Protocol specific: SMBv1 detection (Legacy/Dangerous)
        if b"\xffSMB" in data:
            return "scanning", 0.5, {"info": "Legacy SMBv1 negotiation attempt"}

    except Exception as e:
        return "unknown", 0.0, {"error": str(e)}
    
    return "unknown", 0.0, {}

async def forward(reader, writer, ip, port, direction):
    """
    Forwards data between Client and Target while logging the traffic.
    """
    try:
        while True:
            try:
                # Read data chunk
                data = await reader.read(65536)
                if not data:
                    break
                
                # Forward immediately to minimize latency
                writer.write(data)
                await writer.drain()
                
                # --- Analysis & Logging ---
                # Determine classification based on payload content
                cls, conf, det = analyze_payload(data)
                
                # Prepare parsed representation (readable string or hex)
                parsed_content = data.decode('utf-8', errors='ignore')
                # If parsed content is empty or garbage, use hex representation
                if len(parsed_content) < 5 or not parsed_content.isprintable():
                     parsed_content = f"HEX: {data.hex()[:50]}..."

                log_queue.put_nowait({
                    'ts': datetime.utcnow().isoformat() + 'Z',
                    'ip': ip, 
                    'port': port, 
                    'type': f'data_{direction}',
                    'raw': base64.b64encode(data).decode('ascii'), # Store raw binary as Base64
                    'parsed': parsed_content,
                    'class': cls, 
                    'conf': conf, 
                    'det': json.dumps(det),
                    'headers': '{}' # SMB has no HTTP headers, storing empty JSON
                })

            except Exception as e:
                print(f"[!] Data Forwarding Error ({direction}): {e}")
                break
                
    except Exception as e:
        print(f"[!] General Forward Loop Error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def handle_client(c_reader, c_writer):
    """
    Handles incoming TCP connections.
    1. Checks for volumetric attacks (Brute Force/Scanning).
    2. Connects to the vulnerable target.
    3. Starts bi-directional forwarding.
    """
    peer = c_writer.get_extra_info('peername')
    ip, port = peer if peer else ("unknown", 0)
    
    # --- Step 1: Volumetric Analysis (Stateful) ---
    vol_class, vol_conf, vol_det = check_volumetric_anomalies(ip)
    
    # Log the connection event
    log_queue.put_nowait({
        'ts': datetime.utcnow().isoformat() + 'Z',
        'ip': ip, 'port': port,
        'type': 'connection_open', 
        'raw': '', 'parsed': 'New TCP Connection',
        'class': vol_class, # Apply volumetric classification here (e.g., brute_force)
        'conf': vol_conf, 
        'det': json.dumps(vol_det),
        'headers': '{}'
    })

    try:
        # --- Step 2: Connect to Vulnerable Target ---
        s_reader, s_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        
        # --- Step 3: Bidirectional Forwarding ---
        await asyncio.gather(
            forward(c_reader, s_writer, ip, port, 'c2s'), # Client to Server
            forward(s_reader, c_writer, ip, port, 's2c'), # Server to Client
            return_exceptions=True
        )
    except Exception as e:
        print(f"[!] Connection Handler Error ({ip}): {e}")
        log_queue.put_nowait({
            'ts': datetime.utcnow().isoformat() + 'Z', 'ip': ip, 'port': port,
            'type': 'connection_failed', 'raw': '', 'parsed': str(e),
            'class': 'error', 'conf': 0.0, 'det': '{}', 'headers': '{}'
        })
    finally:
        try:
            c_writer.close()
            await c_writer.wait_closed()
        except:
            pass

async def main():
    print(f"[*] Initializing SMB Honeypot Proxy...")
    init_db()
    
    # Start the DB logger worker in the background
    asyncio.create_task(log_worker())
    
    try:
        server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
        print(f"[*] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[*] Forwarding to -> {TARGET_HOST}:{TARGET_PORT}")
        print(f"[*] Mode: Stateful Analysis (Volumetric + Payload)")
        
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"[!] Server Startup Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down proxy...")