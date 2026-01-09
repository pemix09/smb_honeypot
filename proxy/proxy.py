import asyncio
import base64
import sqlite3
import json
import os
import time
import re
from datetime import datetime

# --- Configuration ---
# Load configuration from environment variables (Docker friendly)
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "445")) # Default SMB port
TARGET_HOST = os.getenv("TARGET_HOST", "vuln_smb") # Hostname of the vulnerable container
TARGET_PORT = int(os.getenv("TARGET_PORT", "445"))
DB_PATH = os.getenv("DB_PATH", "/app/data/honeypot.db")

# Queue for asynchronous logging to prevent I/O blocking
log_queue = asyncio.Queue()

# --- Global State (In-Memory) ---
# 1. Connection History: { "192.168.1.5": [timestamp1, timestamp2, ...] }
#    Used for volumetric analysis (scanning/DoS detection).
CONNECTION_HISTORY = {}

# 2. Login Failure History: { "192.168.1.5": count }
#    Used to track specific SMB login failures confirmed by the server.
LOGIN_FAILURE_HISTORY = {}

# Heuristic Constants
HISTORY_WINDOW = 60  # seconds
BRUTE_FORCE_THRESHOLD = 10
SCANNING_THRESHOLD = 20

# --- Database Management ---

def init_db():
    """
    Initializes the SQLite database with the schema strictly required by the assignment.
    Creates 'logs' and 'daily_summary' tables.
    """
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Table: logs
        cur.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                day TEXT,                 -- Required: YYYY-MM-DD
                src_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                event_type TEXT,
                raw TEXT,
                parsed TEXT,              -- Required: Normalized text
                classification TEXT,      -- Required: Attack tag (e.g., brute_force)
                confidence REAL,
                details TEXT,             -- JSON details
                headers TEXT              -- Required: JSON headers
            )
        ''')

        # Table: daily_summary (Required by assignment schema)
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
    Separating I/O ensures network traffic is not delayed by disk writes.
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
        
        # Extract YYYY-MM-DD for the 'day' column
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
                'SMB',           # Protocol hardcoded for this proxy
                rec['type'], 
                rec['raw'], 
                rec['parsed'], 
                rec['class'], 
                rec['conf'], 
                rec['det'], 
                rec['headers']
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] SQLite Sync Save Error: {e}")

# --- Heuristics & Analysis ---

def update_connection_metrics(ip):
    """
    Updates connection counters for volumetric analysis.
    Returns the number of connections in the last 60 seconds.
    """
    now = time.time()
    if ip not in CONNECTION_HISTORY:
        CONNECTION_HISTORY[ip] = []
    
    # Add new timestamp
    CONNECTION_HISTORY[ip].append(now)
    
    # Prune old timestamps
    CONNECTION_HISTORY[ip] = [t for t in CONNECTION_HISTORY[ip] if now - t < HISTORY_WINDOW]
    
    return len(CONNECTION_HISTORY[ip])

def analyze_traffic(data, direction, ip):
    """
    Deep Packet Inspection (DPI) & Response Analysis.
    Combines string matching, UTF-16 extraction (for usernames), and server error codes.
    
    Args:
        data: Raw bytes.
        direction: 'c2s' (Client->Server) or 's2c' (Server->Client).
        ip: Source IP address.
        
    Returns:
        (classification, confidence, details_dict)
    """
    details = {}
    cls = "benign"
    conf = 0.0
    
    # --- 0. PRE-PROCESSING: String Extraction (UTF-8 & Windows UTF-16) ---
    decoded_str = ""
    try:
        # Standard decoding for exploit signatures
        decoded_str = data.decode('utf-8', errors='ignore').lower()
        
        # ADVANCED: Try to extract usernames/filenames from SMB binary (UTF-16LE)
        # This helps in identifying what username was used in Brute Force
        if direction == 'c2s':
            try:
                raw_utf16 = data.decode('utf-16le', errors='ignore')
                # Regex to find alphanumeric strings between 4 and 20 chars
                potential_strings = re.findall(r'[a-zA-Z0-9_]{4,20}', raw_utf16)
                
                # Filter out common protocol noise
                ignore_list = ['smb', 'ntlm', 'windows', 'workgroup', 'lanman', 'unicode', 'samba']
                filtered = [s for s in potential_strings if s.lower() not in ignore_list]
                
                if filtered:
                    # Save top 5 unique strings found (likely usernames or file paths)
                    details['strings_found'] = list(set(filtered))[:5]
            except: 
                pass
    except: 
        pass

    try:
        # --- 1. Client to Server Analysis (Attack Patterns) ---
        if direction == 'c2s':
            # A. SQL Injection signatures
            sql_patterns = ["union select", "drop table", "' or '1'='1", "information_schema"]
            if any(p in decoded_str for p in sql_patterns):
                details["pattern"] = "SQL keyword detected"
                return "sql_injection", 0.95, details

            # B. Command Injection / RCE signatures
            cmd_patterns = ["cmd.exe", "/bin/sh", "/bin/bash", "powershell", "wget ", "curl ", "; ls", "| nc"]
            if any(p in decoded_str for p in cmd_patterns):
                details["pattern"] = "Shell command detected"
                return "command_injection", 1.0, details

            # C. Malicious File Upload (Binary headers or extensions)
            if ".exe" in decoded_str or "mz" in decoded_str[:5]: # MZ is the magic bytes for Windows Executables
                details["pattern"] = "Binary executable header"
                return "file_upload_malicious", 0.8, details
            
            # D. Legacy Protocol Detection (Scanning/Recon)
            if b"\xffSMB" in data:
                details["info"] = "Legacy SMBv1 negotiation attempt"
                return "scanning", 0.5, details

        # --- 2. Server to Client Analysis (Response Verification) ---
        elif direction == 's2c':
            # A. SQL Error in response (Increases confidence of SQLi)
            sql_errors = ["sql syntax", "mysql_fetch", "ora-009", "syntax error"]
            if any(e in decoded_str for e in sql_errors):
                details["info"] = "Server responded with SQL Error - Attack Confirmed"
                return "sql_injection", 1.0, details

            # B. SMB Login Failure Detection (0xC000006D = STATUS_LOGON_FAILURE)
            # This byte sequence indicates the server rejected the password/username.
            if b"\x6d\x00\x00\xc0" in data:
                # Increment failure count for this IP
                current_fails = LOGIN_FAILURE_HISTORY.get(ip, 0) + 1
                LOGIN_FAILURE_HISTORY[ip] = current_fails
                
                details["failed_logins"] = current_fails
                details["info"] = "Server confirmed login failures"
                
                # Heuristic: If multiple failures occur, suspect brute-force with dictionary
                if current_fails >= 5:
                     details["heuristic"] = "multiple_usernames_or_passwords_suspected"
                     return "brute_force", 1.0, details
                else:
                     return "auth_failed", 0.5, details

    except Exception as e:
        return "unknown", 0.0, {"error": str(e)}
    
    return cls, conf, details

# --- Networking & Forwarding ---

async def forward(reader, writer, ip, port, direction):
    """
    Forwards data between Client and Target, intercepting for analysis.
    """
    try:
        while True:
            # Read chunk
            data = await reader.read(65536)
            if not data:
                break
            
            # Forward immediately (Minimize latency)
            writer.write(data)
            await writer.drain()
            
            # --- Analysis & Logging ---
            try:
                cls, conf, det = analyze_traffic(data, direction, ip)
                
                # Normalize payload for display
                parsed_content = data.decode('utf-8', errors='ignore')
                # If content is binary/garbage, use Hex representation
                if len(parsed_content) < 5 or not parsed_content.isprintable():
                     parsed_content = f"HEX: {data.hex()[:50]}..."

                # We log everything. 'benign' events have 0 confidence.
                log_queue.put_nowait({
                    'ts': datetime.utcnow().isoformat() + 'Z',
                    'ip': ip, 
                    'port': port, 
                    'type': f'data_{direction}',
                    'raw': base64.b64encode(data).decode('ascii'),
                    'parsed': parsed_content,
                    'class': cls, 
                    'conf': conf, 
                    'det': json.dumps(det),
                    'headers': '{}' # SMB has no HTTP headers
                })
            except Exception as log_err:
                print(f"[!] Log Queue Error: {log_err}")

    except Exception as e:
        # Connection closed or reset
        pass 
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def handle_client(c_reader, c_writer):
    """
    Main TCP Handler.
    1. Performs Volumetric Analysis (Connection Counting).
    2. Connects to the vulnerable target.
    3. Spawns forwarding tasks.
    """
    peer = c_writer.get_extra_info('peername')
    ip, port = peer if peer else ("unknown", 0)
    
    # --- Step 1: Volumetric Analysis (Stateful) ---
    conn_count = update_connection_metrics(ip)
    
    # Determine initial classification based on connection rate
    vol_class, vol_conf, vol_det = "benign", 0.0, {}
    
    if conn_count >= SCANNING_THRESHOLD:
        vol_class, vol_conf = "scanning", 0.8
        vol_det = {"connection_count_60s": conn_count}
    elif conn_count >= BRUTE_FORCE_THRESHOLD:
        vol_class, vol_conf = "brute_force", 0.9
        vol_det = {"connection_count_60s": conn_count}

    # Log the new connection
    log_queue.put_nowait({
        'ts': datetime.utcnow().isoformat() + 'Z',
        'ip': ip, 'port': port,
        'type': 'connection_open', 
        'raw': '', 'parsed': 'New TCP Connection',
        'class': vol_class, 
        'conf': vol_conf, 
        'det': json.dumps(vol_det),
        'headers': '{}'
    })

    try:
        # --- Step 2: Connect to Vulnerable Target ---
        s_reader, s_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        
        # --- Step 3: Bidirectional Forwarding ---
        await asyncio.gather(
            forward(c_reader, s_writer, ip, port, 'c2s'), # Client -> Server (Payloads)
            forward(s_reader, c_writer, ip, port, 's2c'), # Server -> Client (Errors/Confirmations)
            return_exceptions=True
        )
    except Exception as e:
        print(f"[!] Handle Client Error ({ip}): {e}")
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
    print(f"[*] Initializing SMB Honeypot Proxy (Advanced Mode)...")
    init_db()
    
    # Start the DB logger worker
    asyncio.create_task(log_worker())
    
    try:
        server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
        print(f"[*] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[*] Forwarding to -> {TARGET_HOST}:{TARGET_PORT}")
        print(f"[*] Features: Volumetric Analysis, Payload Inspection, Response Validation")
        
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"[!] Server Startup Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down proxy...")