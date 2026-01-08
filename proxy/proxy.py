import asyncio
import base64
import sqlite3
import json
import os
from datetime import datetime

# Konfiguracja z Docker-Compose
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "445"))
TARGET_HOST = os.getenv("TARGET_HOST", "vuln_smb")
TARGET_PORT = int(os.getenv("TARGET_PORT", "445"))
DB_PATH = os.getenv("DB_PATH", "/app/data/honeypot.db")

# Kolejka logowania (Background Worker)
log_queue = asyncio.Queue()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            event_type TEXT,
            raw TEXT,
            classification TEXT,
            confidence REAL,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

async def log_worker():
    """Zapisuje logi w tle, aby nie spowalniać protokołu SMB"""
    while True:
        record = await log_queue.get()
        try:
            await asyncio.to_thread(sync_save, record)
        except Exception as e:
            print(f"Błąd zapisu DB: {e}")
        finally:
            log_queue.task_done()

def sync_save(rec):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute('''INSERT INTO logs 
        (timestamp, src_ip, src_port, dst_port, protocol, event_type, raw, classification, confidence, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
        (rec['ts'], rec['ip'], rec['port'], TARGET_PORT, 'SMB', rec['type'], 
         rec['raw'], rec['class'], rec['conf'], rec['det']))
    conn.commit()
    conn.close()

def simple_classify(data):
    """Przykładowa klasyfikacja na potrzeby projektu"""
    d_str = data.decode('utf-8', errors='ignore').lower()
    if any(x in d_str for x in ["nt create", "tree connect"]):
        return "smb_command", 0.5, {"cmd_detected": "enumeration"}
    if len(data) > 3000:
        return "potential_file_transfer", 0.6, {"size": len(data)}
    return "generic_smb_traffic", 0.1, {}

async def forward(reader, writer, ip, port, direction):
    try:
        while True:
            data = await reader.read(65536) # Duży bufor pod SMB
            if not data: break
            
            writer.write(data)
            await writer.drain()

            # Logowanie asynchroniczne
            cls, conf, det = simple_classify(data)
            log_queue.put_nowait({
                'ts': datetime.utcnow().isoformat() + 'Z',
                'ip': ip, 'port': port, 'type': f'data_{direction}',
                'raw': base64.b64encode(data).decode('ascii'),
                'class': cls, 'conf': conf, 'det': json.dumps(det)
            })
    except Exception:
        pass
    finally:
        writer.close()

async def handle_client(c_reader, c_writer):
    peer = c_writer.get_extra_info('peername')
    ip, port = peer if peer else ("unknown", 0)
    
    # Log: Nowe połączenie
    log_queue.put_nowait({
        'ts': datetime.utcnow().isoformat() + 'Z', 'ip': ip, 'port': port,
        'type': 'connection_open', 'raw': '', 'class': 'network', 'conf': 0.0, 'det': '{}'
    })

    try:
        s_reader, s_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        await asyncio.gather(
            forward(c_reader, s_writer, ip, port, 'c2s'),
            forward(s_reader, c_writer, ip, port, 's2c')
        )
    except Exception as e:
        print(f"Błąd połączenia z serwerem Samba: {e}")
    finally:
        c_writer.close()

async def main():
    init_db()
    asyncio.create_task(log_worker())
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    print(f"Proxy SMB działa na {LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())