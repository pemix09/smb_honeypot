import asyncio
import base64
import sqlite3
import json
import os
from datetime import datetime

# Konfiguracja
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "445"))
TARGET_HOST = os.getenv("TARGET_HOST", "vuln_smb")
TARGET_PORT = int(os.getenv("TARGET_PORT", "445"))
DB_PATH = os.getenv("DB_PATH", "/app/data/honeypot.db")

log_queue = asyncio.Queue()

def init_db():
    try:
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
    except Exception as e:
        print(f"[!] Krytyczny błąd inicjalizacji bazy: {e}")

async def log_worker():
    """Worker w tle - zapewnia, że błędy DB nie zrywają połączeń sieciowych"""
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
        cur.execute('''INSERT INTO logs 
            (timestamp, src_ip, src_port, dst_port, protocol, event_type, raw, classification, confidence, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (rec['ts'], rec['ip'], rec['port'], TARGET_PORT, 'SMB', rec['type'], 
             rec['raw'], rec['class'], rec['conf'], rec['det']))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] SQLite Sync Save Error: {e}")

def robust_classify(data):
    """Odporna na błędy klasyfikacja payloadu"""
    try:
        # Próba dekodowania z ignorowaniem błędów (ważne dla ruchu binarnego)
        d_str = data.decode('utf-8', errors='ignore').lower()
        
        if "flag.txt" in d_str:
            return "flag_access_attempt", 1.0, {"target": "FLAG.txt"}
        
        if any(p in d_str for p in ["union select", "drop table", "/etc/passwd", "cmd.exe"]):
            return "exploit_payload_detected", 0.9, {"pattern_found": True}

        if b"\xffSMB" in data: # SMBv1 (często używany w skanach/exploitach)
            return "legacy_smb1_detected", 0.6, {"info": "Legacy SMBv1 negotiation"}
            
        if b"\xfeSMB" in data: # SMBv2/3
            return "smb2_3_traffic", 0.1, {"protocol": "modern"}

    except Exception as e:
        return "binary_data_unknown", 0.0, {"error": str(e)}
    
    return "generic_smb_traffic", 0.1, {}

async def forward(reader, writer, ip, port, direction):
    """Przesyła dane i loguje je, izolując błędy"""
    try:
        while True:
            try:
                data = await reader.read(65536)
                if not data:
                    break
                
                # Przekaż dane natychmiast
                writer.write(data)
                await writer.drain()
            except Exception as e:
                print(f"[!] Network Forward Error ({direction}): {e}")
                break

            # Logowanie jest w osobnym try-except, aby błąd logiki nie zabił połączenia
            try:
                cls, conf, det = robust_classify(data)
                log_queue.put_nowait({
                    'ts': datetime.utcnow().isoformat() + 'Z',
                    'ip': ip, 'port': port, 'type': f'data_{direction}',
                    'raw': base64.b64encode(data).decode('ascii'),
                    'class': cls, 'conf': conf, 'det': json.dumps(det)
                })
            except Exception as e:
                print(f"[!] Payload Processing Error: {e}")
                
    except Exception as e:
        print(f"[!] General Forward Loop Error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def handle_client(c_reader, c_writer):
    peer = c_writer.get_extra_info('peername')
    ip, port = peer if peer else ("unknown", 0)
    
    try:
        # Log: Nowe połączenie
        log_queue.put_nowait({
            'ts': datetime.utcnow().isoformat() + 'Z', 'ip': ip, 'port': port,
            'type': 'connection_open', 'raw': '', 'class': 'network', 'conf': 0.0, 'det': '{}'
        })

        # Łączymy się z docelową Sambą
        s_reader, s_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
        
        # Uruchamiamy forwardowanie w obie strony
        await asyncio.gather(
            forward(c_reader, s_writer, ip, port, 'c2s'),
            forward(s_reader, c_writer, ip, port, 's2c'),
            return_exceptions=True
        )
    except Exception as e:
        print(f"[!] Handle Client Error ({ip}): {e}")
        log_queue.put_nowait({
            'ts': datetime.utcnow().isoformat() + 'Z', 'ip': ip, 'port': port,
            'type': 'connection_failed', 'raw': str(e), 'class': 'error', 'conf': 0.0, 'det': '{}'
        })
    finally:
        try:
            c_writer.close()
            await c_writer.wait_closed()
        except:
            pass

async def main():
    print(f"[*] Inicjalizacja Honeypot Proxy...")
    init_db()
    asyncio.create_task(log_worker())
    
    try:
        server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
        print(f"[*] Proxy SMB nasłuchuje na {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[*] Kierunek: -> {TARGET_HOST}:{TARGET_PORT}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"[!] Server Startup Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Zamykanie proxy...")