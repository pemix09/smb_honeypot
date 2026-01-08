#!/usr/bin/env python3
import os
import sqlite3
import time
import json

DB_PATH = os.getenv('DB_PATH', '/app/data/honeypot.db')
POLL_INTERVAL = float(os.getenv('POLL_INTERVAL', '1.0'))


def wait_for_db(path):
    while not os.path.exists(path):
        print(f'Waiting for DB: {path}')
        time.sleep(1.0)


def tail_db(path):
    last_id = 0
    wait_for_db(path)
    print('Tailing DB:', path)
    try:
        while True:
            try:
                conn = sqlite3.connect(path)
                cur = conn.cursor()
                cur.execute('''SELECT id,timestamp,src_ip,src_port,dst_port,protocol,event_type,classification,confidence,details
                               FROM logs WHERE id > ? ORDER BY id''', (last_id,))
                rows = cur.fetchall()
                for r in rows:
                    last_id = r[0]
                    # pretty print
                    out = {
                        'id': r[0],
                        'timestamp': r[1],
                        'src_ip': r[2],
                        'src_port': r[3],
                        'dst_port': r[4],
                        'protocol': r[5],
                        'event_type': r[6],
                        'classification': r[7],
                        'confidence': r[8],
                        'details': None
                    }
                    try:
                        out['details'] = json.loads(r[9]) if r[9] else None
                    except Exception:
                        out['details'] = r[9]
                    print(json.dumps(out, ensure_ascii=False))
                conn.close()
            except sqlite3.OperationalError as e:
                # DB might be locked briefly
                print('DB error:', e)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print('Stopping DB tail')


if __name__ == '__main__':
    tail_db(DB_PATH)
