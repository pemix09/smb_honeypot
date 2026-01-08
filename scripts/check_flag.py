#!/usr/bin/env python3
"""Attempt to fetch FLAG.txt from an SMB share using Python (pysmb if available).

If pysmb is not installed, exits with code 2.
Also queries the honeypot SQLite DB for related log entries (same as check_flag.sh).
"""
import argparse
import os
import sqlite3
import sys

def query_db(db_path):
    if not os.path.exists(db_path):
        print('DB not found:', db_path)
        return
    print('\n-- Recent logs (last 25) --')
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id,timestamp,src_ip,src_port,dst_port,protocol,event_type,classification,confidence,parsed,details FROM logs ORDER BY id DESC LIMIT 25;")
    for row in cur.fetchall():
        print('|'.join(str(x) if x is not None else '' for x in row))

    print('\n-- Logs mentioning FLAG or FLAG.txt (parsed/details) --')
    cur.execute("SELECT id,timestamp,src_ip,src_port,event_type,classification,parsed,details FROM logs WHERE parsed LIKE '%FLAG%' OR details LIKE '%FLAG%' OR parsed LIKE '%FLAG.txt%' OR details LIKE '%FLAG.txt%' ORDER BY id DESC LIMIT 50;")
    for row in cur.fetchall():
        print('|'.join(str(x) if x is not None else '' for x in row))

    print('\n-- Recent file-upload malicious detections --')
    cur.execute("SELECT id,timestamp,src_ip,src_port,event_type,classification,confidence,details FROM logs WHERE classification='file_upload_malicious' ORDER BY id DESC LIMIT 50;")
    for row in cur.fetchall():
        print('|'.join(str(x) if x is not None else '' for x in row))
    conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('ip', nargs='?', default='127.0.0.1')
    p.add_argument('share', nargs='?', default='share')
    p.add_argument('--db', default='./data/honeypot.db')
    p.add_argument('--out', default='downloaded_FLAG.txt')
    args = p.parse_args()

    # Try to use pysmb (SMBConnection)
    try:
        from smb.SMBConnection import SMBConnection
    except Exception as e:
        print('pysmb not available:', e)
        sys.exit(2)

    conn = SMBConnection('', '', 'local', args.ip, use_ntlm_v2=True)
    try:
        connected = conn.connect(args.ip, 445, timeout=10)
    except Exception as e:
        print('Connection failed:', e)
        connected = False
    if not connected:
        print('Could not connect to SMB on', args.ip)
        sys.exit(3)

    try:
        with open(args.out, 'wb') as fp:
            print('Attempting to retrieve FLAG.txt from', args.share)
            conn.retrieveFile(args.share, 'FLAG.txt', fp)
        print('Saved flag to', args.out)
        try:
            with open(args.out, 'r') as f:
                print('--- FLAG content ---')
                print(f.read())
        except Exception:
            pass
    except Exception as e:
        print('Failed to retrieve FLAG.txt:', e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Always query DB afterwards
    query_db(args.db)


if __name__ == '__main__':
    main()
