#!/usr/bin/env python3
"""
Simple DB inspector for the honeypot SQLite database.
Usage:
  python scripts/db_inspector.py [--db ./data/honeypot.db] [--last N]

It prints last N log rows, counts per classification and daily_summary.
"""
import sqlite3
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('--db', default='./data/honeypot.db')
parser.add_argument('--last', type=int, default=20)
args = parser.parse_args()

conn = sqlite3.connect(args.db)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print(f"Inspecting DB: {args.db}\n")

# Last N logs
print(f"Last {args.last} logs:")
for row in cur.execute('SELECT id,timestamp,src_ip,src_port,dst_port,protocol,event_type,classification,confidence,details FROM logs ORDER BY id DESC LIMIT ?;', (args.last,)):
    details = row['details']
    try:
        d = json.loads(details) if details else None
    except Exception:
        d = details
    print(f"#{row['id']} {row['timestamp']} {row['src_ip']}:{row['src_port']} -> {row['dst_port']} {row['protocol']} {row['event_type']} class={row['classification']} conf={row['confidence']} details={d}")

print('\nCounts by classification:')
for row in cur.execute('SELECT classification, COUNT(*) as c FROM logs GROUP BY classification ORDER BY c DESC;'):
    print(f"{row['classification']}: {row['c']}")

print('\nDaily summary:')
for row in cur.execute('SELECT day, total_events, by_class, first_seen, last_seen FROM daily_summary ORDER BY day DESC;'):
    print(f"{row['day']}: total={row['total_events']} by_class={row['by_class']} first={row['first_seen']} last={row['last_seen']}")

conn.close()
