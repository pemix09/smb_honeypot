#!/usr/bin/env python3
"""Export honeypot SQLite logs to CSV files.

Writes `data/logs.csv` and `data/daily_summary.csv` by default.
Usage:
  python3 scripts/dataset_exporter.py --db ./data/honeypot.db --out ./data
"""
import argparse
import csv
import os
import sqlite3
from datetime import datetime


def export_logs(db_path, out_dir):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('PRAGMA journal_mode = WAL')

    cur.execute('SELECT id,timestamp,day,src_ip,src_port,dst_port,protocol,event_type,raw,parsed,classification,confidence,details,headers FROM logs ORDER BY id')
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]

    os.makedirs(out_dir, exist_ok=True)
    logs_csv = os.path.join(out_dir, 'logs.csv')
    with open(logs_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        for r in rows:
            writer.writerow(r)

    # export daily_summary
    cur.execute('SELECT day,total_events,by_class,first_seen,last_seen FROM daily_summary ORDER BY day')
    rows2 = cur.fetchall()
    summary_csv = os.path.join(out_dir, 'daily_summary.csv')
    with open(summary_csv, 'w', newline='') as f2:
        writer = csv.writer(f2)
        writer.writerow(['day','total_events','by_class','first_seen','last_seen'])
        for r in rows2:
            writer.writerow(r)

    conn.close()
    return logs_csv, summary_csv


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='./data/honeypot.db', help='Path to SQLite DB')
    p.add_argument('--out', default='./data', help='Output directory for CSV files')
    args = p.parse_args()

    db = os.path.abspath(args.db)
    out = os.path.abspath(args.out)
    if not os.path.exists(db):
        print('DB not found:', db)
        return

    logs_csv, summary_csv = export_logs(db, out)
    print('Exported:')
    print(' -', logs_csv)
    print(' -', summary_csv)


if __name__ == '__main__':
    main()
