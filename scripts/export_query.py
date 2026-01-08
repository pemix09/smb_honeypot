#!/usr/bin/env python3
"""
Export results of a SQL query from the honeypot SQLite DB to CSV.
Usage:
  python scripts/export_query.py --db ./data/honeypot.db --query-file scripts/sample_queries.sql --out ./data/query_export.csv --name recent_logs

If --query-file contains multiple queries separated by --name: <tag> lines, you can specify --name to run a particular query.
"""
import sqlite3
import csv
import argparse
import os
import sys
import re

parser = argparse.ArgumentParser()
parser.add_argument('--db', default='./data/honeypot.db')
parser.add_argument('--query-file', default='scripts/sample_queries.sql')
parser.add_argument('--name', default=None, help='Named query to run from the query file')
parser.add_argument('--out', default='./data/query_export.csv')
args = parser.parse_args()

if not os.path.exists(args.db):
    print(f"Error: DB file not found: {args.db}")
    sys.exit(1)
if not os.path.exists(args.query_file):
    print(f"Error: Query file not found: {args.query_file}")
    sys.exit(1)

# Load queries; format supports blocks starting with: -- name: tag
queries = {}
current_name = None
current_sql = []
with open(args.query_file, 'r', encoding='utf-8') as f:
    for line in f:
        if line.strip().lower().startswith('-- name:'):
            if current_name and current_sql:
                queries[current_name] = '\n'.join(current_sql).strip()
            current_name = line.strip()[8:].strip()
            current_sql = []
        else:
            current_sql.append(line.rstrip('\n'))
    if current_name and current_sql:
        queries[current_name] = '\n'.join(current_sql).strip()

if args.name:
    if args.name not in queries:
        print(f"Named query not found in {args.query_file}: {args.name}")
        print(f"Available: {', '.join(queries.keys())}")
        sys.exit(1)
    sql = queries[args.name]
else:
    # if no name provided, use entire file
    if len(queries) == 1:
        sql = list(queries.values())[0]
    else:
        # join all queries for execution
        sql = '\n\n'.join(queries.values())

conn = sqlite3.connect(args.db)
cur = conn.cursor()
try:
    # Check whether `day` column exists in logs; if not, substitute with substr(timestamp,1,10)
    cur.execute("PRAGMA table_info('logs');")
    cols = [r[1] for r in cur.fetchall()]
    if 'day' not in cols:
        # replace standalone word `day` with substr(...) expression
        sql = re.sub(r'(?i)\bday\b', "substr(timestamp,1,10)", sql)

    try:
        cur.execute(sql)
    except sqlite3.OperationalError as e:
        # attempt fallback to legacy named query if available
        msg = str(e)
        if args.name and (args.name + '_legacy') in queries:
            print(f"OperationalError: {msg}. Falling back to named query: {args.name}_legacy")
            sql = queries[args.name + '_legacy']
            # check day substitution again
            cur.execute("PRAGMA table_info('logs');")
            cols = [r[1] for r in cur.fetchall()]
            if 'day' not in cols:
                sql = re.sub(r'(?i)\bday\b', "substr(timestamp,1,10)", sql)
            cur.execute(sql)
        else:
            raise
    rows = cur.fetchall()
    col_names = [d[0] for d in cur.description] if cur.description else []
    if not rows:
        print("Query returned no rows.")
    else:
        with open(args.out, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if col_names:
                writer.writerow(col_names)
            writer.writerows(rows)
        print(f"Exported {len(rows)} rows to {args.out}")
finally:
    conn.close()
