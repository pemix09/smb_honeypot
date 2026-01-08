-- SQLite schema for SMB honeypot
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    day TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    event_type TEXT,
    raw TEXT,
    parsed TEXT,
    classification TEXT,
    confidence REAL,
    details TEXT,
    headers TEXT
);

CREATE TABLE IF NOT EXISTS daily_summary (
    day TEXT PRIMARY KEY,
    total_events INTEGER,
    by_class TEXT,
    first_seen TEXT,
    last_seen TEXT
);
