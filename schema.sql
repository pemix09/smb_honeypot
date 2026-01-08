-- Schema for honeypot SQLite database
PRAGMA foreign_keys = OFF;
PRAGMA journal_mode = WAL;

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

CREATE INDEX IF NOT EXISTS idx_logs_day ON logs(day);
CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_class ON logs(classification);

CREATE TABLE IF NOT EXISTS daily_summary (
    day TEXT PRIMARY KEY,
    total_events INTEGER,
    by_class TEXT,
    first_seen TEXT,
    last_seen TEXT
);
