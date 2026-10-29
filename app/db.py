"""SQLite: e-mails analisados, rótulos e cache de consultas externas."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT UNIQUE NOT NULL,
    message_id TEXT,
    path TEXT,
    folder TEXT,
    subject TEXT,
    from_name TEXT,
    from_addr TEXT,
    from_domain TEXT,
    reply_to TEXT,
    to_addrs TEXT,
    date TEXT,
    size INTEGER,
    snippet TEXT,
    auth TEXT,
    is_bulk INTEGER DEFAULT 0,
    local_findings TEXT DEFAULT '[]',
    mailbox_findings TEXT DEFAULT '[]',
    enrich_findings TEXT DEFAULT '[]',
    ai TEXT DEFAULT '{}',
    links TEXT DEFAULT '[]',
    attachments TEXT DEFAULT '[]',
    qr_codes TEXT DEFAULT '[]',
    campaign TEXT,
    score INTEGER DEFAULT 0,
    level TEXT DEFAULT 'limpo',
    enriched INTEGER DEFAULT 0,
    label TEXT,
    ingested_at REAL,
    analyzed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_emails_score ON emails(score DESC);
CREATE INDEX IF NOT EXISTS idx_emails_from_domain ON emails(from_domain);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT,
    created_at REAL
);
"""

JSON_COLS = {"reply_to", "to_addrs", "auth", "local_findings", "mailbox_findings", "enrich_findings", "ai",
             "links", "attachments", "qr_codes"}


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = Path(path or settings.db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    return con


@contextmanager
def session(path: Path | None = None):
    con = connect(path)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in JSON_COLS:
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except json.JSONDecodeError:
                pass
    return d


def clean(s):
    """Remove 'surrogates' que aparecem em e-mails com bytes inválidos (o SQLite não aceita)."""
    if isinstance(s, str):
        return s.encode("utf-8", "replace").decode("utf-8")
    return s


def dumps(v) -> str:
    return clean(json.dumps(v, ensure_ascii=False, default=str))


def cache_get(con: sqlite3.Connection, key: str, max_age: float = 7 * 86400):
    r = con.execute("SELECT value, created_at FROM cache WHERE key=?", (key,)).fetchone()
    if r and time.time() - r["created_at"] < max_age:
        return json.loads(r["value"])
    return None


def cache_set(con: sqlite3.Connection, key: str, value) -> None:
    con.execute("INSERT OR REPLACE INTO cache(key, value, created_at) VALUES (?,?,?)", (key, dumps(value), time.time()))
    con.commit()
