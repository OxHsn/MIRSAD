"""SQLite response cache — keeps repeat scans fast and polite."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from ..config import CACHE_DB


class Cache:
    def __init__(self, path: Path | str = CACHE_DB, ttl: int = 86_400, enabled: bool = True) -> None:
        self.enabled = enabled
        self.ttl = ttl
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init()

    # ------------------------------------------------------------------ setup
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def _init(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS responses_v2 (
                       key TEXT PRIMARY KEY,
                       ts REAL NOT NULL,
                       expires REAL NOT NULL,
                       status INTEGER,
                       url TEXT,
                       body TEXT
                   )"""
            )

    # ------------------------------------------------------------------- api
    @staticmethod
    def make_key(method: str, url: str, payload=None) -> str:
        raw = f"{method.upper()}|{url}|{json.dumps(payload, sort_keys=True, default=str) if payload else ''}"
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()

    def get(self, key: str) -> tuple[int, str, str] | None:
        if not self.enabled:
            return None
        row = self._conn().execute(
            "SELECT expires, status, url, body FROM responses_v2 WHERE key = ?", (key,)
        ).fetchone()
        if not row:
            return None
        expires, status, url, body = row
        if time.time() > expires:
            return None
        return status, url, body or ""

    def set(self, key: str, status: int, url: str, body: str, ttl: int | None = None) -> None:
        if not self.enabled:
            return
        now = time.time()
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO responses_v2 (key, ts, expires, status, url, body) VALUES (?,?,?,?,?,?)",
                    (key, now, now + (ttl if ttl is not None else self.ttl), status, url, (body or "")[:400_000]),
                )
        except sqlite3.Error:
            pass

    def clear(self) -> int:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM responses_v2")
            return cur.rowcount

    def stats(self) -> dict:
        row = self._conn().execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM responses_v2").fetchone()
        return {"entries": row[0], "oldest": row[1], "newest": row[2]}
