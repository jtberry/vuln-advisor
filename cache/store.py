"""
cache/store.py — SQLite-backed cache for CVE lookups.

Avoids redundant API calls by storing enriched CVE JSON locally with
a configurable TTL (default 24 hours). Shared by the CLI and API so
both benefit from cached results.

Usage:
    cache = CVECache()
    data = cache.get("CVE-2021-44228")   # returns dict or None
    cache.set("CVE-2021-44228", data)
    cache.purge_expired()                # call periodically to trim old entries
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

_DEFAULT_DB = Path(__file__).parent / "vulnadvisor.db"
_DEFAULT_TTL = 60 * 60 * 24  # 24 hours in seconds

_DDL = """
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    cached_at   REAL NOT NULL
);
"""


class CVECache:
    def __init__(self, db_path: Path = _DEFAULT_DB, ttl: int = _DEFAULT_TTL) -> None:
        self.ttl = ttl
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_DDL)
        self._conn.commit()

    def get(self, cve_id: str) -> Optional[dict]:
        """Return cached data for cve_id if it exists and hasn't expired."""
        row = self._conn.execute(
            "SELECT data, cached_at FROM cve_cache WHERE cve_id = ?",
            (cve_id.upper(),),
        ).fetchone()
        if row is None:
            return None
        data, cached_at = row
        if time.time() - cached_at > self.ttl:
            self._delete(cve_id)
            return None
        return json.loads(data)

    def set(self, cve_id: str, data: dict) -> None:
        """Store data for cve_id, replacing any existing entry."""
        self._conn.execute(
            "INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at) VALUES (?, ?, ?)",
            (cve_id.upper(), json.dumps(data), time.time()),
        )
        self._conn.commit()

    def purge_expired(self) -> int:
        """Delete all entries older than TTL. Returns number of rows removed."""
        cutoff = time.time() - self.ttl
        cursor = self._conn.execute("DELETE FROM cve_cache WHERE cached_at < ?", (cutoff,))
        self._conn.commit()
        return cursor.rowcount

    def _delete(self, cve_id: str) -> None:
        self._conn.execute("DELETE FROM cve_cache WHERE cve_id = ?", (cve_id.upper(),))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
