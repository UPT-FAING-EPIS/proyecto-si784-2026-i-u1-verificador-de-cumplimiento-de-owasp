from threading import Lock
from datetime import datetime, timezone
from typing import Optional

from app.models import Scan, Finding


class InMemoryScanStore:
    def __init__(self) -> None:
        self._scans: list[Scan] = []
        self._next_id = 1
        self._lock = Lock()
        self._accesses: list[dict] = []

    def create_scan(self, scan: Scan) -> Scan:
        with self._lock:
            scan.id = self._next_id
            self._next_id += 1
            self._scans.insert(0, scan)
            return scan

    def get_scan(self, scan_id: int) -> Optional[Scan]:
        with self._lock:
            return next((scan for scan in self._scans if scan.id == scan_id), None)

    def list_scans(self, limit: int | None = None) -> list[Scan]:
        with self._lock:
            scans = list(self._scans)
        if limit is None:
            return scans
        return scans[:limit]

    def clear(self) -> None:
        with self._lock:
            self._scans.clear()
            self._next_id = 1
            self._accesses.clear()

    # Access log methods for in-memory store
    def log_access(self, path: str, ip: str, user_agent: str, user: str | None = None, timestamp: str | None = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._accesses.insert(0, {"path": path, "ip": ip, "user_agent": user_agent, "username": user, "created_at": ts})

    def list_accesses(self, limit: int | None = 100) -> list[dict]:
        with self._lock:
            if limit is None:
                return list(self._accesses)
            return list(self._accesses)[:limit]


scan_store = InMemoryScanStore()
