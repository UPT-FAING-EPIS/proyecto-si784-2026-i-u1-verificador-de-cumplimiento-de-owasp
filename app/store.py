from threading import Lock

from app.models import Scan


class InMemoryScanStore:
    def __init__(self) -> None:
        self._scans: list[Scan] = []
        self._next_id = 1
        self._lock = Lock()

    def create_scan(self, scan: Scan) -> Scan:
        with self._lock:
            scan.id = self._next_id
            self._next_id += 1
            self._scans.insert(0, scan)
            return scan

    def get_scan(self, scan_id: int) -> Scan | None:
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


scan_store = InMemoryScanStore()
