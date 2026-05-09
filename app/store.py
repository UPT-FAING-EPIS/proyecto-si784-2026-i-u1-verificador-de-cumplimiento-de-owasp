from threading import Lock
from datetime import datetime, timezone
from typing import Optional
import os
import uuid
import json
import sqlite3
from pathlib import Path

from app.models import Scan, Finding


class APIToken:
    def __init__(self, token: str, user: str):
        self.token = token
        self.user = user
        self.created_at = datetime.now(timezone.utc)
        self.last_used = datetime.now(timezone.utc)
        self.is_active = True


class InMemoryScanStore:
    def __init__(self) -> None:
        self._scans: list[Scan] = []
        self._next_id = 1
        self._lock = Lock()
        self._accesses: list[dict] = []
        self._api_tokens: dict[str, APIToken] = {}
        self._admin_sessions: dict[str, dict] = {}
        self._github_token: str | None = None
        # prepare persistent data directory and files
        self._data_path = Path(os.getenv("APP_DATA_PATH", Path(__file__).parent.parent)) / "data"
        self._data_path.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_path / "scans.sqlite3"
        self._scans_file = self._data_path / "scans.json"
        self._meta_file = self._data_path / "meta.json"
        self._init_tokens()
        self._init_db()
        # try loading persisted scans
        try:
            self._load_persisted()
        except Exception:
            pass

    def _init_tokens(self):
        """Initialize API tokens from environment variables."""
        # Demo token for testing
        demo_token = os.getenv("DEMO_API_TOKEN", "demo-token-12345")
        self._api_tokens[demo_token] = APIToken(token=demo_token, user="demo")
        
        # Admin token
        admin_token = os.getenv("ADMIN_API_TOKEN", "admin-token-67890")
        self._api_tokens[admin_token] = APIToken(token=admin_token, user="admin")

    def generate_token(self, user: str) -> str:
        """Generate a new API token for a user."""
        token = str(uuid.uuid4())
        with self._lock:
            self._api_tokens[token] = APIToken(token=token, user=user)
        return token

    def validate_token(self, token: str) -> Optional[dict]:
        """Validate an API token and return user info."""
        with self._lock:
            api_token = self._api_tokens.get(token)
            if api_token and api_token.is_active:
                api_token.last_used = datetime.now(timezone.utc)
                return {"user": api_token.user, "token": token}
            return None

    def get_all_tokens(self) -> list[dict]:
        """Get all API tokens (for admin dashboard)."""
        with self._lock:
            return [
                {
                    "token": t.token[:20] + "...",
                    "user": t.user,
                    "created_at": t.created_at.isoformat(),
                    "last_used": t.last_used.isoformat(),
                    "is_active": t.is_active,
                }
                for t in self._api_tokens.values()
            ]

    def create_admin_session(self, user: str = "admin") -> str:
        """Create admin session token in memory."""
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc).timestamp() + (6 * 60 * 60)
        with self._lock:
            self._admin_sessions[session_id] = {
                "user": user,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": expires_at,
            }
        return session_id

    def validate_admin_session(self, session_id: str | None) -> bool:
        """Validate admin session token and check expiry."""
        if not session_id:
            return False
        with self._lock:
            session = self._admin_sessions.get(session_id)
            if not session:
                return False
            if session["expires_at"] < datetime.now(timezone.utc).timestamp():
                del self._admin_sessions[session_id]
                return False
            return True

    def revoke_admin_session(self, session_id: str | None) -> None:
        """Revoke admin session token."""
        if not session_id:
            return
        with self._lock:
            self._admin_sessions.pop(session_id, None)

    def set_github_token(self, token: str | None) -> None:
        """Save GitHub token for private repo analysis and issue creation."""
        cleaned = token.strip() if token else None
        with self._lock:
            self._github_token = cleaned if cleaned else None

    def get_github_token(self) -> str | None:
        """Return configured GitHub token (if any)."""
        with self._lock:
            return self._github_token

    def has_github_token(self) -> bool:
        """Whether a GitHub token is configured in memory."""
        with self._lock:
            return bool(self._github_token)

    def create_scan(self, scan: Scan) -> Scan:
        with self._lock:
            scan.id = self._next_id
            self._next_id += 1
            self._scans.insert(0, scan)
            try:
                self._persist()
            except Exception:
                pass
            try:
                self._persist_sqlite(scan)
            except Exception:
                pass
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
            try:
                self._persist()
            except Exception:
                pass
            try:
                self._clear_sqlite()
            except Exception:
                pass

    def _persist(self) -> None:
        """Persist scans and meta (next id) to disk as JSON."""
        data = []
        for s in self._scans:
            data.append({
                "id": s.id,
                "target_type": s.target_type,
                "target_value": s.target_value,
                "status": s.status,
                "score": s.score,
                "created_at": s.created_at.isoformat(),
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                        "evidence": f.evidence,
                        "penalty": getattr(f, 'penalty', 0),
                        "remediation": getattr(f, 'remediation', ''),
                    }
                    for f in s.findings
                ],
            })
        tmp = self._scans_file.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump({"scans": data, "next_id": self._next_id}, fh, ensure_ascii=False, indent=2)
        tmp.replace(self._scans_file)

    def _load_persisted(self) -> None:
        """Load persisted scans from disk if available."""
        if self._db_path.exists():
            try:
                self._load_sqlite()
                return
            except Exception:
                pass
        if not self._scans_file.exists():
            return
        with self._scans_file.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        scans = payload.get("scans", [])
        loaded = []
        from app.models import Scan, Finding
        from datetime import datetime
        for s in scans:
            findings = []
            for f in s.get("findings", []):
                findings.append(Finding(
                    rule_id=f.get("rule_id"),
                    title=f.get("title"),
                    severity=f.get("severity"),
                    description=f.get("description"),
                    evidence=f.get("evidence"),
                    penalty=f.get("penalty", 0),
                    remediation=f.get("remediation", ""),
                ))
            created_at = None
            try:
                created_at = datetime.fromisoformat(s.get("created_at"))
            except Exception:
                created_at = datetime.now(timezone.utc)
            loaded.append(Scan(id=s.get("id", 0), target_type=s.get("target_type", ""), target_value=s.get("target_value", ""), status=s.get("status", ""), score=s.get("score", 0), created_at=created_at, findings=findings))
        with self._lock:
            self._scans = loaded
            self._next_id = int(payload.get("next_id", max([c.id for c in loaded], default=0) + 1))

    def _init_db(self) -> None:
        """Create SQLite schema on first run."""
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    status TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    findings_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
            conn.commit()

    def _persist_sqlite(self, scan: Scan) -> None:
        findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "penalty": getattr(f, "penalty", 0),
                "remediation": getattr(f, "remediation", ""),
            }
            for f in scan.findings
        ]
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (id, target_type, target_value, status, score, created_at, findings_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.id,
                    scan.target_type,
                    scan.target_value,
                    scan.status,
                    scan.score,
                    scan.created_at.isoformat(),
                    json.dumps(findings, ensure_ascii=False),
                ),
            )
            conn.commit()

    def _load_sqlite(self) -> None:
        from app.models import Scan, Finding
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT id, target_type, target_value, status, score, created_at, findings_json FROM scans ORDER BY id DESC"
            ).fetchall()
        loaded = []
        max_id = 0
        from datetime import datetime
        for row in rows:
            scan_id, target_type, target_value, status, score, created_at, findings_json = row
            max_id = max(max_id, int(scan_id))
            findings = []
            try:
                findings_data = json.loads(findings_json or "[]")
            except Exception:
                findings_data = []
            for f in findings_data:
                findings.append(Finding(
                    rule_id=f.get("rule_id"),
                    title=f.get("title"),
                    severity=f.get("severity"),
                    description=f.get("description"),
                    evidence=f.get("evidence"),
                    penalty=f.get("penalty", 0),
                    remediation=f.get("remediation", ""),
                ))
            try:
                created_dt = datetime.fromisoformat(created_at)
            except Exception:
                created_dt = datetime.now(timezone.utc)
            loaded.append(Scan(id=scan_id, target_type=target_type, target_value=target_value, status=status, score=score, created_at=created_dt, findings=findings))
        with self._lock:
            self._scans = loaded
            self._next_id = max_id + 1 if max_id else 1

    def _clear_sqlite(self) -> None:
        if not self._db_path.exists():
            return
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()

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
