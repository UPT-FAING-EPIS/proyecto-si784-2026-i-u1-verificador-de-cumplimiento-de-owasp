from threading import Lock
from datetime import datetime, timezone
from typing import Optional
import os
import uuid

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
        self._init_tokens()

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
