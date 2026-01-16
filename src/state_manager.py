import json
import logging
import sqlite3
import threading
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional


class StateManager:
    """Manages sync state with SQLite persistence and in-memory caching."""

    def __init__(self, db_path: str = "/tmp/pfsense-sync.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

        # In-memory cache for real-time updates
        self.current_status = {
            "state": "idle",  # idle, running, error
            "last_run": None,
            "next_run": None,
            "last_success": None,
            "last_error": None,
            "current_mode": None,
        }
        self.recent_logs = deque(maxlen=500)

    def _init_db(self):
        """Initialize SQLite database and schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mode TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    success INTEGER,
                    collections TEXT,
                    error_message TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sync_id INTEGER,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    FOREIGN KEY (sync_id) REFERENCES sync_history(id)
                )
                """
            )
            # Create trigger to auto-cleanup old logs
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS cleanup_old_logs
                AFTER INSERT ON sync_logs
                BEGIN
                    DELETE FROM sync_logs WHERE id < (
                        SELECT id FROM sync_logs ORDER BY id DESC LIMIT 1 OFFSET 5000
                    );
                END
                """
            )
            conn.commit()

    def record_sync_start(self, mode: str) -> int:
        """Record the start of a sync cycle. Returns sync_id."""
        with self.lock:
            started_at = datetime.now().isoformat()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "INSERT INTO sync_history (mode, started_at) VALUES (?, ?)",
                    (mode, started_at),
                )
                sync_id = cursor.lastrowid
                conn.commit()

            self.current_status["state"] = "running"
            self.current_status["current_mode"] = mode
            return sync_id

    def record_sync_complete(
        self, sync_id: int, success: bool, collections: List[str], error_message: Optional[str] = None
    ):
        """Record the completion of a sync cycle."""
        with self.lock:
            completed_at = datetime.now().isoformat()
            collections_json = json.dumps(collections)

            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    UPDATE sync_history
                    SET completed_at = ?, success = ?, collections = ?, error_message = ?
                    WHERE id = ?
                    """,
                    (completed_at, 1 if success else 0, collections_json, error_message, sync_id),
                )
                conn.commit()

            self.current_status["state"] = "idle" if success else "error"
            self.current_status["last_run"] = completed_at
            if success:
                self.current_status["last_success"] = completed_at
                self.current_status["last_error"] = None
            else:
                self.current_status["last_error"] = error_message
            self.current_status["current_mode"] = None

    def add_log_entry(self, timestamp: str, level: str, message: str, sync_id: Optional[int] = None):
        """Add a log entry to both database and in-memory cache."""
        with self.lock:
            # Add to in-memory cache
            self.recent_logs.append({"timestamp": timestamp, "level": level, "message": message})

            # Add to database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO sync_logs (sync_id, timestamp, level, message) VALUES (?, ?, ?, ?)",
                    (sync_id, timestamp, level, message),
                )
                conn.commit()

    def get_sync_history(self, limit: int = 20) -> List[Dict]:
        """Get recent sync history."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, mode, started_at, completed_at, success, collections, error_message
                FROM sync_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "mode": row["mode"],
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                    "success": bool(row["success"]) if row["success"] is not None else None,
                    "collections": json.loads(row["collections"]) if row["collections"] else [],
                    "error_message": row["error_message"],
                }
                for row in rows
            ]

    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent logs from in-memory cache or database."""
        with self.lock:
            # Return from in-memory cache if sufficient
            if len(self.recent_logs) >= limit:
                return list(self.recent_logs)[-limit:]

            # Otherwise query from database
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    """
                    SELECT timestamp, level, message
                    FROM sync_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                return [
                    {"timestamp": row["timestamp"], "level": row["level"], "message": row["message"]}
                    for row in reversed(rows)
                ]

    def get_current_status(self) -> Dict:
        """Get current sync status."""
        with self.lock:
            return self.current_status.copy()

    def set_next_run(self, next_run: Optional[str]):
        """Set the next scheduled run time."""
        with self.lock:
            self.current_status["next_run"] = next_run


class StateLoggingHandler(logging.Handler):
    """Custom logging handler that captures logs to StateManager."""

    def __init__(self, state_manager: StateManager, sync_id: Optional[int] = None):
        super().__init__()
        self.state_manager = state_manager
        self.sync_id = sync_id

    def emit(self, record):
        """Emit a log record to StateManager."""
        try:
            # Filter out werkzeug HTTP request logs to reduce noise
            if record.name == "werkzeug":
                return

            timestamp = datetime.fromtimestamp(record.created).isoformat()
            level = record.levelname
            message = record.getMessage()
            self.state_manager.add_log_entry(timestamp, level, message, self.sync_id)
        except Exception:
            # Silently fail to avoid breaking the application
            pass
