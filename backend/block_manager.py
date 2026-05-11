"""
backend/block_manager.py
=========================
Command persistence layer for storing and managing attack blocking commands.
Provides reliable storage, retrieval, and status tracking of blocking commands.

Tables:
  - blocking_commands: All commands (pending, sent, executed, failed)
  - block_history: Historical record of blocks applied

Commands flow:
  1. Analysis endpoint creates command → PENDING
  2. ESP32 polls /api/commands/pending
  3. Command sent to ESP32 → SENT
  4. ESP32 executes → callback to /api/commands/{id}/confirm
  5. Status updated → EXECUTED
"""

import os
import json
import sqlite3
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("block_manager")

BASE_DIR = Path(__file__).parent
DB_DIR = BASE_DIR / "data"
DB_PATH = DB_DIR / "blocking_commands.db"

_lock = threading.Lock()


class BlockingCommand:
    """Represents a single blocking command."""
    
    def __init__(self, cmd_id: str, device_id: str, action: str, 
                 target: str, reason: str, attack_data: dict, 
                 status: str = "PENDING", created_at: str = None,
                 sent_at: str = None, executed_at: str = None):
        self.cmd_id = cmd_id
        self.device_id = device_id
        self.action = action  # "block_ip", "block_port", "drop_traffic", etc.
        self.target = target  # IP, port, or pattern
        self.reason = reason  # "DDoS", "Port Scan", "Botnet C2", etc.
        self.attack_data = attack_data  # Raw attack features
        self.status = status  # PENDING, SENT, EXECUTED, FAILED
        self.created_at = created_at or datetime.utcnow().isoformat()
        self.sent_at = sent_at
        self.executed_at = executed_at
    
    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "cmd_id": self.cmd_id,
            "device_id": self.device_id,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "status": self.status,
            "created_at": self.created_at,
            "sent_at": self.sent_at,
            "executed_at": self.executed_at,
        }
    
    def to_mqtt_payload(self) -> str:
        """Convert to MQTT message payload."""
        return json.dumps({
            "cmd_id": self.cmd_id,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "created_at": self.created_at,
        })


class BlockManager:
    """Manages persistence of blocking commands."""
    
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocking_commands (
                    cmd_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    reason TEXT,
                    attack_data TEXT,
                    status TEXT DEFAULT 'PENDING',
                    created_at TEXT,
                    sent_at TEXT,
                    executed_at TEXT,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS block_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cmd_id TEXT,
                    device_id TEXT,
                    action TEXT,
                    target TEXT,
                    reason TEXT,
                    status TEXT,
                    executed_at TEXT,
                    duration_sec REAL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_command(self, device_id: str, action: str, target: str,
                      reason: str, attack_data: dict) -> BlockingCommand:
        """Create and store a new blocking command."""
        import uuid
        cmd_id = f"cmd_{uuid.uuid4().hex[:12]}"
        cmd = BlockingCommand(
            cmd_id=cmd_id,
            device_id=device_id,
            action=action,
            target=target,
            reason=reason,
            attack_data=attack_data,
            status="PENDING",
        )
        
        with _lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO blocking_commands 
                    (cmd_id, device_id, action, target, reason, attack_data, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cmd.cmd_id,
                    cmd.device_id,
                    cmd.action,
                    cmd.target,
                    cmd.reason,
                    json.dumps(attack_data),
                    cmd.status,
                    cmd.created_at,
                ))
                conn.commit()
        
        log.info(f"✅ Command created: {cmd_id} | {action} {target} ({reason})")
        return cmd
    
    def get_pending_commands(self, device_id: str) -> List[BlockingCommand]:
        """Get all pending commands for a device."""
        with _lock:
            with self._get_conn() as conn:
                rows = conn.execute("""
                    SELECT * FROM blocking_commands 
                    WHERE device_id = ? AND status = 'PENDING'
                    ORDER BY created_at ASC
                """, (device_id,)).fetchall()
        
        commands = []
        for row in rows:
            cmd = BlockingCommand(
                cmd_id=row["cmd_id"],
                device_id=row["device_id"],
                action=row["action"],
                target=row["target"],
                reason=row["reason"],
                attack_data=json.loads(row["attack_data"] or "{}"),
                status=row["status"],
                created_at=row["created_at"],
                sent_at=row["sent_at"],
                executed_at=row["executed_at"],
            )
            commands.append(cmd)
        
        return commands
    
    def mark_sent(self, cmd_id: str) -> bool:
        """Mark command as sent to device."""
        now = datetime.utcnow().isoformat()
        with _lock:
            with self._get_conn() as conn:
                conn.execute("""
                    UPDATE blocking_commands 
                    SET status = 'SENT', sent_at = ?
                    WHERE cmd_id = ?
                """, (now, cmd_id))
                conn.commit()
        
        log.info(f"📤 Command sent: {cmd_id}")
        return True
    
    def mark_executed(self, cmd_id: str, duration_sec: float = 0) -> bool:
        """Mark command as executed by device."""
        now = datetime.utcnow().isoformat()
        with _lock:
            with self._get_conn() as conn:
                # Update main table
                conn.execute("""
                    UPDATE blocking_commands 
                    SET status = 'EXECUTED', executed_at = ?
                    WHERE cmd_id = ?
                """, (now, cmd_id))
                
                # Record in history
                row = conn.execute(
                    "SELECT * FROM blocking_commands WHERE cmd_id = ?",
                    (cmd_id,)
                ).fetchone()
                
                if row:
                    conn.execute("""
                        INSERT INTO block_history 
                        (cmd_id, device_id, action, target, reason, status, executed_at, duration_sec)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row["cmd_id"],
                        row["device_id"],
                        row["action"],
                        row["target"],
                        row["reason"],
                        "EXECUTED",
                        now,
                        duration_sec,
                    ))
                
                conn.commit()
        
        log.info(f"🔒 Command executed: {cmd_id} ({duration_sec:.2f}s)")
        return True
    
    def mark_failed(self, cmd_id: str, reason: str = "") -> bool:
        """Mark command as failed."""
        now = datetime.utcnow().isoformat()
        with _lock:
            with self._get_conn() as conn:
                conn.execute("""
                    UPDATE blocking_commands 
                    SET status = 'FAILED'
                    WHERE cmd_id = ?
                """, (cmd_id,))
                conn.commit()
        
        log.warning(f"❌ Command failed: {cmd_id} | {reason}")
        return True
    
    def get_command(self, cmd_id: str) -> Optional[BlockingCommand]:
        """Get a specific command by ID."""
        with _lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM blocking_commands WHERE cmd_id = ?",
                    (cmd_id,)
                ).fetchone()
        
        if not row:
            return None
        
        return BlockingCommand(
            cmd_id=row["cmd_id"],
            device_id=row["device_id"],
            action=row["action"],
            target=row["target"],
            reason=row["reason"],
            attack_data=json.loads(row["attack_data"] or "{}"),
            status=row["status"],
            created_at=row["created_at"],
            sent_at=row["sent_at"],
            executed_at=row["executed_at"],
        )
    
    def get_block_history(self, device_id: str = None, limit: int = 100) -> List[dict]:
        """Get historical blocking records."""
        with _lock:
            with self._get_conn() as conn:
                if device_id:
                    rows = conn.execute("""
                        SELECT * FROM block_history 
                        WHERE device_id = ?
                        ORDER BY created_date DESC LIMIT ?
                    """, (device_id, limit)).fetchall()
                else:
                    rows = conn.execute("""
                        SELECT * FROM block_history 
                        ORDER BY created_date DESC LIMIT ?
                    """, (limit,)).fetchall()
        
        return [dict(row) for row in rows]
    
    def cleanup_old_commands(self, days: int = 7) -> int:
        """Remove completed commands older than N days."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        with _lock:
            with self._get_conn() as conn:
                cursor = conn.execute("""
                    DELETE FROM blocking_commands 
                    WHERE status IN ('EXECUTED', 'FAILED') AND created_at < ?
                """, (cutoff,))
                conn.commit()
                deleted = cursor.rowcount
        
        log.info(f"🗑️  Cleaned up {deleted} old commands")
        return deleted


# Global instance
_manager = None

def get_block_manager() -> BlockManager:
    """Get or create global block manager instance."""
    global _manager
    if _manager is None:
        _manager = BlockManager()
    return _manager
