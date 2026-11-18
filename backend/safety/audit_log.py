import hashlib
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from backend.config import backend_settings

GENESIS_HASH = "0" * 64

class AuditLogger:
    """
    Append-Only Cryptographic Hash-Chained Audit Log:
    Every outbound security check request and target response is cryptographically
    linked to its predecessor via SHA-256, guaranteeing tamper-evident auditability.
    """

    def __init__(self, db_path: str = backend_settings.DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            entry_index INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            nonce TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            response_status INTEGER NOT NULL,
            response_hash TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )
        """)
        conn.commit()
        conn.close()

    def _hash_data(self, data: Any) -> str:
        if data is None:
            raw = ""
        elif isinstance(data, (dict, list)):
            raw = json.dumps(data, sort_keys=True)
        else:
            raw = str(data)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _calculate_entry_hash(
        self,
        index: int,
        timestamp: str,
        nonce: str,
        method: str,
        url: str,
        request_hash: str,
        response_status: int,
        response_hash: str,
        prev_hash: str
    ) -> str:
        payload = f"{index}|{timestamp}|{nonce}|{method}|{url}|{request_hash}|{response_status}|{response_hash}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_latest_hash_and_index(self) -> Tuple[str, int]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT entry_index, entry_hash FROM audit_log ORDER BY entry_index DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if row:
            return row["entry_hash"], row["entry_index"]
        return GENESIS_HASH, -1

    def record(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        response_status: int = 200,
        response_body: Optional[Any] = None,
        latency_ms: float = 0.0
    ) -> Dict[str, Any]:
        """
        Records a test event and computes its cryptographic link in the hash chain.
        """
        prev_hash, last_index = self.get_latest_hash_and_index()
        current_index = last_index + 1
        timestamp = datetime.utcnow().isoformat()
        nonce = uuid.uuid4().hex

        # Combine headers and body for request hash
        req_obj = {"headers": headers or {}, "body": body}
        request_hash = self._hash_data(req_obj)
        response_hash = self._hash_data(response_body)

        entry_hash = self._calculate_entry_hash(
            index=current_index,
            timestamp=timestamp,
            nonce=nonce,
            method=method,
            url=url,
            request_hash=request_hash,
            response_status=response_status,
            response_hash=response_hash,
            prev_hash=prev_hash
        )

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO audit_log (
            entry_index, timestamp, nonce, method, url, request_hash,
            response_status, response_hash, latency_ms, prev_hash, entry_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_index,
            timestamp,
            nonce,
            method,
            url,
            request_hash,
            response_status,
            response_hash,
            latency_ms,
            prev_hash,
            entry_hash
        ))
        conn.commit()
        conn.close()

        return {
            "entry_index": current_index,
            "timestamp": timestamp,
            "method": method,
            "url": url,
            "response_status": response_status,
            "entry_hash": entry_hash,
            "prev_hash": prev_hash
        }

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verifies the cryptographic continuity of the entire hash chain from index 0 to head.
        Returns: (True, None) if completely intact, or (False, "Reason...") if tampered.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log ORDER BY entry_index ASC")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return True, "Audit log is empty (intact)."

        expected_prev_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            if row["entry_index"] != idx:
                return False, f"Sequence gap or broken index at expected position {idx}, found {row['entry_index']}"

            if row["prev_hash"] != expected_prev_hash:
                return False, f"Hash chain broken at index {idx}! Stored prev_hash '{row['prev_hash']}' does not match expected '{expected_prev_hash}'"

            # Recompute entry hash
            recomputed = self._calculate_entry_hash(
                index=row["entry_index"],
                timestamp=row["timestamp"],
                nonce=row["nonce"],
                method=row["method"],
                url=row["url"],
                request_hash=row["request_hash"],
                response_status=row["response_status"],
                response_hash=row["response_hash"],
                prev_hash=row["prev_hash"]
            )

            if recomputed != row["entry_hash"]:
                return False, f"Entry content tampering detected at index {idx}! Stored hash '{row['entry_hash']}' != recomputed '{recomputed}'"

            expected_prev_hash = row["entry_hash"]

        return True, f"Cryptographic integrity verified across all {len(rows)} chained entries."

    def get_entries(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log ORDER BY entry_index DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

audit_logger = AuditLogger()
