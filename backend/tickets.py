import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field
import httpx

from backend.config import backend_settings
from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger

TICKETS_JSON_PATH = "tickets.json"

class SecurityTicket(BaseModel):
    ticket_id: str
    test_id: str
    title: str
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    status: str    # 'OPEN', 'CONFIRMED', 'RESOLVED'
    category: str
    target_endpoint: str
    impact_score: int
    financial_summary: str
    pii_fields_exposed: List[str] = Field(default_factory=list)
    reproduction_curl: str
    reproduction_request: Dict[str, Any]
    expected_secure_status: int
    remediation_guide: str
    created_at: str
    resolved_at: Optional[str] = None
    resolution_evidence: Optional[Dict[str, Any]] = None

class TicketManager:
    """
    Automated Security Ticket Lifecycle & Auto-Closure Engine:
    - Files verified, reproducible findings into persistent SQLite & JSON stores.
    - Preserves exact minimal reproduction requests.
    - Automatically re-tests open tickets when a 'fixed' deployment webhook arrives.
    - Transitions tickets from CONFIRMED -> RESOLVED when re-test proves vulnerability is patched.
    """

    def __init__(self, db_path: str = backend_settings.DB_PATH, json_path: str = TICKETS_JSON_PATH):
        self.db_path = db_path
        self.json_path = json_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            ticket_id TEXT PRIMARY KEY,
            test_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            category TEXT NOT NULL,
            target_endpoint TEXT NOT NULL,
            impact_score INTEGER NOT NULL,
            financial_summary TEXT NOT NULL,
            pii_fields_exposed TEXT,
            reproduction_curl TEXT NOT NULL,
            reproduction_request TEXT NOT NULL,
            expected_secure_status INTEGER NOT NULL,
            remediation_guide TEXT NOT NULL,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            resolution_evidence TEXT
        )
        """)
        conn.commit()
        conn.close()

    def _sync_to_json(self):
        """Dumps all tickets to tickets.json for file-based interoperability."""
        tickets = self.get_all_tickets()
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump([t.model_dump() for t in tickets], f, indent=2)

    def file_ticket(
        self,
        test_id: str,
        title: str,
        category: str,
        target_endpoint: str,
        impact_data: Dict[str, Any],
        reproduction_curl: str,
        reproduction_request: Dict[str, Any],
        expected_secure_status: int
    ) -> SecurityTicket:
        conn = self._get_connection()
        cursor = conn.cursor()

        # Check if an open/confirmed ticket already exists for this test_id
        cursor.execute("SELECT * FROM tickets WHERE test_id = ? AND status != 'RESOLVED'", (test_id,))
        existing = cursor.fetchone()

        if existing:
            ticket_id = existing["ticket_id"]
            created_at = existing["created_at"]
        else:
            code_prefix = test_id.split("-")[1] if "-" in test_id else "SEC"
            ticket_id = f"TICK-{code_prefix}-{uuid.uuid4().hex[:6].upper()}"
            created_at = datetime.utcnow().isoformat()

        ticket = SecurityTicket(
            ticket_id=ticket_id,
            test_id=test_id,
            title=title,
            severity=impact_data["severity"],
            status="CONFIRMED",
            category=category,
            target_endpoint=target_endpoint,
            impact_score=impact_data["impact_score"],
            financial_summary=impact_data["financial_summary"],
            pii_fields_exposed=impact_data.get("pii_fields_exposed", []),
            reproduction_curl=reproduction_curl,
            reproduction_request=reproduction_request,
            expected_secure_status=expected_secure_status,
            remediation_guide=impact_data["remediation_guide"],
            created_at=created_at,
            resolved_at=None,
            resolution_evidence=None
        )

        cursor.execute("""
        INSERT OR REPLACE INTO tickets (
            ticket_id, test_id, title, severity, status, category, target_endpoint,
            impact_score, financial_summary, pii_fields_exposed, reproduction_curl,
            reproduction_request, expected_secure_status, remediation_guide,
            created_at, resolved_at, resolution_evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ticket.ticket_id,
            ticket.test_id,
            ticket.title,
            ticket.severity,
            ticket.status,
            ticket.category,
            ticket.target_endpoint,
            ticket.impact_score,
            ticket.financial_summary,
            json.dumps(ticket.pii_fields_exposed),
            ticket.reproduction_curl,
            json.dumps(ticket.reproduction_request),
            ticket.expected_secure_status,
            ticket.remediation_guide,
            ticket.created_at,
            ticket.resolved_at,
            json.dumps(ticket.resolution_evidence) if ticket.resolution_evidence else None
        ))
        conn.commit()
        conn.close()

        self._sync_to_json()
        return ticket

    def get_all_tickets(self) -> List[SecurityTicket]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tickets ORDER BY impact_score DESC, created_at DESC")
        rows = cursor.fetchall()
        conn.close()

        tickets = []
        for r in rows:
            tickets.append(SecurityTicket(
                ticket_id=r["ticket_id"],
                test_id=r["test_id"],
                title=r["title"],
                severity=r["severity"],
                status=r["status"],
                category=r["category"],
                target_endpoint=r["target_endpoint"],
                impact_score=r["impact_score"],
                financial_summary=r["financial_summary"],
                pii_fields_exposed=json.loads(r["pii_fields_exposed"]) if r["pii_fields_exposed"] else [],
                reproduction_curl=r["reproduction_curl"],
                reproduction_request=json.loads(r["reproduction_request"]),
                expected_secure_status=r["expected_secure_status"],
                remediation_guide=r["remediation_guide"],
                created_at=r["created_at"],
                resolved_at=r["resolved_at"],
                resolution_evidence=json.loads(r["resolution_evidence"]) if r["resolution_evidence"] else None
            ))
        return tickets

    def _reset_target_state(self, client: httpx.Client, base_url: str) -> Optional[str]:
        """
        Resets target app state and returns the first available CONFIRMED booking ID
        for use in REFUND retest (double-cancel idempotency check).
        """
        try:
            client.post(f"{base_url}/admin/reset-state", timeout=5.0)
            # Fetch a fresh booking to cancel twice
            res = client.get(f"{base_url}/api/v1/bookings", headers={"Authorization": "Bearer token-apex-sub"}, timeout=5.0)
            if res.status_code == 200:
                bookings = res.json()
                for b in bookings:
                    if b.get("status") == "CONFIRMED":
                        return b["booking_id"]
        except Exception:
            pass
        return None

    def retest_open_tickets(self, target_base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Re-tests all CONFIRMED tickets against the target service using stored reproduction requests.
        If the target now rejects the exploit with the expected secure status code,
        automatically transitions the ticket to RESOLVED.

        For REFUND (double-cancel idempotency) tickets:
          1. Reset target state so we have a fresh CONFIRMED booking.
          2. Cancel it once (should succeed with 200).
          3. Cancel it again — in FIXED mode this returns 400; in BUGGY mode returns 200.
          4. Resolve ticket only when second cancel returns expected_secure_status (400).
        """
        base_url = target_base_url or backend_settings.TARGET_APP_URL
        tickets = self.get_all_tickets()
        retest_results = []

        with httpx.Client(timeout=6.0) as client:
            for ticket in tickets:
                if ticket.status == "RESOLVED":
                    continue

                req = ticket.reproduction_request
                method = req["method"]
                url = req["url"]
                headers = req.get("headers", {})
                body = req.get("json")

                try:
                    # For duplicate refund idempotency checks:
                    # Reset state → cancel once (prime) → cancel again (this is the check)
                    if "REFUND" in ticket.test_id:
                        fresh_booking_id = self._reset_target_state(client, base_url)
                        if fresh_booking_id:
                            # Rebuild the cancel URL with the fresh booking
                            cancel_url = f"{base_url}/api/v1/bookings/{fresh_booking_id}/cancel"
                        else:
                            cancel_url = url

                        # 1st cancel — prime the cancellation
                        safety_guard.dispatch_safe_request(
                            client=client,
                            method=method,
                            url=cancel_url,
                            headers=headers,
                            json=body,
                            audit_log_fn=audit_logger.record
                        )
                        # 2nd cancel — this is the idempotency check
                        response = safety_guard.dispatch_safe_request(
                            client=client,
                            method=method,
                            url=cancel_url,
                            headers=headers,
                            json=body,
                            audit_log_fn=audit_logger.record
                        )
                    else:
                        response = safety_guard.dispatch_safe_request(
                            client=client,
                            method=method,
                            url=url,
                            headers=headers,
                            json=body,
                            audit_log_fn=audit_logger.record
                        )

                    # Check if bug is now fixed (matches expected secure status, e.g. 403 or 400)
                    is_fixed = (response.status_code == ticket.expected_secure_status)

                    if is_fixed:
                        resolved_at = datetime.utcnow().isoformat()
                        evidence = {
                            "retest_status": response.status_code,
                            "expected_status": ticket.expected_secure_status,
                            "verified_fixed": True,
                            "retest_timestamp": resolved_at,
                            "notes": f"Vulnerability successfully mitigated. Target returned expected secure status {response.status_code}."
                        }

                        conn = self._get_connection()
                        cursor = conn.cursor()
                        cursor.execute("""
                        UPDATE tickets
                        SET status = 'RESOLVED', resolved_at = ?, resolution_evidence = ?
                        WHERE ticket_id = ?
                        """, (resolved_at, json.dumps(evidence), ticket.ticket_id))
                        conn.commit()
                        conn.close()

                        retest_results.append({
                            "ticket_id": ticket.ticket_id,
                            "test_id": ticket.test_id,
                            "status": "RESOLVED",
                            "evidence": evidence
                        })
                    else:
                        retest_results.append({
                            "ticket_id": ticket.ticket_id,
                            "test_id": ticket.test_id,
                            "status": "CONFIRMED_UNFIXED",
                            "current_status": response.status_code
                        })

                except Exception as exc:
                    retest_results.append({
                        "ticket_id": ticket.ticket_id,
                        "test_id": ticket.test_id,
                        "status": "ERROR",
                        "error": str(exc)
                    })

        self._sync_to_json()
        return retest_results

ticket_manager = TicketManager()
