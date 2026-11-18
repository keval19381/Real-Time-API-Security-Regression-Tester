import pytest
import httpx
from backend.test_planner import test_planner
from backend.checks.access_control import AccessControlCheck
from backend.scoring import scorer
from backend.verifier import verifier
from backend.tickets import ticket_manager

BACKEND_BASE = "http://127.0.0.1:8000"
TARGET_APP_BASE = "http://127.0.0.1:8001"

def set_target_app_security(vulnerable: bool):
    with httpx.Client(base_url=TARGET_APP_BASE, timeout=5.0) as client:
        client.post(f"/admin/set-mode?vulnerable={'true' if vulnerable else 'false'}")
        client.post("/admin/reset-state")

@pytest.fixture(scope="module")
def http_client():
    with httpx.Client(base_url=BACKEND_BASE, timeout=15.0) as client:
        yield client

class TestTicketLifecycleAndAutoResolution:
    def test_file_ticket_and_verify_storage(self):
        # File a test ticket
        impact = scorer.calculate_impact(
            test_id="TEST-AUTH-BOLA-01",
            category="AUTHORIZATION_BOUNDARY",
            target_endpoint="GET /api/v1/bookings/{id}"
        )
        ticket = ticket_manager.file_ticket(
            test_id="TEST-AUTH-BOLA-01",
            title="BOLA Cross-Tenant Data Leak",
            category="AUTHORIZATION_BOUNDARY",
            target_endpoint="GET /api/v1/bookings/{booking_id}",
            impact_data=impact,
            reproduction_curl="curl -X GET http://127.0.0.1:8001/api/v1/bookings/BKG-GLOBAL-8802",
            reproduction_request={
                "method": "GET",
                "url": "http://127.0.0.1:8001/api/v1/bookings/BKG-GLOBAL-8802",
                "headers": {"Authorization": "Bearer token-apex-sub"}
            },
            expected_secure_status=403
        )
        assert ticket.ticket_id.startswith("TICK-")
        assert ticket.status == "CONFIRMED"
        assert ticket.severity in ("CRITICAL", "HIGH")

        # Verify retrieval from ticket manager
        all_tickets = ticket_manager.get_all_tickets()
        assert any(t.ticket_id == ticket.ticket_id for t in all_tickets)

    def test_retest_and_autoclosure_when_fixed(self):
        # 1. Start in buggy mode: ensure ticket is filed and status is CONFIRMED
        set_target_app_security(vulnerable=True)

        impact = scorer.calculate_impact("TEST-AUTH-BOLA-01", "AUTHORIZATION_BOUNDARY", "GET /api/v1/bookings/{id}")
        ticket = ticket_manager.file_ticket(
            test_id="TEST-AUTH-BOLA-01",
            title="BOLA Cross-Tenant Data Leak",
            category="AUTHORIZATION_BOUNDARY",
            target_endpoint="GET /api/v1/bookings/{booking_id}",
            impact_data=impact,
            reproduction_curl="curl -X GET http://127.0.0.1:8001/api/v1/bookings/BKG-GLOBAL-8802",
            reproduction_request={
                "method": "GET",
                "url": "http://127.0.0.1:8001/api/v1/bookings/BKG-GLOBAL-8802",
                "headers": {"Authorization": "Bearer token-apex-sub"}
            },
            expected_secure_status=403
        )
        assert ticket.status == "CONFIRMED"

        # 2. Switch target app to FIXED mode
        set_target_app_security(vulnerable=False)

        # 3. Trigger retest: ticket manager re-runs reproduction request
        retest_results = ticket_manager.retest_open_tickets(TARGET_APP_BASE)
        assert len(retest_results) >= 1

        # 4. Verify ticket auto-closed to RESOLVED
        updated_tickets = ticket_manager.get_all_tickets()
        target_ticket = next(t for t in updated_tickets if t.ticket_id == ticket.ticket_id)
        assert target_ticket.status == "RESOLVED"
        assert target_ticket.resolved_at is not None
        assert target_ticket.resolution_evidence["verified_fixed"] is True
        assert target_ticket.resolution_evidence["retest_status"] == 403


class TestPipelineAndDashboardEndpoints:
    def test_run_dast_pipeline_endpoint(self, http_client):
        set_target_app_security(vulnerable=True)
        res = http_client.post("/api/pipeline/run?version=v2.0.0")
        assert res.status_code == 200
        data = res.json()
        assert "run_id" in data
        assert data["findings_count"] >= 3
        assert len(data["confirmed_tickets"]) >= 3

    def test_get_tickets_endpoint(self, http_client):
        res = http_client.get("/api/tickets")
        assert res.status_code == 200
        tickets = res.json()
        assert isinstance(tickets, list)
        assert len(tickets) >= 1

    def test_retest_tickets_endpoint(self, http_client):
        res = http_client.post("/api/tickets/retest")
        assert res.status_code == 200
        results = res.json()
        assert isinstance(results, list)

    def test_dashboard_html_served(self, http_client):
        res = http_client.get("/dashboard")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "Real-Time API Security Regression Platform" in res.text
        assert "LIVE DAST" in res.text

    def test_root_serves_dashboard(self, http_client):
        res = http_client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "Real-Time API Security Regression Platform" in res.text
