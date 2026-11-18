import pytest
import httpx
from backend.test_planner import test_planner, TestPriority, TestCategory

BACKEND_BASE = "http://127.0.0.1:8000"

@pytest.fixture(scope="module")
def http_client():
    with httpx.Client(base_url=BACKEND_BASE, timeout=10.0) as client:
        yield client

class TestPrioritizedPlanner:
    def test_plan_generation_structure(self):
        plan = test_planner.generate_plan(deployment_version="v2.1.0")
        assert plan.plan_id.startswith("PLAN-")
        assert plan.deployment_version == "v2.1.0"
        assert plan.total_tests >= 6

        test_ids = [tc.test_id for tc in plan.test_cases]
        assert "TEST-AUTH-BOLA-01" in test_ids
        assert "TEST-BIZ-FARE-01" in test_ids
        assert "TEST-BIZ-REFUND-01" in test_ids
        assert "TEST-AUTH-BFLA-01" in test_ids
        assert "TEST-HYGIENE-SHADOW-01" in test_ids
        assert "TEST-HYGIENE-ZOMBIE-01" in test_ids

    def test_plan_priorities_and_categories(self):
        plan = test_planner.generate_plan()
        
        # Verify P0 tests
        p0_tests = [tc for tc in plan.test_cases if tc.priority == TestPriority.P0_CRITICAL]
        assert len(p0_tests) >= 2
        categories = [tc.category for tc in p0_tests]
        assert TestCategory.AUTHORIZATION_BOUNDARY in categories
        assert TestCategory.BUSINESS_LOGIC in categories

        # Verify summary dictionary matches test count
        total_summary = sum(plan.summary.values())
        assert total_summary == plan.total_tests

    def test_bola_test_case_details(self):
        plan = test_planner.generate_plan()
        bola_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-AUTH-BOLA-01")
        assert bola_tc.method == "GET"
        assert "/api/v1/bookings/" in bola_tc.path
        assert bola_tc.auth_context["actor_agency"] != bola_tc.auth_context["target_resource_owner"]
        assert bola_tc.expected_secure_status == 403
        assert bola_tc.vulnerable_status == 200

    def test_fare_tampering_test_case_details(self):
        plan = test_planner.generate_plan()
        fare_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-BIZ-FARE-01")
        assert fare_tc.method == "POST"
        assert fare_tc.request_body["amount"] == 1.00
        assert fare_tc.expected_secure_status == 400


class TestPhase3RESTEndpoints:
    def test_get_safety_status_endpoint(self, http_client):
        res = http_client.get("/api/safety/status")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "active"
        assert "localhost" in data["safety_guard"]["allowed_hosts"]
        assert data["audit_chain_integrity"]["valid"] is True

    def test_get_audit_log_endpoint(self, http_client):
        res = http_client.get("/api/safety/audit?limit=10")
        assert res.status_code == 200
        entries = res.json()
        assert isinstance(entries, list)

    def test_verify_audit_chain_endpoint(self, http_client):
        res = http_client.get("/api/safety/verify")
        assert res.status_code == 200
        data = res.json()
        assert data["tamper_evident"] is True
        assert data["valid"] is True

    def test_generate_and_latest_test_plan_endpoints(self, http_client):
        # Generate new plan
        post_res = http_client.post("/api/test-plans/generate?version=v2.0.2")
        assert post_res.status_code == 200
        plan = post_res.json()
        assert plan["deployment_version"] == "v2.0.2"
        assert plan["total_tests"] >= 6

        # Fetch latest plan
        get_res = http_client.get("/api/test-plans/latest")
        assert get_res.status_code == 200
        latest = get_res.json()
        assert "test_cases" in latest
        assert len(latest["test_cases"]) >= 6
