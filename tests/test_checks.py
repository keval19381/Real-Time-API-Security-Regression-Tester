import pytest
import httpx
from backend.test_planner import test_planner
from backend.checks.access_control import AccessControlCheck
from backend.checks.business_logic import BusinessLogicCheck
from backend.checks.input_handling import InputHandlingCheck
from backend.checks.api_hygiene import ApiHygieneCheck
from backend.verifier import verifier
from backend.scoring import scorer

TARGET_APP_BASE = "http://127.0.0.1:8001"

def set_target_mode(vulnerable: bool):
    with httpx.Client(base_url=TARGET_APP_BASE, timeout=5.0) as client:
        client.post(f"/admin/set-mode?vulnerable={'true' if vulnerable else 'false'}")
        client.post("/admin/reset-state")

@pytest.fixture(autouse=True)
def setup_state():
    set_target_mode(vulnerable=True)
    yield

class TestAccessControlChecks:
    def test_bola_check_detects_bug_and_mitigation(self):
        plan = test_planner.generate_plan()
        bola_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-AUTH-BOLA-01")
        check = AccessControlCheck()

        # In buggy mode: BOLA vulnerability detected
        set_target_mode(vulnerable=True)
        res_buggy = check.run(bola_tc, TARGET_APP_BASE)
        assert res_buggy.vulnerability_detected is True
        assert res_buggy.status_code == 200

        # In fixed mode: BOLA blocked
        set_target_mode(vulnerable=False)
        res_fixed = check.run(bola_tc, TARGET_APP_BASE)
        assert res_fixed.vulnerability_detected is False
        assert res_fixed.status_code == 403

    def test_bfla_check_detects_bug_and_mitigation(self):
        plan = test_planner.generate_plan()
        bfla_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-AUTH-BFLA-01")
        check = AccessControlCheck()

        # In buggy mode: BFLA privilege escalation detected
        set_target_mode(vulnerable=True)
        res_buggy = check.run(bfla_tc, TARGET_APP_BASE)
        assert res_buggy.vulnerability_detected is True
        assert res_buggy.status_code == 200

        # In fixed mode: Sub-agent rejected with 403
        set_target_mode(vulnerable=False)
        res_fixed = check.run(bfla_tc, TARGET_APP_BASE)
        assert res_fixed.vulnerability_detected is False
        assert res_fixed.status_code == 403


class TestBusinessLogicChecks:
    def test_fare_tampering_check(self):
        plan = test_planner.generate_plan()
        fare_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-BIZ-FARE-01")
        check = BusinessLogicCheck()

        # Buggy mode: tampered fare accepted
        set_target_mode(vulnerable=True)
        res_buggy = check.run(fare_tc, TARGET_APP_BASE)
        assert res_buggy.vulnerability_detected is True
        assert res_buggy.status_code == 200

        # Fixed mode: rejected with 400 Bad Request
        set_target_mode(vulnerable=False)
        res_fixed = check.run(fare_tc, TARGET_APP_BASE)
        assert res_fixed.vulnerability_detected is False
        assert res_fixed.status_code == 400

    def test_duplicate_refund_check(self):
        plan = test_planner.generate_plan()
        refund_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-BIZ-REFUND-01")
        check = BusinessLogicCheck()

        # Buggy mode: duplicate refund emitted
        set_target_mode(vulnerable=True)
        res_buggy = check.run(refund_tc, TARGET_APP_BASE)
        assert res_buggy.vulnerability_detected is True
        assert res_buggy.status_code == 200

        # Fixed mode: duplicate refund rejected with 400
        set_target_mode(vulnerable=False)
        res_fixed = check.run(refund_tc, TARGET_APP_BASE)
        assert res_fixed.vulnerability_detected is False
        assert res_fixed.status_code == 400


class TestMinimalReproductionVerifier:
    def test_reproduction_verification(self):
        plan = test_planner.generate_plan()
        bola_tc = next(tc for tc in plan.test_cases if tc.test_id == "TEST-AUTH-BOLA-01")
        check = AccessControlCheck()

        set_target_mode(vulnerable=True)
        primary_result = check.run(bola_tc, TARGET_APP_BASE)
        assert primary_result.vulnerability_detected is True

        # Run minimal reproduction pass
        is_reproducible, evidence = verifier.verify(primary_result)
        assert is_reproducible is True
        assert "reproduction_curl" in evidence
        assert evidence["pass1_status"] == 200
        assert evidence["pass2_status"] == 200
        assert "curl -X GET" in evidence["reproduction_curl"]


class TestSeverityScoring:
    def test_scoring_weights_and_thresholds(self):
        # BOLA score: auth(4)*3 + pii(4)*4 = 12 + 16 = 28 -> CRITICAL
        bola_score = scorer.calculate_impact(
            test_id="TEST-AUTH-BOLA-01",
            category="AUTHORIZATION_BOUNDARY",
            target_endpoint="GET /api/v1/bookings/{id}"
        )
        assert bola_score["severity"] in ("CRITICAL", "HIGH")
        assert bola_score["impact_score"] >= 20
        assert "passenger_name" in bola_score["pii_fields_exposed"]

        # Fare tampering: fin(5)*5 + auth(2)*3 = 25 + 6 = 31 -> CRITICAL
        fare_score = scorer.calculate_impact(
            test_id="TEST-BIZ-FARE-01",
            category="BUSINESS_LOGIC",
            target_endpoint="POST /api/v1/bookings/{id}/pay"
        )
        assert fare_score["severity"] == "CRITICAL"
        assert fare_score["impact_score"] >= 25

        # Hygiene check: hygiene(4)*1 = 4 -> LOW
        shadow_score = scorer.calculate_impact(
            test_id="TEST-HYGIENE-SHADOW-01",
            category="API_HYGIENE",
            target_endpoint="POST /api/v1/promotions/apply"
        )
        assert shadow_score["severity"] == "LOW"
        assert shadow_score["impact_score"] <= 5
