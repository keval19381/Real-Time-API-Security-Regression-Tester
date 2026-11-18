import time
import httpx
from typing import Dict, Any
from backend.checks.base import BaseCheck, CheckResult
from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger
from backend.test_planner import TestCasePlan

class ApiHygieneCheck(BaseCheck):
    """
    Evaluates API Hygiene & Surface Governance:
    Identifies shadow endpoints (active routes omitted from OpenAPI spec)
    and zombie endpoints (deprecated routes with zero active traffic).
    """

    def __init__(self):
        super().__init__(
            name="ApiHygieneCheck",
            category="API_HYGIENE",
            description="Detects undocumented shadow APIs and unmaintained zombie endpoints."
        )

    def run(self, test_case: TestCasePlan, target_base_url: str) -> CheckResult:
        url = f"{target_base_url}{test_case.path}"
        token = test_case.auth_context.get("token", "token-apex-sub")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        reproduction = {
            "method": test_case.method,
            "url": url,
            "headers": headers,
            "json": test_case.request_body
        }

        start_time = time.time()
        with httpx.Client(timeout=8.0) as client:
            try:
                response = safety_guard.dispatch_safe_request(
                    client=client,
                    method=test_case.method,
                    url=url,
                    headers=headers,
                    json=test_case.request_body,
                    audit_log_fn=audit_logger.record
                )
                latency = (time.time() - start_time) * 1000.0

                resp_data = None
                try:
                    resp_data = response.json()
                except Exception:
                    resp_data = response.text

                # For shadow / zombie routes, the endpoint responds with 200, but its documentation state constitutes the hygiene flaw
                is_shadow = "SHADOW" in test_case.test_id
                is_zombie = "ZOMBIE" in test_case.test_id

                # Flag finding if shadow route is active (200 OK) or zombie route still responds
                finding_detected = (response.status_code == 200)

                return CheckResult(
                    check_name=self.name,
                    test_id=test_case.test_id,
                    target_endpoint=test_case.target_endpoint,
                    method=test_case.method,
                    url=url,
                    vulnerability_detected=finding_detected,
                    status_code=response.status_code,
                    expected_status=test_case.expected_secure_status,
                    response_body=resp_data,
                    reproduction_request=reproduction,
                    latency_ms=round(latency, 2)
                )

            except Exception as e:
                latency = (time.time() - start_time) * 1000.0
                return CheckResult(
                    check_name=self.name,
                    test_id=test_case.test_id,
                    target_endpoint=test_case.target_endpoint,
                    method=test_case.method,
                    url=url,
                    vulnerability_detected=False,
                    status_code=500,
                    expected_status=test_case.expected_secure_status,
                    reproduction_request=reproduction,
                    error_message=str(e),
                    latency_ms=round(latency, 2)
                )
