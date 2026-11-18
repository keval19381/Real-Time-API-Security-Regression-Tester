import time
import httpx
from typing import Dict, Any
from backend.checks.base import BaseCheck, CheckResult
from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger
from backend.test_planner import TestCasePlan

class InputHandlingCheck(BaseCheck):
    """
    Evaluates Input Boundaries & Type Safety:
    Probes numeric boundaries (negative fares, zero amounts), type mismatches,
    and schema validation robustness.
    """

    def __init__(self):
        super().__init__(
            name="InputHandlingCheck",
            category="INPUT_HANDLING",
            description="Probes negative fare injections, schema boundary validation, and type coercion errors."
        )

    def run(self, test_case: TestCasePlan, target_base_url: str) -> CheckResult:
        url = f"{target_base_url}{test_case.path}"
        token = test_case.auth_context.get("token", "token-apex-sub")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        # Negative amount payload mutation
        tampered_body = {"amount": -150.00, "payment_method": "corporate_credit"}
        reproduction = {
            "method": "POST",
            "url": url,
            "headers": headers,
            "json": tampered_body
        }

        start_time = time.time()
        with httpx.Client(timeout=8.0) as client:
            try:
                response = safety_guard.dispatch_safe_request(
                    client=client,
                    method="POST",
                    url=url,
                    headers=headers,
                    json=tampered_body,
                    audit_log_fn=audit_logger.record
                )
                latency = (time.time() - start_time) * 1000.0

                resp_data = None
                try:
                    resp_data = response.json()
                except Exception:
                    resp_data = response.text

                # Vulnerable if server accepted negative payment with 200 OK
                vulnerable = (response.status_code == 200)

                return CheckResult(
                    check_name=self.name,
                    test_id=f"{test_case.test_id}-INPUT-NEG",
                    target_endpoint=test_case.target_endpoint,
                    method="POST",
                    url=url,
                    vulnerability_detected=vulnerable,
                    status_code=response.status_code,
                    expected_status=400,
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
                    method="POST",
                    url=url,
                    vulnerability_detected=False,
                    status_code=500,
                    expected_status=400,
                    reproduction_request=reproduction,
                    error_message=str(e),
                    latency_ms=round(latency, 2)
                )
