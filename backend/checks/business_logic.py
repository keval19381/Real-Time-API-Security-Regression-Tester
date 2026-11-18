import time
import httpx
from typing import Dict, Any
from backend.checks.base import BaseCheck, CheckResult
from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger
from backend.test_planner import TestCasePlan

class BusinessLogicCheck(BaseCheck):
    """
    Evaluates Domain Business Logic Integrity:
    1. Client-Side Fare Override: Verifies server validates price integrity and rejects manipulated amounts.
    2. Cancellation Idempotency & Double Refund: Verifies state locks prevent duplicate payouts.
    """

    def __init__(self):
        super().__init__(
            name="BusinessLogicCheck",
            category="BUSINESS_LOGIC",
            description="Detects client price tampering and duplicate cancellation double-refund cash bleeds."
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
                # Special handling for duplicate refund idempotency test
                if "REFUND" in test_case.test_id:
                    # 1st cancel request (sets state to cancelled)
                    res1 = safety_guard.dispatch_safe_request(
                        client=client,
                        method="POST",
                        url=url,
                        headers=headers,
                        audit_log_fn=audit_logger.record
                    )
                    # 2nd duplicate cancel request (tests idempotency lock)
                    res2 = safety_guard.dispatch_safe_request(
                        client=client,
                        method="POST",
                        url=url,
                        headers=headers,
                        audit_log_fn=audit_logger.record
                    )
                    latency = (time.time() - start_time) * 1000.0
                    
                    # Vulnerable if second request also returned 200 (duplicate refund processed)
                    vulnerable = (res2.status_code == 200)

                    resp_data = None
                    try:
                        resp_data = res2.json()
                    except Exception:
                        resp_data = res2.text

                    return CheckResult(
                        check_name=self.name,
                        test_id=test_case.test_id,
                        target_endpoint=test_case.target_endpoint,
                        method=test_case.method,
                        url=url,
                        vulnerability_detected=vulnerable,
                        status_code=res2.status_code,
                        expected_status=test_case.expected_secure_status,
                        response_body=resp_data,
                        reproduction_request=reproduction,
                        latency_ms=round(latency, 2)
                    )

                # Standard single-request logic check (e.g. fare tampering)
                response = safety_guard.dispatch_safe_request(
                    client=client,
                    method=test_case.method,
                    url=url,
                    headers=headers,
                    json=test_case.request_body,
                    audit_log_fn=audit_logger.record
                )
                latency = (time.time() - start_time) * 1000.0

                resp_json = None
                try:
                    resp_json = response.json()
                except Exception:
                    resp_json = response.text

                # In fare tampering: vulnerable if server returned 200 and accepted the tampered amount
                vulnerable = (response.status_code == 200)

                return CheckResult(
                    check_name=self.name,
                    test_id=test_case.test_id,
                    target_endpoint=test_case.target_endpoint,
                    method=test_case.method,
                    url=url,
                    vulnerability_detected=vulnerable,
                    status_code=response.status_code,
                    expected_status=test_case.expected_secure_status,
                    response_body=resp_json,
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
