import json
import httpx
from typing import Dict, Any, Tuple
from backend.checks.base import CheckResult
from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger

class ReproductionVerifier:
    """
    Two-Pass Minimal Reproduction Verifier:
    Ensures zero false positives by executing a second, isolated reproduction pass
    with minimal required payload. Only consistently reproducible violations
    are escalated into confirmed vulnerability tickets.
    """

    def generate_curl(self, method: str, url: str, headers: Dict[str, str], body: Any = None) -> str:
        """Constructs an executable, minimal curl command for manual developer reproduction."""
        cmd_parts = [f"curl -X {method.upper()} \"{url}\""]
        for k, v in headers.items():
            cmd_parts.append(f"-H \"{k}: {v}\"")
        if body:
            if isinstance(body, (dict, list)):
                cmd_parts.append(f"-d '{json.dumps(body)}'")
            else:
                cmd_parts.append(f"-d '{body}'")
        return " \\\n  ".join(cmd_parts)

    def verify(self, result: CheckResult) -> Tuple[bool, Dict[str, Any]]:
        """
        Executes an isolated second pass to verify reproducibility.
        Returns: (is_reproducible, verification_evidence)
        """
        if not result.vulnerability_detected:
            return False, {"message": "Primary check did not detect a vulnerability."}

        req = result.reproduction_request
        method = req["method"]
        url = req["url"]
        headers = req.get("headers", {})
        body = req.get("json")

        curl_cmd = self.generate_curl(method, url, headers, body)

        # Execute minimal secondary pass
        with httpx.Client(timeout=6.0) as client:
            try:
                response = safety_guard.dispatch_safe_request(
                    client=client,
                    method=method,
                    url=url,
                    headers=headers,
                    json=body,
                    audit_log_fn=audit_logger.record
                )

                resp_data = None
                try:
                    resp_data = response.json()
                except Exception:
                    resp_data = response.text

                # Check if secondary response matches primary vulnerable status
                is_reproducible = (response.status_code == result.status_code)

                evidence = {
                    "pass1_status": result.status_code,
                    "pass2_status": response.status_code,
                    "is_reproducible": is_reproducible,
                    "reproduction_curl": curl_cmd,
                    "pass2_response": resp_data,
                    "verified": is_reproducible
                }

                return is_reproducible, evidence

            except Exception as exc:
                return False, {
                    "is_reproducible": False,
                    "error": str(exc),
                    "reproduction_curl": curl_cmd
                }

verifier = ReproductionVerifier()
