from typing import Dict, Any, List

class SeverityScorer:
    """
    Business Impact & Severity Scoring Engine:
    Calculates weighted domain risk formula:
      Impact = 5*(Financial Loss) + 4*(PII Exposure) + 3*(Auth Bypass) + 1*(Hygiene)
    Maps score to standardized severity tiers (CRITICAL, HIGH, MEDIUM, LOW).
    """

    def calculate_impact(
        self,
        test_id: str,
        category: str,
        target_endpoint: str,
        response_body: Any = None
    ) -> Dict[str, Any]:
        fin_loss = 0
        pii_exp = 0
        auth_bypass = 0
        hygiene = 0
        pii_fields: List[str] = []
        financial_summary = "No direct financial exposure identified."

        if "BOLA" in test_id:
            # Cross-agency booking read
            auth_bypass = 4
            pii_exp = 4
            pii_fields = ["passenger_name", "passenger_email", "passport_number", "booking_id", "agency_id"]
            remediation = (
                "Enforce tenant authorization check in routes/book.py: "
                "verify booking.agency_id == current_user.agency_id before returning booking data. Return 403 Forbidden on mismatch."
            )

        elif "FARE" in test_id:
            # Client fare tampering
            fin_loss = 5
            auth_bypass = 2
            financial_summary = "High financial loss: Server confirms booking using arbitrary client-submitted price."
            remediation = (
                "In routes/pay.py, validate submitted amount against server-side hold locked fare (booking.total_amount). "
                "Reject price tampering with 400 Bad Request."
            )

        elif "REFUND" in test_id:
            # Duplicate cancellation double refund
            fin_loss = 4
            financial_summary = "Duplicate payout risk: Concurrent or sequential cancellation emits multiple cash refunds."
            remediation = (
                "In routes/cancel.py, enforce strict state machine locking. "
                "If booking.status == 'CANCELLED', reject subsequent requests with 400 Bad Request."
            )

        elif "BFLA" in test_id:
            # Admin commissions privilege escalation
            auth_bypass = 4
            fin_loss = 2
            financial_summary = "Confidential financial intelligence and override tokens exposed to standard sub-agents."
            remediation = (
                "In routes/admin.py, add RBAC guard: verify current_user.role == 'agency_admin' "
                "before returning commission statements. Return 403 Forbidden for sub-agents."
            )

        elif "SHADOW" in test_id:
            hygiene = 4
            remediation = (
                "Include shadow route in public OpenAPI spec (remove include_in_schema=False in routes/shadow.py) "
                "or retire route if decommissioned."
            )

        elif "ZOMBIE" in test_id:
            hygiene = 3
            remediation = (
                "Decommission legacy XML endpoint (routes/legacy.py) or migrate legacy consumers to /api/v1/flights/search."
            )

        else:
            auth_bypass = 1
            remediation = "Apply standard input validation and tenant boundary checks."

        # Compute weighted formula
        score = (5 * fin_loss) + (4 * pii_exp) + (3 * auth_bypass) + (1 * hygiene)

        if score >= 20:
            severity = "CRITICAL"
        elif score >= 12:
            severity = "HIGH"
        elif score >= 6:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "severity": severity,
            "impact_score": score,
            "weights": {
                "financial_loss": fin_loss,
                "pii_exposure": pii_exp,
                "auth_bypass": auth_bypass,
                "api_hygiene": hygiene
            },
            "financial_summary": financial_summary,
            "pii_fields_exposed": pii_fields,
            "remediation_guide": remediation
        }

scorer = SeverityScorer()
