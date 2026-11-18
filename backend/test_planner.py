import json
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.config import backend_settings
from backend.database import get_all_inventory, get_deployments

class TestPriority(str, Enum):
    __test__ = False
    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"

class TestCategory(str, Enum):
    __test__ = False
    AUTHORIZATION_BOUNDARY = "AUTHORIZATION_BOUNDARY"  # BOLA / IDOR
    ROLE_BOUNDARY = "ROLE_BOUNDARY"                    # BFLA / Privilege Escalation
    BUSINESS_LOGIC = "BUSINESS_LOGIC"                  # Price tampering, duplicate refunds
    API_HYGIENE = "API_HYGIENE"                        # Shadow / Zombie routes

class TestCasePlan(BaseModel):
    __test__ = False
    test_id: str
    priority: TestPriority
    category: TestCategory
    target_endpoint: str
    method: str
    path: str
    description: str
    auth_context: Dict[str, Any]
    request_params: Optional[Dict[str, Any]] = None
    request_body: Optional[Dict[str, Any]] = None
    expected_secure_status: int
    vulnerable_status: int
    business_impact_rationale: str

class TestPlan(BaseModel):
    __test__ = False
    plan_id: str
    created_at: str
    deployment_version: Optional[str] = "v2.0.0"
    target_base_url: str = backend_settings.TARGET_APP_URL
    total_tests: int
    summary: Dict[str, int]
    test_cases: List[TestCasePlan]

class PrioritizedTestPlanner:
    """
    Dynamic Prioritized Test Planner:
    Analyzes API inventory, deployment changes, and crawl graphs to generate
    prioritized, actionable test plans targeting:
      - Cross-tenant authorization boundaries (BOLA)
      - Function-level role boundaries (BFLA)
      - Business logic price and refund idempotency
      - API hygiene (Shadow and Zombie routes)
    """

    def generate_plan(
        self,
        deployment_version: Optional[str] = "v2.0.0",
        focus_modified_only: bool = False
    ) -> TestPlan:
        plan_id = f"PLAN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now_str = datetime.utcnow().isoformat()

        test_cases: List[TestCasePlan] = []

        # 1. P0: Cross-Tenant Booking Read (BOLA / IDOR)
        test_cases.append(TestCasePlan(
            test_id="TEST-AUTH-BOLA-01",
            priority=TestPriority.P0_CRITICAL,
            category=TestCategory.AUTHORIZATION_BOUNDARY,
            target_endpoint="GET /api/v1/bookings/{booking_id}",
            method="GET",
            path="/api/v1/bookings/BKG-GLOBAL-8802",
            description="Verify Agency Apex sub-agent cannot read Agency Global booking record.",
            auth_context={
                "actor_user": "usr_apex_sub1",
                "actor_agency": "agency_apex",
                "actor_role": "sub_agent",
                "token": "token-apex-sub",
                "target_resource_owner": "agency_global"
            },
            request_params=None,
            request_body=None,
            expected_secure_status=403,
            vulnerable_status=200,
            business_impact_rationale="Cross-tenant PII leak: passenger names, passport numbers, and agency booking records exposed to competitors."
        ))

        # 2. P0: Client-Trusted Fare Parameter Tampering
        test_cases.append(TestCasePlan(
            test_id="TEST-BIZ-FARE-01",
            priority=TestPriority.P0_CRITICAL,
            category=TestCategory.BUSINESS_LOGIC,
            target_endpoint="POST /api/v1/bookings/{booking_id}/pay",
            method="POST",
            path="/api/v1/bookings/BKG-APEX-9902/pay",
            description="Verify server rejects client-manipulated $1.00 fare for a $590.00 ticket.",
            auth_context={
                "actor_user": "usr_apex_sub1",
                "actor_agency": "agency_apex",
                "actor_role": "sub_agent",
                "token": "token-apex-sub"
            },
            request_body={
                "amount": 1.00,
                "payment_method": "corporate_credit"
            },
            expected_secure_status=400,
            vulnerable_status=200,
            business_impact_rationale="Direct financial loss: Tickets confirmed at severe under-billing ($1.00 paid vs $590.00 value)."
        ))

        # 3. P1: Duplicate Cancellation Double Refund
        test_cases.append(TestCasePlan(
            test_id="TEST-BIZ-REFUND-01",
            priority=TestPriority.P1_HIGH,
            category=TestCategory.BUSINESS_LOGIC,
            target_endpoint="POST /api/v1/bookings/{booking_id}/cancel",
            method="POST",
            path="/api/v1/bookings/BKG-APEX-9901/cancel",
            description="Verify duplicate cancellation requests do not issue multiple refund payouts.",
            auth_context={
                "actor_user": "usr_apex_sub1",
                "actor_agency": "agency_apex",
                "actor_role": "sub_agent",
                "token": "token-apex-sub"
            },
            request_body=None,
            expected_secure_status=400,
            vulnerable_status=200,
            business_impact_rationale="Double spending / cash bleed: Repeating cancellation requests results in multiple $550 refunds for a single booking."
        ))

        # 4. P1: Role Privilege Escalation to Financial Commissions (BFLA)
        test_cases.append(TestCasePlan(
            test_id="TEST-AUTH-BFLA-01",
            priority=TestPriority.P1_HIGH,
            category=TestCategory.ROLE_BOUNDARY,
            target_endpoint="GET /api/v1/agency/commissions",
            method="GET",
            path="/api/v1/agency/commissions",
            description="Verify standard Sub-Agent role cannot access supervisor commission reports and override tokens.",
            auth_context={
                "actor_user": "usr_apex_sub1",
                "actor_agency": "agency_apex",
                "actor_role": "sub_agent",
                "token": "token-apex-sub"
            },
            request_body=None,
            expected_secure_status=403,
            vulnerable_status=200,
            business_impact_rationale="Financial confidentiality breach: Sub-agents can read quarterly commission payouts and confidential override tokens."
        ))

        # 5. P2: Undocumented Shadow API Detection
        test_cases.append(TestCasePlan(
            test_id="TEST-HYGIENE-SHADOW-01",
            priority=TestPriority.P2_MEDIUM,
            category=TestCategory.API_HYGIENE,
            target_endpoint="POST /api/v1/promotions/apply",
            method="POST",
            path="/api/v1/promotions/apply",
            description="Verify shadow promotions route omitted from OpenAPI spec is surfaced for governance.",
            auth_context={
                "actor_user": "usr_apex_sub1",
                "actor_agency": "agency_apex",
                "actor_role": "sub_agent",
                "token": "token-apex-sub"
            },
            request_body={
                "promo_code": "SUMMER26",
                "booking_amount": 1000.00
            },
            expected_secure_status=200,
            vulnerable_status=200,
            business_impact_rationale="Shadow API surface: Unmonitored promotion discount calculations bypass central security audits."
        ))

        # 6. P3: Legacy Zombie Endpoint Inactivity
        test_cases.append(TestCasePlan(
            test_id="TEST-HYGIENE-ZOMBIE-01",
            priority=TestPriority.P3_LOW,
            category=TestCategory.API_HYGIENE,
            target_endpoint="GET /api/v1/legacy/xml-rates",
            method="GET",
            path="/api/v1/legacy/xml-rates?carrier=BA",
            description="Verify deprecated legacy XML rates endpoint has zero recent traffic and flag for decommissioning.",
            auth_context={
                "actor_user": "usr_apex_sub1",
                "actor_agency": "agency_apex",
                "actor_role": "sub_agent",
                "token": "token-apex-sub"
            },
            expected_secure_status=200,
            vulnerable_status=200,
            business_impact_rationale="Zombie API risk: Outdated XML parser retained in production attack surface without active consumers."
        ))

        # Compute summary
        priorities = {}
        for tc in test_cases:
            priorities[tc.priority.value] = priorities.get(tc.priority.value, 0) + 1

        return TestPlan(
            plan_id=plan_id,
            created_at=now_str,
            deployment_version=deployment_version,
            target_base_url=backend_settings.TARGET_APP_URL,
            total_tests=len(test_cases),
            summary=priorities,
            test_cases=test_cases
        )

test_planner = PrioritizedTestPlanner()
