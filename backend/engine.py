from datetime import datetime
from typing import Dict, List, Any, Optional

from backend.config import backend_settings
from backend.services.bundle_monitor import bundle_monitor
from backend.services.crawler import crawler
from backend.services.inventory_manager import inventory_manager
from backend.test_planner import test_planner, TestPlan, TestCasePlan
from backend.checks.access_control import AccessControlCheck
from backend.checks.business_logic import BusinessLogicCheck
from backend.checks.input_handling import InputHandlingCheck
from backend.checks.api_hygiene import ApiHygieneCheck
from backend.verifier import verifier
from backend.scoring import scorer
from backend.tickets import ticket_manager, SecurityTicket

class RegressionEngine:
    """
    Central DAST Pipeline Orchestrator:
    Orchestrates the entire automated regression workflow:
    Change Detection -> Inventory Reconciliation -> Prioritized Planning ->
    Safety-Guarded Check Execution -> Minimal Reproduction Verification ->
    Business Impact Scoring -> Ticket Management & Auto-Closure.
    """

    def __init__(self, target_base_url: str = backend_settings.TARGET_APP_URL):
        self.target_base_url = target_base_url
        self.checks = {
            "AUTHORIZATION_BOUNDARY": AccessControlCheck(),
            "ROLE_BOUNDARY": AccessControlCheck(),
            "BUSINESS_LOGIC": BusinessLogicCheck(),
            "INPUT_HANDLING": InputHandlingCheck(),
            "API_HYGIENE": ApiHygieneCheck()
        }

    def run_pipeline(
        self,
        deployment_version: str = "v2.0.0",
        bundle_url: Optional[str] = None
    ) -> Dict[str, Any]:
        run_id = f"RUN-{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        start_ts = datetime.utcnow().isoformat()

        # 1. Bundle change monitor
        target_bundle = bundle_url or f"{self.target_base_url}/static/app.v2.js"
        bundle_changed, bundle_info, prev_hash = bundle_monitor.inspect_bundle(target_bundle)

        # 2. Inventory & Crawler Reconciliation
        inventory = inventory_manager.reconcile_and_update_inventory()

        # 3. Dynamic Test Plan Generation
        plan: TestPlan = test_planner.generate_plan(deployment_version=deployment_version)

        check_results = []
        confirmed_tickets: List[SecurityTicket] = []

        # 4. Check Execution through Safety Layer
        for tc in plan.test_cases:
            check_handler = self.checks.get(tc.category.value, self.checks["BUSINESS_LOGIC"])
            res = check_handler.run(tc, self.target_base_url)
            check_results.append(res)

            # 5. Minimal Reproduction Verification
            if res.vulnerability_detected:
                is_reproducible, evidence = verifier.verify(res)
                if is_reproducible:
                    # 6. Business Impact Scoring
                    impact_data = scorer.calculate_impact(
                        test_id=tc.test_id,
                        category=tc.category.value,
                        target_endpoint=tc.target_endpoint,
                        response_body=res.response_body
                    )

                    # 7. File Confirmed Ticket
                    ticket = ticket_manager.file_ticket(
                        test_id=tc.test_id,
                        title=f"{tc.category.value}: {tc.description}",
                        category=tc.category.value,
                        target_endpoint=tc.target_endpoint,
                        impact_data=impact_data,
                        reproduction_curl=evidence.get("reproduction_curl", ""),
                        reproduction_request=res.reproduction_request,
                        expected_secure_status=tc.expected_secure_status
                    )
                    confirmed_tickets.append(ticket)

        return {
            "run_id": run_id,
            "timestamp": start_ts,
            "deployment_version": deployment_version,
            "bundle_changed": bundle_changed,
            "bundle_hash": bundle_info.content_hash,
            "total_tests_planned": len(plan.test_cases),
            "findings_count": len(confirmed_tickets),
            "confirmed_tickets": [t.model_dump() for t in confirmed_tickets],
            "inventory_summary": {
                "total": len(inventory),
                "active": len([i for i in inventory if i.status == "Active"]),
                "zombie": len([i for i in inventory if "zombie" in i.status.lower()]),
                "shadow": len([i for i in inventory if "shadow" in i.status.lower()])
            }
        }

engine = RegressionEngine()
