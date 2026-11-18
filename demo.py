"""
End-to-End Automated Demonstration Script for Real-Time API Security Regression Tester (DAST).
Executes the full pipeline:
  1. Checks health of target app (port 8001) and backend tester (port 8000)
  2. Resets target app into vulnerable mode
  3. Simulates a CI/CD deployment webhook (commit c7d8e9f, bundle app.v2.js)
  4. Triggers change detection, crawls flow, reconciles inventory, and runs prioritized test plans
  5. Reproduces findings with two-pass minimal payloads and files confirmed tickets
  6. Simulates fixed deployment, triggers automated re-test, and resolves tickets
  7. Prints summary and URL to live telemetry dashboard
"""

import time
import json
import sys
import httpx

TARGET_BASE = "http://127.0.0.1:8001"
BACKEND_BASE = "http://127.0.0.1:8000"

def print_banner(text: str):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def run_demo():
    print_banner("1. Checking Service Availability")
    with httpx.Client(timeout=5.0) as client:
        try:
            t_res = client.get(f"{TARGET_BASE}/health")
            print(f"[+] Target App: Healthy on {TARGET_BASE} ({t_res.json().get('mode')} mode)")
        except Exception as e:
            print(f"[-] Target App unreachable at {TARGET_BASE}: {e}")
            sys.exit(1)

        try:
            b_res = client.get(f"{BACKEND_BASE}/health")
            print(f"[+] DAST Backend: Healthy on {BACKEND_BASE}")
        except Exception as e:
            print(f"[-] DAST Backend unreachable at {BACKEND_BASE}: {e}")
            sys.exit(1)

    print_banner("2. Initializing Target App in Vulnerable (Buggy) Mode")
    with httpx.Client(timeout=5.0) as client:
        client.post(f"{TARGET_BASE}/admin/set-mode?vulnerable=true")
        client.post(f"{TARGET_BASE}/admin/reset-state")
        print("[+] Target App reset: BUGS_ENABLED=True, FIXED_MODE=False")

    print_banner("3. Simulating CI/CD Deployment Webhook (Release v2.0.0)")
    with httpx.Client(timeout=15.0) as client:
        webhook_payload = {
            "event": "deployment",
            "version": "v2.0.0",
            "commit_sha": "c7d8e9f01a2b",
            "bundle_url": f"{TARGET_BASE}/static/app.v2.js"
        }
        res = client.post(f"{BACKEND_BASE}/webhook/deploy", json=webhook_payload)
        deploy_data = res.json()
        print(f"[+] Webhook Accepted: Deploy ID {deploy_data.get('deploy_id')}")
        print(f"[+] JS Bundle SHA-256 Hash: {deploy_data.get('new_bundle_hash')[:24]}...")
        print(f"[+] Shadow Route Detected: {deploy_data.get('shadow_routes_detected')}")
        print(f"[+] Zombie Route Detected: {deploy_data.get('zombie_routes_detected')}")

    print_banner("4. Executing Safety-Guarded DAST Regression Pipeline")
    with httpx.Client(timeout=25.0) as client:
        pipe_res = client.post(f"{BACKEND_BASE}/api/pipeline/run?version=v2.0.0")
        pipe_data = pipe_res.json()
        print(f"[+] Pipeline Run ID: {pipe_data.get('run_id')}")
        print(f"[+] Tests Planned & Executed: {pipe_data.get('total_tests_planned')}")
        print(f"[+] Confirmed Reproducible Flaws: {pipe_data.get('findings_count')}")

        print("\n--- Filed Security Tickets ---")
        for ticket in pipe_data.get("confirmed_tickets", []):
            print(f"  * [{ticket['severity']}] {ticket['ticket_id']}: {ticket['title']}")
            print(f"    Target: {ticket['target_endpoint']} | Risk Score: {ticket['impact_score']}")
            print(f"    Impact: {ticket['financial_summary']}")
            print(f"    Remediation: {ticket['remediation_guide']}\n")

    print_banner("5. Verifying Cryptographic Audit Log Integrity")
    with httpx.Client(timeout=5.0) as client:
        audit_res = client.get(f"{BACKEND_BASE}/api/safety/verify")
        audit_data = audit_res.json()
        print(f"[+] Audit Log Tamper-Evident: {audit_data.get('tamper_evident')}")
        print(f"[+] Cryptographic Chain Valid: {audit_data.get('valid')}")
        print(f"[+] Details: {audit_data.get('details')}")

    print_banner("6. Simulating 'Fixed' Production Deployment & Automated Retest")
    print("[*] Switching target app to FIXED mode...")
    with httpx.Client(timeout=5.0) as client:
        client.post(f"{TARGET_BASE}/admin/set-mode?vulnerable=false")
        client.post(f"{TARGET_BASE}/admin/reset-state")
        print("[+] Target App updated: FIXED_MODE=True (Bugs mitigated)")

    print("[*] Triggering automated retest of open tickets...")
    with httpx.Client(timeout=10.0) as client:
        retest_res = client.post(f"{BACKEND_BASE}/api/tickets/retest")
        retest_data = retest_res.json()
        print(f"[+] Tickets Re-tested: {len(retest_data)}")
        for r in retest_data:
            print(f"  * {r['ticket_id']} ({r['test_id']}): STATUS -> {r['status']}")

    print_banner("7. Demonstration Complete!")
    print(f"  Interactive Live Dashboard: {BACKEND_BASE}/dashboard")
    print(f"  Target Application API:      {TARGET_BASE}/docs")
    print("=" * 70)

if __name__ == "__main__":
    run_demo()
