"""
Deployment Webhook Simulation Script
Simulates a CI/CD deployment event triggering downstream change detection,
security regression testing, and API inventory updates.
"""

import argparse
import json
import sys
from datetime import datetime
import httpx

def trigger_deployment(
    backend_webhook_url: str = "http://127.0.0.1:8000/webhook/deploy",
    target_app_url: str = "http://127.0.0.1:8001",
    version: str = "v2.0.0",
    commit_sha: str = "c7d8e9f01a2b",
    bundle_name: str = "app.v2.js",
    switch_fixed: bool = False
):
    print(f"[*] Simulating deployment event for '{target_app_url}'...")
    print(f"    Version: {version}")
    print(f"    Commit: {commit_sha}")
    print(f"    Bundle: {bundle_name}")

    # Optionally toggle target app mode
    if switch_fixed:
        try:
            print(f"[*] Switching target app at {target_app_url} to FIXED mode...")
            resp = httpx.post(f"{target_app_url}/admin/set-mode?vulnerable=false", timeout=5.0)
            print(f"    Target app mode set: {resp.json()}")
        except Exception as e:
            print(f"    [!] Note: Could not contact target app /admin/set-mode: {e}")

    payload = {
        "event": "deployment",
        "service": "target_app",
        "environment": "production",
        "version": version,
        "commit_sha": commit_sha,
        "timestamp": datetime.utcnow().isoformat(),
        "bundle_url": f"{target_app_url}/static/{bundle_name}",
        "openapi_url": f"{target_app_url}/openapi.json",
        "target_base_url": target_app_url,
        "deployed_by": "ci-runner-deploybot",
        "notes": f"Simulated deployment of release {version} with updated JS bundle and routes."
    }

    print(f"[*] Sending deployment webhook to {backend_webhook_url}...")
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(backend_webhook_url, json=payload)
            print(f"[+] Webhook response status: {response.status_code}")
            try:
                print(f"[+] Webhook response body:\n{json.dumps(response.json(), indent=2)}")
            except Exception:
                print(f"[+] Raw response: {response.text}")
            return response.status_code in (200, 201, 202)
    except httpx.ConnectError:
        print(f"[-] Connection refused at {backend_webhook_url}. (Ensure backend service is running).")
        return False
    except Exception as exc:
        print(f"[-] Error delivering webhook: {exc}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Simulate a CI/CD deployment webhook to the security regression platform.")
    parser.add_argument("--webhook-url", default="http://127.0.0.1:8000/webhook/deploy", help="Backend webhook receiver URL")
    parser.add_argument("--target-url", default="http://127.0.0.1:8001", help="Target application base URL")
    parser.add_argument("--version", default="v2.0.0", help="Release version tag")
    parser.add_argument("--commit", default="c7d8e9f01a2b", help="Git commit SHA")
    parser.add_argument("--bundle", default="app.v2.js", help="Static JS bundle filename")
    parser.add_argument("--fixed", action="store_true", help="Set target app to fixed security mode")

    args = parser.parse_args()
    success = trigger_deployment(
        backend_webhook_url=args.webhook_url,
        target_app_url=args.target_url,
        version=args.version,
        commit_sha=args.commit,
        bundle_name=args.bundle,
        switch_fixed=args.fixed
    )
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
