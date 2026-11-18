import hashlib
import re
import os
from typing import Dict, List, Tuple, Optional
import httpx
from backend.database import get_latest_bundle_hash, save_bundle_hash
from backend.models import BundleHashInfo

class BundleMonitor:
    """
    Monitors client-side static JavaScript bundles for changes.
    Computes cryptographic hashes and parses route definitions to detect
    new, changed, or removed endpoints.
    """

    ENDPOINT_REGEX = re.compile(
        r"""(?:(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?)\s*\(\s*[`"'](?:\$\{API_BASE\}|/api/v1)(/[a-zA-Z0-9_\-\/{}$]+)[`"']|[`"'](/api/v1/[a-zA-Z0-9_\-\/]+)[`"'])"""
    )

    def extract_endpoints_from_js(self, js_content: str) -> List[str]:
        """Extracts REST endpoint paths defined or referenced inside JS bundle code."""
        endpoints = set()
        
        # Match literal /api/v1/ paths or template literals with ${API_BASE}
        matches = self.ENDPOINT_REGEX.findall(js_content)
        for m in matches:
            path_part = m[0] or m[1]
            if path_part:
                clean_path = path_part.split("?")[0].strip()
                if not clean_path.startswith("/api/v1"):
                    clean_path = f"/api/v1{clean_path}"
                endpoints.add(clean_path)
        
        # Also parse common object literals like {search: ..., book: ...}
        for line in js_content.splitlines():
            if "fetch(" in line or "/api/v1" in line:
                for token in re.findall(r"(/api/v1/[a-zA-Z0-9_\-/]+)", line):
                    endpoints.add(token.strip())

        return sorted(list(endpoints))

    def compute_hash(self, content: str) -> str:
        """Computes SHA-256 hash of bundle text."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def inspect_bundle(self, bundle_url: str, local_fallback_path: Optional[str] = None) -> Tuple[bool, BundleHashInfo, Optional[str]]:
        """
        Fetches the JS bundle, hashes its content, extracts routes, and compares with previous hash.
        Returns: (has_changed, BundleHashInfo, previous_hash)
        """
        js_content = ""
        file_name = bundle_url.split("/")[-1] if "/" in bundle_url else "app.js"

        # Try fetching from HTTP first
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(bundle_url)
                if res.status_code == 200:
                    js_content = res.text
        except Exception:
            pass

        # Fallback to local filesystem if target server isn't reachable
        if not js_content and local_fallback_path and os.path.exists(local_fallback_path):
            with open(local_fallback_path, "r", encoding="utf-8") as f:
                js_content = f.read()

        if not js_content:
            # Fallback to default target_app static dir if present
            default_path = os.path.join(os.path.dirname(__file__), "..", "..", "target_app", "static", file_name)
            if os.path.exists(default_path):
                with open(default_path, "r", encoding="utf-8") as f:
                    js_content = f.read()

        current_hash = self.compute_hash(js_content)
        detected_endpoints = self.extract_endpoints_from_js(js_content)
        previous_hash = get_latest_bundle_hash()

        has_changed = (previous_hash is None or previous_hash != current_hash)

        bundle_info = BundleHashInfo(
            bundle_url=bundle_url,
            file_name=file_name,
            content_hash=current_hash,
            detected_endpoints=detected_endpoints,
            timestamp=httpx._utils.get_environment_proxies().get("dummy", "") or ""
        )

        if has_changed:
            save_bundle_hash(bundle_url, file_name, current_hash, detected_endpoints)

        return has_changed, bundle_info, previous_hash

bundle_monitor = BundleMonitor()
