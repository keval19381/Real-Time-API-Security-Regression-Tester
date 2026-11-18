from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx

from backend.config import backend_settings
from backend.models import EndpointInventoryItem
from backend.database import save_inventory_item, get_all_inventory
from backend.services.traffic_parser import traffic_parser, normalize_path
from backend.services.crawler import crawler

class APIInventoryManager:
    """
    Manages API Inventory by cross-referencing:
    1. OpenAPI specification (documented contract)
    2. Synthetic & real Traffic Logs (runtime activity)
    3. Playwright Crawler graph (discovered workflows)
    4. Client JS Bundles (frontend calls)

    Labels every endpoint into:
      - 'Active': Documented and observed with recent traffic (< 30 days)
      - 'Legacy-unused (zombie)': Documented in OpenAPI spec, but zero traffic in last 30+ days
      - 'Undocumented (shadow)': Observed in traffic/crawler/frontend, but omitted from OpenAPI spec
    """

    def __init__(self, target_base_url: str = backend_settings.TARGET_APP_URL):
        self.target_base_url = target_base_url

    def fetch_openapi_spec(self) -> Dict[str, Any]:
        """Fetches OpenAPI JSON specification from target app."""
        url = f"{self.target_base_url}/openapi.json"
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(url)
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return {"paths": {}}

    def reconcile_and_update_inventory(self) -> List[EndpointInventoryItem]:
        """
        Performs full reconciliation and persists classified inventory items to the database.
        """
        openapi_spec = self.fetch_openapi_spec()
        openapi_paths = openapi_spec.get("paths", {})

        # Parse traffic logs
        traffic_stats = traffic_parser.parse_logs()

        # Run crawler (or inspect latest crawl graph)
        crawl_graph = crawler.crawl_flow()
        crawler_nodes = {n["id"]: n for n in crawl_graph.get("nodes", [])}

        all_endpoints: Dict[str, Dict[str, Any]] = {}

        # 1. Ingest OpenAPI paths
        for path, path_item in openapi_paths.items():
            for method, op_data in path_item.items():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    method_upper = method.upper()
                    norm_path = normalize_path(path)
                    ep_id = f"{method_upper} {norm_path}"
                    
                    params = []
                    for p in op_data.get("parameters", []):
                        params.append({"name": p.get("name"), "in": p.get("in", "query"), "required": p.get("required", False)})

                    all_endpoints[ep_id] = {
                        "endpoint_id": ep_id,
                        "method": method_upper,
                        "path": norm_path,
                        "in_openapi": True,
                        "in_crawler": False,
                        "in_traffic": False,
                        "traffic_count_last_90d": 0,
                        "traffic_count_last_30d": 0,
                        "last_seen_in_traffic": None,
                        "allowed_roles": [],
                        "parameters": params,
                        "description": op_data.get("summary") or op_data.get("description"),
                        "first_detected": datetime.utcnow().isoformat()
                    }

        # 2. Ingest Crawler nodes
        for node_id, node_data in crawler_nodes.items():
            method_upper = node_data.get("method", "GET").upper()
            norm_path = normalize_path(node_data.get("path", ""))
            ep_id = f"{method_upper} {norm_path}"

            if ep_id not in all_endpoints:
                all_endpoints[ep_id] = {
                    "endpoint_id": ep_id,
                    "method": method_upper,
                    "path": norm_path,
                    "in_openapi": False,
                    "in_crawler": True,
                    "in_traffic": False,
                    "traffic_count_last_90d": 0,
                    "traffic_count_last_30d": 0,
                    "last_seen_in_traffic": None,
                    "allowed_roles": node_data.get("allowed_roles", []),
                    "parameters": [{"name": p, "in": "query/body"} for p in node_data.get("parameters", [])],
                    "description": "Discovered by Playwright workflow crawler",
                    "first_detected": datetime.utcnow().isoformat()
                }
            else:
                all_endpoints[ep_id]["in_crawler"] = True
                all_endpoints[ep_id]["allowed_roles"] = sorted(list(set(
                    all_endpoints[ep_id]["allowed_roles"] + node_data.get("allowed_roles", [])
                )))
                for p in node_data.get("parameters", []):
                    if not any(existing.get("name") == p for existing in all_endpoints[ep_id]["parameters"]):
                        all_endpoints[ep_id]["parameters"].append({"name": p, "in": "query/body"})

        # 3. Ingest Traffic Stats
        for (method, norm_path), stats in traffic_stats.items():
            ep_id = f"{method} {norm_path}"
            if ep_id not in all_endpoints:
                all_endpoints[ep_id] = {
                    "endpoint_id": ep_id,
                    "method": method,
                    "path": norm_path,
                    "in_openapi": False,
                    "in_crawler": False,
                    "in_traffic": True,
                    "traffic_count_last_90d": stats["count_90d"],
                    "traffic_count_last_30d": stats["count_30d"],
                    "last_seen_in_traffic": stats["last_seen"],
                    "allowed_roles": stats["roles"],
                    "parameters": [],
                    "description": "Discovered via runtime traffic log ingestion",
                    "first_detected": datetime.utcnow().isoformat()
                }
            else:
                all_endpoints[ep_id]["in_traffic"] = True
                all_endpoints[ep_id]["traffic_count_last_90d"] = stats["count_90d"]
                all_endpoints[ep_id]["traffic_count_last_30d"] = stats["count_30d"]
                all_endpoints[ep_id]["last_seen_in_traffic"] = stats["last_seen"]
                all_endpoints[ep_id]["allowed_roles"] = sorted(list(set(
                    all_endpoints[ep_id]["allowed_roles"] + stats["roles"]
                )))

        # 4. Classification
        inventory_items: List[EndpointInventoryItem] = []
        for ep_id, data in all_endpoints.items():
            in_openapi = data["in_openapi"]
            count_30d = data["traffic_count_last_30d"]
            in_traffic = data["in_traffic"]
            in_crawler = data["in_crawler"]

            # Labeling logic
            if not in_openapi and (in_traffic or in_crawler):
                status = "Undocumented (shadow)"
            elif in_openapi and (count_30d == 0):
                status = "Legacy-unused (zombie)"
            else:
                status = "Active"

            item = EndpointInventoryItem(
                endpoint_id=ep_id,
                method=data["method"],
                path=data["path"],
                status=status,
                in_openapi=in_openapi,
                in_crawler=in_crawler,
                in_traffic=in_traffic,
                traffic_count_last_90d=data["traffic_count_last_90d"],
                traffic_count_last_30d=count_30d,
                last_seen_in_traffic=data["last_seen_in_traffic"],
                allowed_roles=data["allowed_roles"],
                parameters=data["parameters"],
                description=data.get("description"),
                first_detected=data["first_detected"]
            )
            save_inventory_item(item)
            inventory_items.append(item)

        return inventory_items

inventory_manager = APIInventoryManager()
