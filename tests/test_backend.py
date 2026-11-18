import pytest
import httpx
from backend.config import backend_settings
from backend.services.traffic_parser import traffic_parser
from backend.services.bundle_monitor import bundle_monitor
from backend.services.crawler import crawler
from backend.services.inventory_manager import inventory_manager

BACKEND_BASE = "http://127.0.0.1:8000"
TARGET_APP_BASE = "http://127.0.0.1:8001"

@pytest.fixture(scope="module")
def http_client():
    with httpx.Client(base_url=BACKEND_BASE, timeout=15.0) as client:
        yield client

class TestHealth:
    def test_backend_and_target_health(self, http_client):
        res = http_client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"

        with httpx.Client(base_url=TARGET_APP_BASE, timeout=5.0) as target_client:
            t_res = target_client.get("/health")
            assert t_res.status_code == 200
            assert t_res.json()["status"] == "healthy"


class TestTrafficLogGenerationAndParsing:
    def test_synthetic_traffic_generation(self):
        # Generate 90 days of traffic
        log_path = traffic_parser.generate_synthetic_logs(days=90, total_requests=1000)
        assert log_path is not None

        # Parse logs
        stats = traffic_parser.parse_logs(log_path)
        assert len(stats) >= 5

        # Check Active endpoint has recent traffic
        search_key = ("GET", "/api/v1/flights/search")
        assert search_key in stats
        assert stats[search_key]["count_30d"] > 0
        assert stats[search_key]["count_90d"] > stats[search_key]["count_30d"]

        # Check Shadow endpoint has recent traffic
        promo_key = ("POST", "/api/v1/promotions/apply")
        assert promo_key in stats
        assert stats[promo_key]["count_30d"] > 0

        # Check Zombie endpoint has older traffic, but zero in last 30 days
        legacy_key = ("GET", "/api/v1/legacy/xml-rates")
        assert legacy_key in stats
        assert stats[legacy_key]["count_30d"] == 0
        assert stats[legacy_key]["count_90d"] > 0


class TestBundleMonitor:
    def test_bundle_hash_and_endpoint_extraction(self):
        bundle_url = f"{TARGET_APP_BASE}/static/app.v2.js"
        changed, info, prev_hash = bundle_monitor.inspect_bundle(bundle_url)
        
        assert info.content_hash is not None
        assert len(info.content_hash) == 64  # SHA256 length
        assert len(info.detected_endpoints) >= 5
        assert "/api/v1/promotions/apply" in info.detected_endpoints
        assert "/api/v1/flights/hold" in info.detected_endpoints


class TestPlaywrightCrawler:
    def test_crawler_walks_flow_and_builds_graph(self):
        graph_data = crawler.crawl_flow()
        assert graph_data is not None
        
        nodes = graph_data.get("nodes", [])
        links = graph_data.get("links", [])
        
        assert len(nodes) >= 6
        assert len(links) >= 4

        node_ids = [n["id"] for n in nodes]
        assert "GET /api/v1/flights/search" in node_ids
        assert "POST /api/v1/flights/hold" in node_ids
        assert "POST /api/v1/bookings" in node_ids
        assert "POST /api/v1/bookings/{booking_id}/pay" in node_ids
        assert "POST /api/v1/bookings/{booking_id}/cancel" in node_ids

        # Verify role permissions captured in nodes
        comm_node = next((n for n in nodes if n["id"] == "GET /api/v1/agency/commissions"), None)
        assert comm_node is not None
        assert "agency_admin" in comm_node["allowed_roles"]

        # Verify edge transitions
        transition_pairs = [(link["source"], link["target"]) for link in links]
        assert ("GET /api/v1/flights/search", "POST /api/v1/flights/hold") in transition_pairs
        assert ("POST /api/v1/flights/hold", "POST /api/v1/bookings") in transition_pairs


class TestAPIInventoryCategorization:
    def test_reconcile_and_classify_endpoints(self):
        items = inventory_manager.reconcile_and_update_inventory()
        assert len(items) >= 8

        # 1. Active endpoints
        search_item = next((i for i in items if i.endpoint_id == "GET /api/v1/flights/search"), None)
        assert search_item is not None
        assert search_item.status == "Active"
        assert search_item.in_openapi is True
        assert search_item.traffic_count_last_30d > 0

        # 2. Shadow endpoint (Active traffic & crawler, but omitted from OpenAPI)
        shadow_item = next((i for i in items if i.endpoint_id == "POST /api/v1/promotions/apply"), None)
        assert shadow_item is not None
        assert shadow_item.status == "Undocumented (shadow)"
        assert shadow_item.in_openapi is False
        assert shadow_item.in_crawler is True

        # 3. Zombie endpoint (Documented in OpenAPI, but 0 traffic in last 30 days)
        zombie_item = next((i for i in items if i.endpoint_id == "GET /api/v1/legacy/xml-rates"), None)
        assert zombie_item is not None
        assert zombie_item.status == "Legacy-unused (zombie)"
        assert zombie_item.in_openapi is True
        assert zombie_item.traffic_count_last_30d == 0


class TestBackendRESTEndpoints:
    def test_deployment_webhook_endpoint(self, http_client):
        payload = {
            "event": "deployment",
            "service": "target_app",
            "version": "v2.0.1",
            "commit_sha": "d4e5f6a1b2c3",
            "bundle_url": f"{TARGET_APP_BASE}/static/app.v2.js"
        }
        res = http_client.post("/webhook/deploy", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["version"] == "v2.0.1"
        assert "POST /api/v1/promotions/apply" in data["shadow_routes_detected"]
        assert "GET /api/v1/legacy/xml-rates" in data["zombie_routes_detected"]
        assert data["inventory_summary"]["active"] >= 5

    def test_get_inventory_rest_endpoint(self, http_client):
        res = http_client.get("/api/inventory")
        assert res.status_code == 200
        items = res.json()
        assert len(items) >= 8

        # Filter by shadow status
        shadow_res = http_client.get("/api/inventory?status=shadow")
        assert shadow_res.status_code == 200
        shadow_items = shadow_res.json()
        assert len(shadow_items) >= 1
        assert shadow_items[0]["path"] == "/api/v1/promotions/apply"
        assert shadow_items[0]["status"] == "Undocumented (shadow)"

        # Filter by zombie status
        zombie_res = http_client.get("/api/inventory?status=zombie")
        assert zombie_res.status_code == 200
        zombie_items = zombie_res.json()
        assert any(item["path"] == "/api/v1/legacy/xml-rates" for item in zombie_items)

    def test_get_inventory_summary_endpoint(self, http_client):
        res = http_client.get("/api/inventory/summary")
        assert res.status_code == 200
        summary = res.json()
        assert summary["total_endpoints"] >= 8
        assert summary["active_endpoints"] >= 5
        assert summary["shadow_endpoints"] >= 1
        assert summary["zombie_endpoints"] >= 1

    def test_get_graph_endpoint(self, http_client):
        res = http_client.get("/api/graph")
        assert res.status_code == 200
        graph = res.json()
        assert "nodes" in graph
        assert "links" in graph
        assert len(graph["nodes"]) >= 6
