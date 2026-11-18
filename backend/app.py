from fastapi import FastAPI, Query, HTTPException, status, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
import os
import uuid
import asyncio

from backend.config import backend_settings
from backend.models import (
    DeploymentWebhookPayload,
    DeploymentChangeSummary,
    EndpointInventoryItem
)
from backend.database import (
    get_all_inventory,
    get_deployments,
    save_deployment,
    get_latest_crawl_graph
)
from backend.services.bundle_monitor import bundle_monitor
from backend.services.traffic_parser import traffic_parser
from backend.services.crawler import crawler
from backend.services.inventory_manager import inventory_manager
from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger
from backend.test_planner import test_planner, TestPlan
from backend.tickets import ticket_manager, SecurityTicket
from backend.engine import engine

app = FastAPI(
    title=backend_settings.APP_NAME,
    description="Real-Time API Security Regression Platform - Change Detection & API Inventory Service",
    version="2.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# WebSocket connection manager — broadcasts live events to all connected UIs
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Manages active WebSocket connections and broadcasts JSON events."""
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, event: Dict[str, Any]):
        dead = set()
        for ws in self.active:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        self.active -= dead

ws_manager = ConnectionManager()

async def _broadcast(event_type: str, payload: Dict[str, Any]):
    """Helper: build a standard envelope and broadcast."""
    await ws_manager.broadcast({
        "event": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": payload
    })

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": backend_settings.APP_NAME,
        "target_app_url": backend_settings.TARGET_APP_URL,
        "timestamp": datetime.utcnow().isoformat()
    }

# ---------------------------------------------------------------------------
# WebSocket live-event stream — dashboard connects here for push updates
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """
    Live-push WebSocket endpoint.
    Clients connect and receive JSON events whenever a deployment webhook,
    pipeline run, or ticket retest completes.
    Event envelope: { "event": str, "timestamp": str, "data": {...} }
    """
    await ws_manager.connect(ws)
    try:
        # Keep the connection alive; client can send pings (ignored)
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

@app.post("/webhook/deploy", response_model=DeploymentChangeSummary)
def handle_deployment_webhook(payload: DeploymentWebhookPayload, background_tasks: BackgroundTasks):
    """
    CI/CD Deployment Webhook Endpoint:
    1. Triggers JS Bundle hash-change detection.
    2. Runs multi-role Playwright crawler to explore workflows.
    3. Reconciles OpenAPI schema against runtime traffic logs and crawler graphs.
    4. Categorizes new, modified, zombie, and shadow endpoints.
    5. Records deployment change summary for downstream regression testing.
    6. Broadcasts live event to all connected WebSocket dashboard clients.
    """
    deploy_id = f"DEP-{uuid.uuid4().hex[:8].upper()}"
    bundle_url = payload.bundle_url or f"{backend_settings.TARGET_APP_URL}/static/app.v2.js"

    # 1. Inspect bundle hash change
    bundle_changed, bundle_info, previous_hash = bundle_monitor.inspect_bundle(bundle_url)

    # 2. Run reconciliation (crawls API and ingests traffic stats)
    inventory = inventory_manager.reconcile_and_update_inventory()

    # 3. Categorize findings
    shadow_routes = [item.endpoint_id for item in inventory if "shadow" in item.status.lower()]
    zombie_routes = [item.endpoint_id for item in inventory if "zombie" in item.status.lower()]
    active_routes = [item.endpoint_id for item in inventory if item.status.lower() == "active"]

    summary_counts = {
        "total_endpoints": len(inventory),
        "active": len(active_routes),
        "zombie": len(zombie_routes),
        "shadow": len(shadow_routes)
    }

    summary = DeploymentChangeSummary(
        deploy_id=deploy_id,
        version=payload.version,
        commit_sha=payload.commit_sha,
        timestamp=datetime.utcnow().isoformat(),
        bundle_changed=bundle_changed,
        previous_bundle_hash=previous_hash,
        new_bundle_hash=bundle_info.content_hash,
        newly_discovered_routes=bundle_info.detected_endpoints,
        modified_routes=[item.endpoint_id for item in inventory if item.in_crawler and item.in_openapi],
        shadow_routes_detected=shadow_routes,
        zombie_routes_detected=zombie_routes,
        inventory_summary=summary_counts
    )

    save_deployment(summary)

    # Broadcast live event to WebSocket clients (runs async in event loop after response)
    background_tasks.add_task(_broadcast, "deployment", {
        "deploy_id": deploy_id,
        "version": payload.version,
        "bundle_changed": bundle_changed,
        "shadow_count": len(shadow_routes),
        "zombie_count": len(zombie_routes),
        "shadow_routes": shadow_routes,
        "zombie_routes": zombie_routes,
    })

    return summary

@app.get("/api/inventory", response_model=List[EndpointInventoryItem])
def get_inventory(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: Active, zombie, shadow"),
    in_openapi: Optional[bool] = Query(None, description="Filter by OpenAPI presence")
):
    """Exposes the API inventory with classification labels."""
    items = get_all_inventory()
    if not items:
        # If DB is empty, run initial reconciliation
        items = inventory_manager.reconcile_and_update_inventory()

    if status_filter:
        items = [i for i in items if status_filter.lower() in i.status.lower()]
    if in_openapi is not None:
        items = [i for i in items if i.in_openapi == in_openapi]

    return items

@app.get("/api/inventory/summary")
def get_inventory_summary():
    """Returns aggregated summary metrics of the API inventory."""
    items = get_all_inventory()
    if not items:
        items = inventory_manager.reconcile_and_update_inventory()

    total = len(items)
    active = len([i for i in items if i.status == "Active"])
    zombies = len([i for i in items if "zombie" in i.status.lower()])
    shadows = len([i for i in items if "shadow" in i.status.lower()])

    return {
        "total_endpoints": total,
        "active_endpoints": active,
        "zombie_endpoints": zombies,
        "shadow_endpoints": shadows,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/graph")
def get_graph():
    """Returns the latest NetworkX crawl graph in node-link JSON format."""
    graph_data = get_latest_crawl_graph()
    if not graph_data:
        graph_data = crawler.crawl_flow()
    return graph_data

@app.post("/api/traffic/generate")
def generate_traffic(days: int = 90, requests: int = 2500):
    """Generates synthetic traffic logs spanning 30-90 days."""
    path = traffic_parser.generate_synthetic_logs(days=days, total_requests=requests)
    return {
        "status": "success",
        "message": f"Generated {requests} synthetic traffic log entries spanning past {days} days.",
        "log_path": path
    }

@app.post("/api/traffic/parse")
def parse_traffic():
    """Ingests runtime traffic logs and returns aggregated statistics."""
    stats = traffic_parser.parse_logs()
    return {
        "status": "success",
        "endpoints_processed": len(stats),
        "data": [
            {
                "method": k[0],
                "path": k[1],
                "count_30d": v["count_30d"],
                "count_90d": v["count_90d"],
                "last_seen": v["last_seen"]
            }
            for k, v in stats.items()
        ]
    }

@app.post("/api/crawler/run")
def run_crawler_endpoint():
    """Triggers the Playwright multi-role API crawler."""
    graph_data = crawler.crawl_flow()
    return {
        "status": "success",
        "nodes_discovered": len(graph_data.get("nodes", [])),
        "edges_mapped": len(graph_data.get("links", [])),
        "graph": graph_data
    }

@app.get("/api/deployments")
def list_deployments():
    """Lists past deployments and detected change summaries."""
    return get_deployments()

# --- Phase 3: Safety Layer & Test Planner Endpoints ---

@app.get("/api/safety/status")
def get_safety_status():
    """Returns real-time telemetry from the safety layer: allowlist, rate limits, circuit breaker."""
    is_valid, msg = audit_logger.verify_integrity()
    return {
        "status": "active",
        "safety_guard": safety_guard.get_safety_metrics(),
        "audit_chain_integrity": {
            "valid": is_valid,
            "message": msg
        }
    }

@app.get("/api/safety/audit")
def get_audit_log(limit: int = 50):
    """Returns append-only hash-chained audit log records."""
    return audit_logger.get_entries(limit=limit)

@app.get("/api/safety/verify")
def verify_audit_chain():
    """Cryptographically verifies hash chain continuity from index 0 to head."""
    is_valid, msg = audit_logger.verify_integrity()
    return {
        "tamper_evident": True,
        "valid": is_valid,
        "details": msg,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/test-plans/generate", response_model=TestPlan)
def generate_test_plan(version: Optional[str] = "v2.0.0", focus_modified: bool = False):
    """Generates a prioritized regression test plan targeting authorization, business logic, and API hygiene."""
    return test_planner.generate_plan(deployment_version=version, focus_modified_only=focus_modified)

@app.get("/api/test-plans/latest", response_model=TestPlan)
def get_latest_test_plan():
    """Retrieves the current prioritized regression test plan."""
    return test_planner.generate_plan()

# --- Phase 4 & Phase 5: Tickets, Retest, Full DAST Pipeline, and Dashboard ---

@app.get("/api/tickets", response_model=List[SecurityTicket])
def get_security_tickets():
    """Returns all security tickets (OPEN, CONFIRMED, RESOLVED)."""
    return ticket_manager.get_all_tickets()

@app.post("/api/tickets/retest")
def retest_open_tickets(background_tasks: BackgroundTasks):
    """Re-executes reproduction requests against target app to verify mitigations and auto-close tickets.
    Broadcasts a 'retest_complete' event to connected WebSocket dashboard clients."""
    results = ticket_manager.retest_open_tickets()

    resolved = sum(1 for r in results if r.get("status") == "RESOLVED")
    background_tasks.add_task(_broadcast, "retest_complete", {
        "total_retested": len(results),
        "resolved": resolved,
        "unfixed": len(results) - resolved,
    })

    return results

@app.post("/api/pipeline/run")
def run_dast_regression_pipeline(background_tasks: BackgroundTasks, version: Optional[str] = "v2.0.0"):
    """
    Executes the full automated regression testing pipeline end-to-end:
    Change Detection -> Inventory Reconciliation -> Prioritized Planning ->
    Safety Execution -> Minimal Reproduction Verification -> Impact Scoring -> Ticket Filing.
    Broadcasts a live 'pipeline_complete' event to WebSocket dashboard clients.
    """
    result = engine.run_pipeline(deployment_version=version)

    # Broadcast pipeline completion to all connected dashboards
    background_tasks.add_task(_broadcast, "pipeline_complete", {
        "run_id": result.get("run_id"),
        "findings_count": result.get("findings_count", 0),
        "total_tests": result.get("total_tests_planned", 0),
        "bundle_changed": result.get("bundle_changed", False),
    })

    return result

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    """Serves the standalone live telemetry dashboard."""
    dashboard_file = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
    if os.path.exists(dashboard_file):
        with open(dashboard_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h2>DAST Dashboard file not found</h2>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host=backend_settings.HOST, port=backend_settings.PORT, reload=True)
