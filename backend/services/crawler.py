import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import networkx as nx
from networkx.readwrite import json_graph
from playwright.sync_api import sync_playwright

from backend.config import backend_settings
from backend.database import save_crawl_graph
from backend.services.traffic_parser import normalize_path

ROLES_CREDENTIALS = {
    "sub_agent": {
        "token": "token-apex-sub",
        "agency_id": "agency_apex",
        "description": "Standard Sub-Agent user"
    },
    "agency_admin": {
        "token": "token-apex-admin",
        "agency_id": "agency_apex",
        "description": "Agency Administrator with financial permissions"
    }
}

class PlaywrightAPICrawler:
    """
    Playwright-based crawler that walks API booking flows using separate credentials
    per role (sub_agent, agency_admin). Constructs a NetworkX DiGraph recording
    endpoints, parameters, flow transitions, and role permissions, then persists it.
    """

    def __init__(self, target_base_url: str = backend_settings.TARGET_APP_URL):
        self.target_base_url = target_base_url

    def crawl_flow(self) -> Dict[str, Any]:
        """
        Executes multi-role crawl using Playwright APIRequestContext.
        Returns serialized NetworkX graph in node-link format.
        """
        G = nx.DiGraph()

        discovered_endpoints: Dict[str, Dict[str, Any]] = {}
        transitions: List[Tuple[str, str, Dict[str, Any]]] = []

        with sync_playwright() as p:
            for role_name, creds in ROLES_CREDENTIALS.items():
                token = creds["token"]
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }

                # Initialize Playwright request context for this role
                request_context = p.request.new_context(
                    base_url=self.target_base_url,
                    extra_http_headers=headers
                )

                try:
                    # 1. Search Flights
                    search_resp = request_context.get("/api/v1/flights/search?origin=JFK&destination=LHR")
                    search_key = "GET /api/v1/flights/search"
                    if search_key not in discovered_endpoints:
                        discovered_endpoints[search_key] = {
                            "method": "GET",
                            "path": "/api/v1/flights/search",
                            "parameters": ["origin", "destination", "date"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if search_resp.status == 200:
                        discovered_endpoints[search_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[search_key]["denied_roles"].append(role_name)

                    flights = search_resp.json() if search_resp.status == 200 else []
                    flight_id = flights[0]["flight_id"] if flights else "FL-101"
                    seat_fare = flights[0]["fare"] if flights else 550.0

                    # 2. Hold Fare
                    hold_key = "POST /api/v1/flights/hold"
                    hold_resp = request_context.post(
                        "/api/v1/flights/hold",
                        data=json.dumps({"flight_id": flight_id, "passengers": 1})
                    )
                    if hold_key not in discovered_endpoints:
                        discovered_endpoints[hold_key] = {
                            "method": "POST",
                            "path": "/api/v1/flights/hold",
                            "parameters": ["flight_id", "passengers"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if hold_resp.status == 200:
                        discovered_endpoints[hold_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[hold_key]["denied_roles"].append(role_name)

                    transitions.append((search_key, hold_key, {"flow": "select_flight_to_hold"}))

                    hold_data = hold_resp.json() if hold_resp.status == 200 else {}
                    hold_id = hold_data.get("hold_id", "HLD-INIT-01")

                    # 3. Create Booking
                    book_key = "POST /api/v1/bookings"
                    book_resp = request_context.post(
                        "/api/v1/bookings",
                        data=json.dumps({
                            "hold_id": hold_id,
                            "passenger_name": f"Test {role_name.capitalize()}",
                            "passenger_email": f"{role_name}@agency.com",
                            "passport_number": "P123987456"
                        })
                    )
                    if book_key not in discovered_endpoints:
                        discovered_endpoints[book_key] = {
                            "method": "POST",
                            "path": "/api/v1/bookings",
                            "parameters": ["hold_id", "passenger_name", "passenger_email", "passport_number"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if book_resp.status == 200:
                        discovered_endpoints[book_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[book_key]["denied_roles"].append(role_name)

                    transitions.append((hold_key, book_key, {"flow": "create_booking_from_hold"}))

                    book_data = book_resp.json() if book_resp.status == 200 else {}
                    booking_id = book_data.get("booking_id", "BKG-APEX-9901")

                    # 4. Read Booking
                    read_bkg_key = "GET /api/v1/bookings/{booking_id}"
                    read_bkg_resp = request_context.get(f"/api/v1/bookings/{booking_id}")
                    if read_bkg_key not in discovered_endpoints:
                        discovered_endpoints[read_bkg_key] = {
                            "method": "GET",
                            "path": "/api/v1/bookings/{booking_id}",
                            "parameters": ["booking_id"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if read_bkg_resp.status == 200:
                        discovered_endpoints[read_bkg_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[read_bkg_key]["denied_roles"].append(role_name)

                    transitions.append((book_key, read_bkg_key, {"flow": "view_booking_details"}))

                    # 5. List Bookings
                    list_bkg_key = "GET /api/v1/bookings"
                    list_resp = request_context.get("/api/v1/bookings")
                    if list_bkg_key not in discovered_endpoints:
                        discovered_endpoints[list_bkg_key] = {
                            "method": "GET",
                            "path": "/api/v1/bookings",
                            "parameters": [],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if list_resp.status == 200:
                        discovered_endpoints[list_bkg_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[list_bkg_key]["denied_roles"].append(role_name)

                    # 6. Pay for Booking
                    pay_key = "POST /api/v1/bookings/{booking_id}/pay"
                    pay_resp = request_context.post(
                        f"/api/v1/bookings/{booking_id}/pay",
                        data=json.dumps({"amount": seat_fare, "payment_method": "corporate_credit"})
                    )
                    if pay_key not in discovered_endpoints:
                        discovered_endpoints[pay_key] = {
                            "method": "POST",
                            "path": "/api/v1/bookings/{booking_id}/pay",
                            "parameters": ["booking_id", "amount", "payment_method"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if pay_resp.status == 200:
                        discovered_endpoints[pay_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[pay_key]["denied_roles"].append(role_name)

                    transitions.append((book_key, pay_key, {"flow": "pay_booking"}))

                    # 7. Cancel Booking
                    cancel_key = "POST /api/v1/bookings/{booking_id}/cancel"
                    cancel_resp = request_context.post(f"/api/v1/bookings/{booking_id}/cancel")
                    if cancel_key not in discovered_endpoints:
                        discovered_endpoints[cancel_key] = {
                            "method": "POST",
                            "path": "/api/v1/bookings/{booking_id}/cancel",
                            "parameters": ["booking_id"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if cancel_resp.status == 200:
                        discovered_endpoints[cancel_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[cancel_key]["denied_roles"].append(role_name)

                    transitions.append((pay_key, cancel_key, {"flow": "cancel_confirmed_booking"}))

                    # 8. Check Admin Commissions
                    comm_key = "GET /api/v1/agency/commissions"
                    comm_resp = request_context.get("/api/v1/agency/commissions")
                    if comm_key not in discovered_endpoints:
                        discovered_endpoints[comm_key] = {
                            "method": "GET",
                            "path": "/api/v1/agency/commissions",
                            "parameters": [],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if comm_resp.status == 200:
                        discovered_endpoints[comm_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[comm_key]["denied_roles"].append(role_name)

                    # 9. Test Shadow Promotions Endpoint
                    promo_key = "POST /api/v1/promotions/apply"
                    promo_resp = request_context.post(
                        "/api/v1/promotions/apply",
                        data=json.dumps({"promo_code": "SUMMER26", "booking_amount": 500.0})
                    )
                    if promo_key not in discovered_endpoints:
                        discovered_endpoints[promo_key] = {
                            "method": "POST",
                            "path": "/api/v1/promotions/apply",
                            "parameters": ["promo_code", "booking_amount"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if promo_resp.status == 200:
                        discovered_endpoints[promo_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[promo_key]["denied_roles"].append(role_name)

                    # 10. Test Legacy XML Rates Endpoint
                    legacy_key = "GET /api/v1/legacy/xml-rates"
                    legacy_resp = request_context.get("/api/v1/legacy/xml-rates?carrier=BA")
                    if legacy_key not in discovered_endpoints:
                        discovered_endpoints[legacy_key] = {
                            "method": "GET",
                            "path": "/api/v1/legacy/xml-rates",
                            "parameters": ["carrier"],
                            "allowed_roles": [],
                            "denied_roles": []
                        }
                    if legacy_resp.status == 200:
                        discovered_endpoints[legacy_key]["allowed_roles"].append(role_name)
                    else:
                        discovered_endpoints[legacy_key]["denied_roles"].append(role_name)

                finally:
                    request_context.dispose()

        # Add Nodes to NetworkX DiGraph
        for ep_key, data in discovered_endpoints.items():
            G.add_node(
                ep_key,
                method=data["method"],
                path=data["path"],
                parameters=data["parameters"],
                allowed_roles=sorted(list(set(data["allowed_roles"]))),
                denied_roles=sorted(list(set(data["denied_roles"])))
            )

        # Add Edges to NetworkX DiGraph
        for u, v, attr in transitions:
            if G.has_node(u) and G.has_node(v):
                G.add_edge(u, v, **attr)

        graph_data = json_graph.node_link_data(G, edges="links")
        graph_id = f"crawl_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        save_crawl_graph(graph_id, graph_data)

        return graph_data

crawler = PlaywrightAPICrawler()
