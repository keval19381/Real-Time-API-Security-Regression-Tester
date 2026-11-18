import pytest
import httpx

BASE_URL = "http://127.0.0.1:8001"
APEX_SUB_TOKEN = "token-apex-sub"
APEX_ADMIN_TOKEN = "token-apex-admin"
GLOBAL_SUB_TOKEN = "token-global-sub"
GLOBAL_ADMIN_TOKEN = "token-global-admin"

def set_target_app_mode(vulnerable: bool):
    """Toggle target app security mode via admin API endpoint."""
    with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
        resp = client.post(f"/admin/set-mode?vulnerable={'true' if vulnerable else 'false'}")
        assert resp.status_code == 200
        assert resp.json()["bugs_enabled"] == vulnerable

@pytest.fixture(autouse=True)
def setup_db():
    """Reset database state before each test run."""
    with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
        resp = client.post("/admin/reset-state")
        assert resp.status_code == 200
    yield

class TestBookingFlow:
    """Tests the full Search -> Hold -> Book -> Pay -> Cancel lifecycle against the running service."""
    
    def test_full_booking_flow_lifecycle(self):
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            # 1. Search Flights
            search_res = client.get("/api/v1/flights/search?origin=JFK&destination=LHR", headers=headers)
            assert search_res.status_code == 200
            flights = search_res.json()
            assert len(flights) >= 1
            flight_id = flights[0]["flight_id"]
            seat_fare = flights[0]["fare"]

            # 2. Hold Fare
            hold_res = client.post(
                "/api/v1/flights/hold",
                headers=headers,
                json={"flight_id": flight_id, "passengers": 2}
            )
            assert hold_res.status_code == 200
            hold_data = hold_res.json()
            hold_id = hold_data["hold_id"]
            assert hold_data["total_locked_fare"] == seat_fare * 2

            # 3. Create Booking
            book_res = client.post(
                "/api/v1/bookings",
                headers=headers,
                json={
                    "hold_id": hold_id,
                    "passenger_name": "John Doe",
                    "passenger_email": "john.doe@example.com",
                    "passport_number": "US998877"
                }
            )
            assert book_res.status_code == 200
            book_data = book_res.json()
            booking_id = book_data["booking_id"]
            assert book_data["status"] == "HELD"
            assert book_data["total_amount"] == seat_fare * 2

            # 4. Pay Booking
            pay_res = client.post(
                f"/api/v1/bookings/{booking_id}/pay",
                headers=headers,
                json={"amount": seat_fare * 2, "payment_method": "corporate_credit"}
            )
            assert pay_res.status_code == 200
            pay_data = pay_res.json()
            assert pay_data["status"] == "SUCCESS"
            assert pay_data["amount_charged"] == seat_fare * 2

            # Verify status is confirmed
            get_res = client.get(f"/api/v1/bookings/{booking_id}", headers=headers)
            assert get_res.status_code == 200
            assert get_res.json()["status"] == "CONFIRMED"

            # 5. Cancel Booking
            cancel_res = client.post(
                f"/api/v1/bookings/{booking_id}/cancel",
                headers=headers
            )
            assert cancel_res.status_code == 200
            cancel_data = cancel_res.json()
            assert cancel_data["status"] == "CANCELLED"
            assert cancel_data["refund_amount"] == seat_fare * 2


class TestIntentionalSecurityBugs:
    """
    Proves each of the 4 intentional bugs:
    1. Cross-agency booking read (BOLA / IDOR)
    2. Client-trusted fare tampering
    3. Duplicate cancellation refund (Double refund)
    4. Sub-Agent reaching admin route (BFLA)
    Verifies they exist in buggy mode and are blocked in fixed mode.
    """

    # --- Bug 1: Cross-Agency Booking Read (BOLA / IDOR) ---
    def test_bug1_cross_agency_read_in_buggy_mode(self):
        set_target_app_mode(vulnerable=True)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.get("/api/v1/bookings/BKG-GLOBAL-8802", headers=headers)
            # In buggy mode: Apex user can view Global user's booking!
            assert res.status_code == 200
            data = res.json()
            assert data["booking_id"] == "BKG-GLOBAL-8802"
            assert data["agency_id"] == "agency_global"

    def test_bug1_cross_agency_read_blocked_in_fixed_mode(self):
        set_target_app_mode(vulnerable=False)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.get("/api/v1/bookings/BKG-GLOBAL-8802", headers=headers)
            # In fixed mode: Strict tenant isolation denies access
            assert res.status_code == 403
            assert "Access denied" in res.json()["detail"]

    # --- Bug 2: Client-Trusted Fare Parameter Tampering ---
    def test_bug2_client_trusted_fare_in_buggy_mode(self):
        set_target_app_mode(vulnerable=True)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.post(
                "/api/v1/bookings/BKG-APEX-9902/pay",
                headers=headers,
                json={"amount": 1.00, "payment_method": "corporate_credit"}
            )
            # In buggy mode: Tampered $1.00 fare is trusted and accepted
            assert res.status_code == 200
            assert res.json()["amount_charged"] == 1.00
            
            bkg = client.get("/api/v1/bookings/BKG-APEX-9902", headers=headers).json()
            assert bkg["amount_paid"] == 1.00
            assert bkg["status"] == "CONFIRMED"

    def test_bug2_client_trusted_fare_rejected_in_fixed_mode(self):
        set_target_app_mode(vulnerable=False)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.post(
                "/api/v1/bookings/BKG-APEX-9902/pay",
                headers=headers,
                json={"amount": 1.00, "payment_method": "corporate_credit"}
            )
            # In fixed mode: Tampered amount rejected with 400 Bad Request
            assert res.status_code == 400
            assert "Payment amount mismatch" in res.json()["detail"]

    # --- Bug 3: Duplicate Cancel Refund (Double Refund) ---
    def test_bug3_duplicate_cancel_refund_in_buggy_mode(self):
        set_target_app_mode(vulnerable=True)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            # 1st cancel
            res1 = client.post("/api/v1/bookings/BKG-APEX-9901/cancel", headers=headers)
            assert res1.status_code == 200
            assert res1.json()["total_refunded_to_date"] == 550.00

            # 2nd duplicate cancel
            res2 = client.post("/api/v1/bookings/BKG-APEX-9901/cancel", headers=headers)
            # In buggy mode: Flaw permits duplicate refund, doubling payout
            assert res2.status_code == 200
            assert res2.json()["total_refunded_to_date"] == 1100.00
            assert "Refund #2 issued" in res2.json()["message"]

    def test_bug3_duplicate_cancel_refund_blocked_in_fixed_mode(self):
        set_target_app_mode(vulnerable=False)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            # 1st cancel succeeds
            res1 = client.post("/api/v1/bookings/BKG-APEX-9901/cancel", headers=headers)
            assert res1.status_code == 200
            assert res1.json()["total_refunded_to_date"] == 550.00

            # 2nd duplicate cancel is blocked
            res2 = client.post("/api/v1/bookings/BKG-APEX-9901/cancel", headers=headers)
            assert res2.status_code == 400
            assert "already cancelled" in res2.json()["detail"]

    # --- Bug 4: Sub-Agent Reaching Admin Route (BFLA) ---
    def test_bug4_subagent_access_admin_route_in_buggy_mode(self):
        set_target_app_mode(vulnerable=True)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.get("/api/v1/agency/commissions", headers=headers)
            # In buggy mode: Sub-agent can read confidential commissions
            assert res.status_code == 200
            data = res.json()
            assert data["agency_id"] == "agency_apex"
            assert "payout_due" in data
            assert "confidential_override_token" in data

    def test_bug4_subagent_access_admin_route_blocked_in_fixed_mode(self):
        set_target_app_mode(vulnerable=False)
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.get("/api/v1/agency/commissions", headers=headers)
            # In fixed mode: Sub-agent gets 403 Forbidden
            assert res.status_code == 403
            assert "Agency Admin role required" in res.json()["detail"]

            # Admin user can access
            admin_headers = {"Authorization": f"Bearer {APEX_ADMIN_TOKEN}"}
            admin_res = client.get("/api/v1/agency/commissions", headers=admin_headers)
            assert admin_res.status_code == 200
            assert admin_res.json()["agency_id"] == "agency_apex"


class TestSpecialEndpoints:
    """Verifies legacy (zombie) and shadow (undocumented) endpoints."""

    def test_legacy_endpoint_accessible(self):
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            res = client.get("/api/v1/legacy/xml-rates?carrier=BA", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "deprecated"

    def test_shadow_endpoint_accessible_but_omitted_from_openapi(self):
        headers = {"Authorization": f"Bearer {APEX_SUB_TOKEN}"}
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as client:
            # Active promotion application
            res = client.post(
                "/api/v1/promotions/apply",
                headers=headers,
                json={"promo_code": "SUMMER26", "booking_amount": 1000.00}
            )
            assert res.status_code == 200
            assert res.json()["final_amount"] == 850.00

            # OpenAPI schema must NOT list the shadow endpoint
            openapi_res = client.get("/openapi.json")
            assert openapi_res.status_code == 200
            paths = openapi_res.json()["paths"]
            assert "/api/v1/promotions/apply" not in paths
            assert "/api/v1/legacy/xml-rates" in paths
