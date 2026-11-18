from typing import Dict, List
from datetime import datetime, timedelta
import uuid
from target_app.models import FlightItem, HoldResponse, BookingResponse

# In-memory storage for flights, holds and bookings
MOCK_FLIGHTS: Dict[str, FlightItem] = {
    "FL-101": FlightItem(
        flight_id="FL-101",
        airline="British Airways",
        flight_number="BA-178",
        origin="JFK",
        destination="LHR",
        departure_time="2026-12-01T18:30:00Z",
        arrival_time="2026-12-02T06:45:00Z",
        fare=550.00,
        currency="USD",
        seats_available=12
    ),
    "FL-202": FlightItem(
        flight_id="FL-202",
        airline="Air France",
        flight_number="AF-023",
        origin="JFK",
        destination="CDG",
        departure_time="2026-12-01T20:00:00Z",
        arrival_time="2026-12-02T09:15:00Z",
        fare=620.00,
        currency="USD",
        seats_available=8
    ),
    "FL-303": FlightItem(
        flight_id="FL-303",
        airline="Lufthansa",
        flight_number="LH-401",
        origin="JFK",
        destination="FRA",
        departure_time="2026-12-01T16:15:00Z",
        arrival_time="2026-12-02T05:30:00Z",
        fare=590.00,
        currency="USD",
        seats_available=15
    ),
    "FL-404": FlightItem(
        flight_id="FL-404",
        airline="Emirates",
        flight_number="EK-204",
        origin="JFK",
        destination="DXB",
        departure_time="2026-12-02T11:20:00Z",
        arrival_time="2026-12-03T07:50:00Z",
        fare=890.00,
        currency="USD",
        seats_available=20
    )
}

HOLDS_DB: Dict[str, HoldResponse] = {}
BOOKINGS_DB: Dict[str, BookingResponse] = {}

def reset_database():
    HOLDS_DB.clear()
    BOOKINGS_DB.clear()
    
    # Pre-seed active holds
    hold_apex = HoldResponse(
        hold_id="HLD-INIT-01",
        flight_id="FL-101",
        passengers=1,
        locked_fare_per_seat=550.00,
        total_locked_fare=550.00,
        currency="USD",
        expires_at=(datetime.utcnow() + timedelta(minutes=15)).isoformat()
    )
    HOLDS_DB[hold_apex.hold_id] = hold_apex

    hold_global = HoldResponse(
        hold_id="HLD-INIT-02",
        flight_id="FL-202",
        passengers=2,
        locked_fare_per_seat=620.00,
        total_locked_fare=1240.00,
        currency="USD",
        expires_at=(datetime.utcnow() + timedelta(minutes=15)).isoformat()
    )
    HOLDS_DB[hold_global.hold_id] = hold_global

    # Pre-seed sample bookings across both agencies with different statuses
    # --- Agency 1 (agency_apex) Bookings ---
    bkg_apex_1 = BookingResponse(
        booking_id="BKG-APEX-9901",
        hold_id="HLD-INIT-01",
        flight_id="FL-101",
        agency_id="agency_apex",
        passenger_name="Alice Smith",
        passenger_email="alice.smith@example.com",
        passport_number="P987654321A",
        total_amount=550.00,
        amount_paid=550.00,
        status="CONFIRMED",
        created_at=(datetime.utcnow() - timedelta(hours=2)).isoformat(),
        cancellation_refunds=0,
        total_refunded=0.0
    )
    BOOKINGS_DB[bkg_apex_1.booking_id] = bkg_apex_1

    bkg_apex_2 = BookingResponse(
        booking_id="BKG-APEX-9902",
        hold_id="HLD-PRE-03",
        flight_id="FL-303",
        agency_id="agency_apex",
        passenger_name="Arthur Dent",
        passenger_email="arthur.dent@galaxy.org",
        passport_number="P42424242A",
        total_amount=590.00,
        amount_paid=0.0,
        status="HELD",
        created_at=(datetime.utcnow() - timedelta(minutes=30)).isoformat(),
        cancellation_refunds=0,
        total_refunded=0.0
    )
    BOOKINGS_DB[bkg_apex_2.booking_id] = bkg_apex_2

    bkg_apex_3 = BookingResponse(
        booking_id="BKG-APEX-9903",
        hold_id="HLD-PRE-04",
        flight_id="FL-404",
        agency_id="agency_apex",
        passenger_name="Charles Xavier",
        passenger_email="prof.x@mutants.edu",
        passport_number="P00000001X",
        total_amount=890.00,
        amount_paid=890.00,
        status="CANCELLED",
        created_at=(datetime.utcnow() - timedelta(days=1)).isoformat(),
        cancellation_refunds=1,
        total_refunded=890.00
    )
    BOOKINGS_DB[bkg_apex_3.booking_id] = bkg_apex_3

    # --- Agency 2 (agency_global) Bookings ---
    bkg_global_1 = BookingResponse(
        booking_id="BKG-GLOBAL-8802",
        hold_id="HLD-INIT-02",
        flight_id="FL-202",
        agency_id="agency_global",
        passenger_name="Bob Jones",
        passenger_email="bob.jones@example.com",
        passport_number="P123456789B",
        total_amount=620.00,
        amount_paid=620.00,
        status="CONFIRMED",
        created_at=(datetime.utcnow() - timedelta(hours=1)).isoformat(),
        cancellation_refunds=0,
        total_refunded=0.0
    )
    BOOKINGS_DB[bkg_global_1.booking_id] = bkg_global_1

    bkg_global_2 = BookingResponse(
        booking_id="BKG-GLOBAL-8803",
        hold_id="HLD-PRE-05",
        flight_id="FL-101",
        agency_id="agency_global",
        passenger_name="Grace Hopper",
        passenger_email="grace.hopper@navy.mil",
        passport_number="P77788899C",
        total_amount=550.00,
        amount_paid=0.0,
        status="HELD",
        created_at=(datetime.utcnow() - timedelta(minutes=45)).isoformat(),
        cancellation_refunds=0,
        total_refunded=0.0
    )
    BOOKINGS_DB[bkg_global_2.booking_id] = bkg_global_2

# Initialize seeds on module import
reset_database()
