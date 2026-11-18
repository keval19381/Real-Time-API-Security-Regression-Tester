from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class FlightItem(BaseModel):
    flight_id: str
    airline: str
    flight_number: str
    origin: str
    destination: str
    departure_time: str
    arrival_time: str
    fare: float
    currency: str = "USD"
    seats_available: int

class FlightSearchRequest(BaseModel):
    origin: str = Field(..., example="JFK")
    destination: str = Field(..., example="LHR")
    departure_date: str = Field(..., example="2026-12-01")

class HoldRequest(BaseModel):
    flight_id: str
    passengers: int = 1

class HoldResponse(BaseModel):
    hold_id: str
    flight_id: str
    passengers: int
    locked_fare_per_seat: float
    total_locked_fare: float
    currency: str = "USD"
    expires_at: str

class BookingRequest(BaseModel):
    hold_id: str
    passenger_name: str
    passenger_email: str
    passport_number: str

class BookingResponse(BaseModel):
    booking_id: str
    hold_id: str
    flight_id: str
    agency_id: str
    passenger_name: str
    passenger_email: str
    passport_number: str
    total_amount: float
    amount_paid: float
    status: str  # 'HELD', 'CONFIRMED', 'CANCELLED'
    created_at: str
    cancellation_refunds: int = 0
    total_refunded: float = 0.0

class PaymentRequest(BaseModel):
    payment_method: str = "corporate_credit"
    amount: float  # In buggy mode, server trusts this client-provided amount!
    currency: str = "USD"

class PaymentResponse(BaseModel):
    payment_id: str
    booking_id: str
    amount_charged: float
    status: str
    timestamp: str

class CancelResponse(BaseModel):
    booking_id: str
    status: str
    refund_amount: float
    total_refunded_to_date: float
    message: str

class CommissionReport(BaseModel):
    agency_id: str
    quarter: str
    total_bookings: int
    gross_volume: float
    commission_rate: float
    payout_due: float
    confidential_override_token: str

class PromotionRequest(BaseModel):
    promo_code: str
    booking_amount: float

class PromotionResponse(BaseModel):
    promo_code: str
    discount_percentage: float
    discount_amount: float
    final_amount: float
