from datetime import datetime, timedelta
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from target_app.models import HoldRequest, HoldResponse
from target_app.auth import get_current_user, User
from target_app.database import MOCK_FLIGHTS, HOLDS_DB

router = APIRouter(prefix="/api/v1/flights", tags=["Holds"])

@router.post("/hold", response_model=HoldResponse)
def hold_fare(
    payload: HoldRequest,
    current_user: User = Depends(get_current_user)
):
    flight = MOCK_FLIGHTS.get(payload.flight_id)
    if not flight:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flight '{payload.flight_id}' not found"
        )
    
    if payload.passengers < 1 or payload.passengers > flight.seats_available:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Requested {payload.passengers} seats, only {flight.seats_available} available"
        )

    hold_id = f"HLD-{uuid.uuid4().hex[:8].upper()}"
    locked_fare_per_seat = flight.fare
    total_locked_fare = round(locked_fare_per_seat * payload.passengers, 2)
    expires_at = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

    hold = HoldResponse(
        hold_id=hold_id,
        flight_id=flight.flight_id,
        passengers=payload.passengers,
        locked_fare_per_seat=locked_fare_per_seat,
        total_locked_fare=total_locked_fare,
        currency=flight.currency,
        expires_at=expires_at
    )
    HOLDS_DB[hold_id] = hold
    return hold
