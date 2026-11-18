from datetime import datetime
from typing import List
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from target_app.models import BookingRequest, BookingResponse
from target_app.auth import get_current_user, User
from target_app.database import HOLDS_DB, BOOKINGS_DB
from target_app.config import settings

router = APIRouter(prefix="/api/v1/bookings", tags=["Bookings"])

@router.get("", response_model=List[BookingResponse])
def list_bookings(
    current_user: User = Depends(get_current_user)
):
    """
    List bookings.
    In buggy mode: leaks all bookings across agencies.
    In fixed mode: returns only the calling agency's bookings.
    """
    if settings.is_buggy():
        return list(BOOKINGS_DB.values())
    return [b for b in BOOKINGS_DB.values() if b.agency_id == current_user.agency_id]

@router.post("", response_model=BookingResponse)
def create_booking(
    payload: BookingRequest,
    current_user: User = Depends(get_current_user)
):
    hold = HOLDS_DB.get(payload.hold_id)
    if not hold:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hold '{payload.hold_id}' expired or not found"
        )
    
    booking_id = f"BKG-{current_user.agency_id.split('_')[-1].upper()}-{uuid.uuid4().hex[:6].upper()}"
    booking = BookingResponse(
        booking_id=booking_id,
        hold_id=hold.hold_id,
        flight_id=hold.flight_id,
        agency_id=current_user.agency_id,
        passenger_name=payload.passenger_name,
        passenger_email=payload.passenger_email,
        passport_number=payload.passport_number,
        total_amount=hold.total_locked_fare,
        amount_paid=0.0,
        status="HELD",
        created_at=datetime.utcnow().isoformat(),
        cancellation_refunds=0,
        total_refunded=0.0
    )
    BOOKINGS_DB[booking_id] = booking
    return booking

@router.get("/{booking_id}", response_model=BookingResponse)
def get_booking(
    booking_id: str,
    current_user: User = Depends(get_current_user)
):
    booking = BOOKINGS_DB.get(booking_id)
    if not booking:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Booking '{booking_id}' not found"
        )
    
    # Intentional Bug 1: BOLA / IDOR
    # In buggy mode, any agency user can inspect another agency's booking!
    if settings.is_buggy():
        # Buggy behavior: No cross-agency ownership validation
        return booking
    else:
        # Fixed behavior: Strict agency isolation
        if booking.agency_id != current_user.agency_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Booking belongs to agency '{booking.agency_id}'"
            )
        return booking
