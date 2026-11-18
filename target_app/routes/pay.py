from datetime import datetime
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from target_app.models import PaymentRequest, PaymentResponse
from target_app.auth import get_current_user, User
from target_app.database import BOOKINGS_DB
from target_app.config import settings

router = APIRouter(prefix="/api/v1/bookings", tags=["Payments"])

@router.post("/{booking_id}/pay", response_model=PaymentResponse)
def pay_booking(
    booking_id: str,
    payload: PaymentRequest,
    current_user: User = Depends(get_current_user)
):
    booking = BOOKINGS_DB.get(booking_id)
    if not booking:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Booking '{booking_id}' not found"
        )
    
    # Ownership check
    if not settings.is_buggy() and booking.agency_id != current_user.agency_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot pay for a booking belonging to another agency"
        )

    # Intentional Bug 2: Client-side Fare Trust
    if settings.is_buggy():
        # Buggy behavior: Trust the client-submitted fare completely!
        charged_amount = payload.amount
    else:
        # Fixed behavior: Enforce that client amount matches server locked fare
        if abs(payload.amount - booking.total_amount) > 0.01:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Payment amount mismatch: Expected ${booking.total_amount:.2f}, received ${payload.amount:.2f}"
            )
        charged_amount = booking.total_amount

    booking.amount_paid = charged_amount
    booking.status = "CONFIRMED"

    payment_id = f"PAY-{uuid.uuid4().hex[:8].upper()}"
    return PaymentResponse(
        payment_id=payment_id,
        booking_id=booking.booking_id,
        amount_charged=charged_amount,
        status="SUCCESS",
        timestamp=datetime.utcnow().isoformat()
    )
