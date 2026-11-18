from fastapi import APIRouter, Depends, HTTPException, status
from target_app.models import CancelResponse
from target_app.auth import get_current_user, User
from target_app.database import BOOKINGS_DB
from target_app.config import settings

router = APIRouter(prefix="/api/v1/bookings", tags=["Cancellations"])

@router.post("/{booking_id}/cancel", response_model=CancelResponse)
def cancel_booking(
    booking_id: str,
    current_user: User = Depends(get_current_user)
):
    booking = BOOKINGS_DB.get(booking_id)
    if not booking:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Booking '{booking_id}' not found"
        )
    
    if not settings.is_buggy() and booking.agency_id != current_user.agency_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot cancel a booking belonging to another agency"
        )

    # Intentional Bug 3: Double refund on duplicate cancellation
    if settings.is_buggy():
        # Buggy behavior: No idempotency check! Increment refunds and refund again
        refund_amount = booking.total_amount
        booking.cancellation_refunds += 1
        booking.total_refunded += refund_amount
        booking.status = "CANCELLED"
        
        return CancelResponse(
            booking_id=booking.booking_id,
            status=booking.status,
            refund_amount=refund_amount,
            total_refunded_to_date=booking.total_refunded,
            message=f"Refund #{booking.cancellation_refunds} issued successfully for ${refund_amount:.2f}"
        )
    else:
        # Fixed behavior: Strict state check and idempotency lock
        if booking.status == "CANCELLED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Booking is already cancelled. Refund has already been processed."
            )
        
        refund_amount = booking.amount_paid if booking.amount_paid > 0 else booking.total_amount
        booking.cancellation_refunds = 1
        booking.total_refunded = refund_amount
        booking.status = "CANCELLED"
        
        return CancelResponse(
            booking_id=booking.booking_id,
            status=booking.status,
            refund_amount=refund_amount,
            total_refunded_to_date=booking.total_refunded,
            message="Booking cancelled and single refund processed."
        )
