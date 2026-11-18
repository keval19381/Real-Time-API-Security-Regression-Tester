from fastapi import APIRouter, Depends, HTTPException, status
from target_app.models import PromotionRequest, PromotionResponse
from target_app.auth import get_current_user, User

# Active route intentionally omitted from OpenAPI specification (Shadow endpoint)
router = APIRouter(prefix="/api/v1/promotions", tags=["Promotions"], include_in_schema=False)

@router.post("/apply", response_model=PromotionResponse)
def apply_promotion(
    payload: PromotionRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Active promotion application route.
    NOTE: include_in_schema=False so this is NOT listed in the OpenAPI documentation!
    """
    discounts = {
        "SUMMER26": 0.15,
        "APEXVIP": 0.20,
        "EARLYBIRD": 0.10
    }
    
    code = payload.promo_code.upper()
    if code not in discounts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Promotion code '{payload.promo_code}' is invalid or expired"
        )
    
    pct = discounts[code]
    discount_amount = round(payload.booking_amount * pct, 2)
    final_amount = round(payload.booking_amount - discount_amount, 2)

    return PromotionResponse(
        promo_code=code,
        discount_percentage=pct * 100,
        discount_amount=discount_amount,
        final_amount=final_amount
    )
