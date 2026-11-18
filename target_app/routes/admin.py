from fastapi import APIRouter, Depends, HTTPException, status
from target_app.models import CommissionReport
from target_app.auth import get_current_user, User
from target_app.config import settings

router = APIRouter(prefix="/api/v1/agency", tags=["Agency Admin"])

@router.get("/commissions", response_model=CommissionReport)
def get_agency_commissions(
    current_user: User = Depends(get_current_user)
):
    # Intentional Bug 4: BFLA / Broken Function Level Authorization
    if settings.is_buggy():
        # Buggy behavior: Role check omitted! Sub-agents can read admin commissions
        pass
    else:
        # Fixed behavior: Enforce agency_admin role requirement
        if current_user.role != "agency_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Agency Admin role required to view financial commissions."
            )
    
    return CommissionReport(
        agency_id=current_user.agency_id,
        quarter="2026-Q4",
        total_bookings=142,
        gross_volume=184500.00,
        commission_rate=0.085,
        payout_due=15682.50,
        confidential_override_token="COMM-OVERRIDE-SEC-998811"
    )
