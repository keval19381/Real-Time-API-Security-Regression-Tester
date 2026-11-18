from fastapi import APIRouter, Depends, Query
from target_app.auth import get_current_user, User

# Unused legacy route included in OpenAPI spec (Zombie endpoint)
router = APIRouter(prefix="/api/v1/legacy", tags=["Legacy / Deprecated"], include_in_schema=True)

@router.get("/xml-rates")
def get_legacy_xml_rates(
    carrier: str = Query("BA", description="Carrier code"),
    current_user: User = Depends(get_current_user)
):
    """
    DEPRECATED (v0.9 API): Returns XML-formatted raw rate sheet.
    This route is obsolete and scheduled for decommissioning.
    """
    return {
        "status": "deprecated",
        "notice": "Please migrate to /api/v1/flights/search",
        "raw_xml_payload": f"<Rates carrier='{carrier}'><Base>450</Base><Taxes>98</Taxes></Rates>"
    }
