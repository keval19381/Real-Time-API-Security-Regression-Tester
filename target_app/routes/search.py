from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from target_app.models import FlightItem
from target_app.auth import get_current_user, User
from target_app.database import MOCK_FLIGHTS

router = APIRouter(prefix="/api/v1/flights", tags=["Flights"])

@router.get("/search", response_model=List[FlightItem])
def search_flights(
    origin: str = Query("JFK", description="Origin airport code"),
    destination: str = Query("LHR", description="Destination airport code"),
    date: Optional[str] = Query(None, description="Date in YYYY-MM-DD"),
    current_user: User = Depends(get_current_user)
):
    results = [
        f for f in MOCK_FLIGHTS.values()
        if (not origin or f.origin.upper() == origin.upper()) and
           (not destination or f.destination.upper() == destination.upper())
    ]
    if not results:
        return list(MOCK_FLIGHTS.values())
    return results
