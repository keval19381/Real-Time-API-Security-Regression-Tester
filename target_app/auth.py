from typing import Optional, Dict
from pydantic import BaseModel
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

class User(BaseModel):
    user_id: str
    agency_id: str
    agency_name: str
    role: str  # 'sub_agent' or 'agency_admin'
    name: str

# Seed credentials and user mappings across two agencies, a few users per role
DEMO_USERS: Dict[str, User] = {
    # --- Agency 1: Apex Travel Partners ---
    "token-apex-sub": User(
        user_id="usr_apex_sub1",
        agency_id="agency_apex",
        agency_name="Apex Travel Partners",
        role="sub_agent",
        name="Alice Smith (Sub-Agent)"
    ),
    "token-apex-sub-1": User(
        user_id="usr_apex_sub1",
        agency_id="agency_apex",
        agency_name="Apex Travel Partners",
        role="sub_agent",
        name="Alice Smith (Sub-Agent)"
    ),
    "token-apex-sub-2": User(
        user_id="usr_apex_sub2",
        agency_id="agency_apex",
        agency_name="Apex Travel Partners",
        role="sub_agent",
        name="Arthur Dent (Sub-Agent)"
    ),
    "token-apex-admin": User(
        user_id="usr_apex_admin1",
        agency_id="agency_apex",
        agency_name="Apex Travel Partners",
        role="agency_admin",
        name="Amanda Waller (Agency Admin)"
    ),
    "token-apex-admin-2": User(
        user_id="usr_apex_admin2",
        agency_id="agency_apex",
        agency_name="Apex Travel Partners",
        role="agency_admin",
        name="Aaron Burr (Agency Admin)"
    ),

    # --- Agency 2: Global Tours & Voyages ---
    "token-global-sub": User(
        user_id="usr_global_sub1",
        agency_id="agency_global",
        agency_name="Global Tours & Voyages",
        role="sub_agent",
        name="George Miller (Sub-Agent)"
    ),
    "token-global-sub-1": User(
        user_id="usr_global_sub1",
        agency_id="agency_global",
        agency_name="Global Tours & Voyages",
        role="sub_agent",
        name="George Miller (Sub-Agent)"
    ),
    "token-global-sub-2": User(
        user_id="usr_global_sub2",
        agency_id="agency_global",
        agency_name="Global Tours & Voyages",
        role="sub_agent",
        name="Grace Hopper (Sub-Agent)"
    ),
    "token-global-admin": User(
        user_id="usr_global_admin1",
        agency_id="agency_global",
        agency_name="Global Tours & Voyages",
        role="agency_admin",
        name="Gerald Vance (Agency Admin)"
    ),
    "token-global-admin-2": User(
        user_id="usr_global_admin2",
        agency_id="agency_global",
        agency_name="Global Tours & Voyages",
        role="agency_admin",
        name="Gloria Steinem (Agency Admin)"
    ),
}

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    if token in DEMO_USERS:
        return DEMO_USERS[token]
    
    # Also support bearer prefixes like user_id or {agency_id}_{role}
    for user in DEMO_USERS.values():
        if token == user.user_id or token == f"{user.agency_id}_{user.role}":
            return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired Bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )
