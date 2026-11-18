from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from target_app.config import settings
from target_app.routes import search, hold, book, pay, cancel, admin, legacy, shadow
from target_app.database import reset_database

app = FastAPI(
    title=settings.APP_NAME,
    description="Mock B2B Travel Booking Service for Real-Time Security Regression Testing",
    version="2.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json"
)

# Enable CORS for local testing and frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static bundle directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Include route modules
app.include_router(search.router)
app.include_router(hold.router)
app.include_router(book.router)
app.include_router(pay.router)
app.include_router(cancel.router)
app.include_router(admin.router)
app.include_router(legacy.router)
app.include_router(shadow.router)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "bugs_enabled": settings.is_buggy(),
        "mode": "vulnerable" if settings.is_buggy() else "fixed"
    }

@app.post("/admin/reset-state")
def reset_state():
    reset_database()
    return {"status": "ok", "message": "Database and hold state reset to default."}

@app.post("/admin/set-mode")
def set_mode(vulnerable: bool):
    settings.BUGS_ENABLED = vulnerable
    settings.FIXED_MODE = not vulnerable
    return {
        "status": "ok",
        "bugs_enabled": settings.is_buggy(),
        "mode": "vulnerable" if settings.is_buggy() else "fixed"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("target_app.app:app", host=settings.HOST, port=settings.PORT, reload=True)
