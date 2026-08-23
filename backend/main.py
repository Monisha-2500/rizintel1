import os
import sys
import logging

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from routers import findings, dashboard, assets, sla, integration

logger = logging.getLogger("rizintel")

app = FastAPI(
    title="RizIntel M8 Backend Layer",
    description="FastAPI Service providing validated endpoints for RizIntel operations.",
    version="1.0.0",
    # Disable /docs and /redoc in production to limit attack surface
    docs_url="/docs" if os.getenv("RIZINTEL_ENV", "development") == "development" else None,
    redoc_url=None,
)

# ── CORS Configuration ────────────────────────────────────────────────────────
_RAW_ORIGINS = os.getenv(
    "RIZINTEL_ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
)

if _RAW_ORIGINS.strip() == "*":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-User-Role", "X-User-Name", "Authorization"],
        expose_headers=["X-RizIntel-Chain-Valid"],
        max_age=600,
    )
else:
    _origins = [o.strip() for o in _RAW_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_origin_regex=r"https://.*\.vercel\.app",
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-User-Role", "X-User-Name", "Authorization"],
        expose_headers=["X-RizIntel-Chain-Valid"],
        max_age=600,
    )

# ── Global 500 handler: never leak stack traces to clients ────────────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please contact your security administrator."},
    )

# Mount Routers
app.include_router(findings.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(sla.router, prefix="/api")
app.include_router(integration.router, prefix="/api")

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "RizIntel M8 Backend"}

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    is_dev = os.getenv("RIZINTEL_ENV", "development") == "development"
    uvicorn.run("main:app", host=host, port=port, reload=is_dev)

