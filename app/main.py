import time
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api import api_router
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.core.rate_limiter import limiter

# Bootstrap logging — must run first
setup_logging()

logger = get_logger(__name__)

# FastAPI app instance
app = FastAPI(
    title="AuthApp API",
    description="Backend API for the AuthApp full-stack application.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware — enable cross-origin requests for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach rate limiter to app state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ---------------------------------------------------------------------------
# Middleware — log every request + response with timing
# ---------------------------------------------------------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next) -> Response:
    """
    Attach a unique request ID to each incoming request and log:
      - Incoming request (method + path + client IP)
      - Outgoing response (status code + duration in ms)
    """
    request_id = str(uuid.uuid4())[:8]  # short 8-char ID for readability
    start_time = time.perf_counter()

    logger.info(
        "REQUEST  [%s] %s %s  client=%s",
        request_id,
        request.method,
        request.url.path,
        request.client.host if request.client else "unknown",
    )

    response: Response = await call_next(request)

    duration_ms = (time.perf_counter() - start_time) * 1000
    logger.info(
        "RESPONSE [%s] status=%s  duration=%.2fms",
        request_id,
        response.status_code,
        duration_ms,
    )

    # Attach the request ID as a response header for easy tracing
    response.headers["X-Request-ID"] = request_id
    return response


# Routers
app.include_router(api_router)


@app.get("/", tags=["Health"])
def health_check() -> dict:
    logger.debug("Health check called")
    return {"status": "ok", "message": "AuthApp API is running."}
