"""FastAPI server for API Shield."""

import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .core import APIEvent
from .engine import AnalysisEngine, EngineConfig


# Global engine instance
_engine: Optional[AnalysisEngine] = None


class AnalyzeRequest(BaseModel):
    """Request model for /analyze endpoint."""

    method: str
    path: str
    client_ip: str
    user_id: Optional[str] = None
    headers: Dict[str, str] = {}
    query_params: Dict[str, str] = {}
    response_code: Optional[int] = None
    geo: Optional[Dict[str, Any]] = None
    device_fingerprint: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """Response model for /analyze endpoint."""

    request_id: str
    risk_score: float
    action: str
    blocking: bool
    reason: str
    signals: Dict[str, float]
    detectors_triggered: list
    processing_time_ms: float


class MetricsResponse(BaseModel):
    """Response model for /metrics endpoint."""

    total_requests: int
    blocked_requests: int
    rate_limited_requests: int
    challenged_requests: int
    allowed_requests: int
    block_rate: float
    avg_processing_time_ms: float
    max_processing_time_ms: float
    detector_triggers: Dict[str, int]


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""

    status: str
    engine_initialized: bool
    version: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage engine lifecycle."""
    global _engine
    _engine = AnalysisEngine()
    await _engine.initialize()
    yield
    await _engine.shutdown()


def create_app(config: Optional[EngineConfig] = None) -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="API Shield",
        description="Real-time API Security Analysis Platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/analyze", response_model=AnalyzeResponse)
    async def analyze(request: AnalyzeRequest):
        """Analyze an API request for security threats."""
        if not _engine:
            raise HTTPException(status_code=503, detail="Engine not initialized")

        event = APIEvent(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            method=request.method,
            path=request.path,
            client_ip=request.client_ip,
            user_id=request.user_id,
            headers=request.headers,
            query_params=request.query_params,
            response_code=request.response_code,
            geo=request.geo,
            device_fingerprint=request.device_fingerprint,
        )

        result = await _engine.analyze(event)

        return AnalyzeResponse(
            request_id=result.request_id,
            risk_score=result.risk_score,
            action=result.action.type.value,
            blocking=result.action.blocking,
            reason=result.action.reason,
            signals=result.signals,
            detectors_triggered=result.detectors_triggered,
            processing_time_ms=result.processing_time_ms,
        )

    @app.get("/metrics", response_model=MetricsResponse)
    async def metrics():
        """Get engine metrics."""
        if not _engine:
            raise HTTPException(status_code=503, detail="Engine not initialized")

        m = _engine.get_metrics()
        return MetricsResponse(**m)

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            engine_initialized=_engine is not None and _engine._initialized,
            version="0.1.0",
        )

    @app.middleware("http")
    async def self_protect(request: Request, call_next):
        """Self-protection middleware - analyze requests to this API."""
        # Skip health and metrics endpoints
        if request.url.path in ["/health", "/metrics", "/docs", "/openapi.json"]:
            return await call_next(request)

        if _engine and _engine._initialized:
            # Analyze the incoming request
            event = APIEvent(
                request_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                method=request.method,
                path=request.url.path,
                client_ip=request.client.host if request.client else "unknown",
                headers=dict(request.headers),
            )

            result = await _engine.analyze(event)

            if result.action.blocking:
                raise HTTPException(
                    status_code=result.action.response_code,
                    detail=result.action.reason,
                )

        return await call_next(request)

    return app


# For direct uvicorn usage: uvicorn api_shield.server:app
app = create_app()
