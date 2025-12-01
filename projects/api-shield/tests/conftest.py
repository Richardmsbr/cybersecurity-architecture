"""Pytest configuration and fixtures for API Shield tests."""

import pytest
from datetime import datetime
from typing import Generator

from api_shield.core import APIEvent
from api_shield.engine import AnalysisEngine, EngineConfig
from api_shield.detectors import (
    BOLADetector,
    AuthAnomalyDetector,
    RateAnomalyDetector,
    BehavioralAnomalyDetector,
)


@pytest.fixture
def sample_event() -> APIEvent:
    """Create a sample API event for testing."""
    return APIEvent(
        request_id="test-req-001",
        timestamp=datetime.utcnow(),
        method="GET",
        path="/api/users/123",
        client_ip="192.168.1.100",
        user_id="user_456",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        },
        query_params={"include": "profile"},
        response_code=200,
    )


@pytest.fixture
def auth_failure_event() -> APIEvent:
    """Create an authentication failure event."""
    return APIEvent(
        request_id="test-req-002",
        timestamp=datetime.utcnow(),
        method="POST",
        path="/api/auth/login",
        client_ip="192.168.1.100",
        user_id="user_456",
        headers={"user-agent": "Mozilla/5.0"},
        response_code=401,
    )


@pytest.fixture
def bola_detector() -> BOLADetector:
    """Create a BOLA detector instance."""
    return BOLADetector(
        min_sessions=10,  # Lower for testing
        unique_threshold=5,
        sequential_score=0.8,
    )


@pytest.fixture
def auth_detector() -> AuthAnomalyDetector:
    """Create an auth anomaly detector instance."""
    return AuthAnomalyDetector(
        failed_threshold=3,  # Lower for testing
        lockout_window_minutes=5,
        impossible_travel_kmh=1000,
        credential_stuffing_threshold=5,
    )


@pytest.fixture
def rate_detector() -> RateAnomalyDetector:
    """Create a rate anomaly detector instance."""
    return RateAnomalyDetector(
        global_limit=50,  # Lower for testing
        endpoint_limit=10,
        baseline_factor=3.0,
        spike_factor=5.0,
    )


@pytest.fixture
def behavioral_detector() -> BehavioralAnomalyDetector:
    """Create a behavioral anomaly detector instance."""
    return BehavioralAnomalyDetector(
        min_requests_for_profile=10,
        bot_interval_threshold=0.1,
        learning_period_requests=5,  # Lower for testing
    )


@pytest.fixture
def engine_config() -> EngineConfig:
    """Create an engine configuration for testing."""
    return EngineConfig(
        block_threshold=0.8,
        rate_limit_threshold=0.5,
        challenge_threshold=0.3,
        monitor_threshold=0.1,
        parallel_detection=True,
        timeout_seconds=5.0,
    )


@pytest.fixture
async def engine(engine_config: EngineConfig) -> Generator[AnalysisEngine, None, None]:
    """Create and initialize an analysis engine."""
    eng = AnalysisEngine(engine_config)
    await eng.initialize()
    yield eng
    await eng.shutdown()


def create_sequential_events(
    user_id: str,
    base_path: str,
    start_id: int,
    count: int,
    client_ip: str = "192.168.1.100"
) -> list[APIEvent]:
    """Create a sequence of events with sequential IDs (for BOLA testing)."""
    events = []
    for i in range(count):
        events.append(APIEvent(
            request_id=f"test-seq-{i}",
            timestamp=datetime.utcnow(),
            method="GET",
            path=f"{base_path}/{start_id + i}",
            client_ip=client_ip,
            user_id=user_id,
            headers={"user-agent": "Mozilla/5.0"},
            response_code=200,
        ))
    return events


def create_rapid_events(
    user_id: str,
    path: str,
    count: int,
    client_ip: str = "192.168.1.100"
) -> list[APIEvent]:
    """Create multiple rapid events (for rate limiting testing)."""
    events = []
    for i in range(count):
        events.append(APIEvent(
            request_id=f"test-rapid-{i}",
            timestamp=datetime.utcnow(),
            method="GET",
            path=path,
            client_ip=client_ip,
            user_id=user_id,
            headers={"user-agent": "Mozilla/5.0"},
            response_code=200,
        ))
    return events
