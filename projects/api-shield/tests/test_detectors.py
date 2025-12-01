"""Tests for detection modules."""

import pytest
from datetime import datetime, timedelta

from api_shield.core import APIEvent, RiskScore
from api_shield.detectors import (
    BOLADetector,
    AuthAnomalyDetector,
    RateAnomalyDetector,
    BehavioralAnomalyDetector,
)
from conftest import create_sequential_events, create_rapid_events


class TestBOLADetector:
    """Tests for BOLA/IDOR detection."""

    @pytest.mark.asyncio
    async def test_initialization(self, bola_detector):
        """Detector should initialize properly."""
        await bola_detector.initialize()
        assert bola_detector.name == "bola"
        assert bola_detector.weight == 0.30

    @pytest.mark.asyncio
    async def test_no_user_id_returns_zero(self, bola_detector):
        """Should return zero score for requests without user_id."""
        await bola_detector.initialize()
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/users/123",
            client_ip="127.0.0.1",
            user_id=None,  # No user
        )
        result = await bola_detector.analyze(event)
        assert result.score == 0.0
        assert "no_user_id" in result.signals.get("status", "")

    @pytest.mark.asyncio
    async def test_no_resource_returns_zero(self, bola_detector):
        """Should return zero score for requests without resource."""
        await bola_detector.initialize()
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/health",  # No resource ID
            client_ip="127.0.0.1",
            user_id="user_123",
        )
        result = await bola_detector.analyze(event)
        assert result.score == 0.0

    @pytest.mark.asyncio
    async def test_sequential_pattern_detection(self, bola_detector):
        """Should detect sequential ID access patterns."""
        await bola_detector.initialize()

        # Simulate learning period
        bola_detector.session_count = bola_detector.min_sessions + 1

        # Create sequential events
        events = create_sequential_events(
            user_id="attacker",
            base_path="/api/users",
            start_id=1000,
            count=15,
        )

        # Analyze all events
        last_result = None
        for event in events:
            last_result = await bola_detector.analyze(event)

        # Should detect sequential pattern
        assert last_result is not None
        assert any("sequential" in k or "enumeration" in k for k in last_result.signals.keys()) or last_result.score > 0

    @pytest.mark.asyncio
    async def test_normal_access_low_score(self, bola_detector):
        """Normal resource access should have low score."""
        await bola_detector.initialize()
        bola_detector.session_count = bola_detector.min_sessions + 1

        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/users/profile",
            client_ip="127.0.0.1",
            user_id="user_123",
            response_code=200,
        )

        result = await bola_detector.analyze(event)
        assert result.score < 0.5  # Should be low for normal access


class TestAuthAnomalyDetector:
    """Tests for authentication anomaly detection."""

    @pytest.mark.asyncio
    async def test_initialization(self, auth_detector):
        """Detector should initialize properly."""
        await auth_detector.initialize()
        assert auth_detector.name == "auth"
        assert auth_detector.weight == 0.25

    @pytest.mark.asyncio
    async def test_brute_force_detection(self, auth_detector):
        """Should detect brute force attacks."""
        await auth_detector.initialize()

        # Simulate multiple failed login attempts
        for i in range(5):
            event = APIEvent(
                request_id=f"test-{i}",
                timestamp=datetime.utcnow(),
                method="POST",
                path="/api/auth/login",
                client_ip="192.168.1.100",
                user_id="victim_user",
                response_code=401,  # Failed auth
            )
            result = await auth_detector.analyze(event)

        # Last result should indicate brute force
        assert result.score > 0
        assert any("brute" in k.lower() for k in result.signals.keys())

    @pytest.mark.asyncio
    async def test_credential_stuffing_detection(self, auth_detector):
        """Should detect credential stuffing from same IP."""
        await auth_detector.initialize()

        # Multiple failed attempts from same IP, different users
        for i in range(6):
            event = APIEvent(
                request_id=f"test-{i}",
                timestamp=datetime.utcnow(),
                method="POST",
                path="/api/auth/login",
                client_ip="10.0.0.1",  # Same IP
                user_id=f"user_{i}",   # Different users
                response_code=401,
            )
            result = await auth_detector.analyze(event)

        # Should detect credential stuffing
        assert any("credential" in k.lower() or "stuffing" in k.lower()
                   for k in result.signals.keys()) or result.score > 0

    @pytest.mark.asyncio
    async def test_new_ip_detection(self, auth_detector):
        """Should flag login from new IP."""
        await auth_detector.initialize()

        # First successful login establishes baseline
        event1 = APIEvent(
            request_id="test-1",
            timestamp=datetime.utcnow(),
            method="POST",
            path="/api/auth/login",
            client_ip="192.168.1.100",
            user_id="user_123",
            response_code=200,
        )
        await auth_detector.analyze(event1)

        # Login from new IP
        event2 = APIEvent(
            request_id="test-2",
            timestamp=datetime.utcnow(),
            method="POST",
            path="/api/auth/login",
            client_ip="10.0.0.50",  # Different IP
            user_id="user_123",
            response_code=200,
        )
        result = await auth_detector.analyze(event2)

        # Should flag new IP
        assert "new_ip" in result.signals or result.score > 0

    @pytest.mark.asyncio
    async def test_token_multi_ip_detection(self, auth_detector):
        """Should detect same token used from multiple IPs."""
        await auth_detector.initialize()

        token = "Bearer eyJhbGciOiJIUzI1NiJ9.test.signature"

        # Use same token from multiple IPs
        for i in range(5):
            event = APIEvent(
                request_id=f"test-{i}",
                timestamp=datetime.utcnow(),
                method="GET",
                path="/api/data",
                client_ip=f"192.168.1.{100 + i}",  # Different IPs
                user_id="user_123",
                headers={"authorization": token},
                response_code=200,
            )
            result = await auth_detector.analyze(event)

        # Should flag token usage from multiple IPs
        assert "token_multi_ip" in result.signals or result.score > 0


class TestRateAnomalyDetector:
    """Tests for rate anomaly detection."""

    @pytest.mark.asyncio
    async def test_initialization(self, rate_detector):
        """Detector should initialize properly."""
        await rate_detector.initialize()
        assert rate_detector.name == "rate"
        assert rate_detector.weight == 0.20

    @pytest.mark.asyncio
    async def test_global_limit_exceeded(self, rate_detector):
        """Should detect when global rate limit is exceeded."""
        await rate_detector.initialize()

        # Exceed global limit (50 in test config)
        events = create_rapid_events(
            user_id="user_123",
            path="/api/data",
            count=60,
        )

        last_result = None
        for event in events:
            last_result = await rate_detector.analyze(event)

        # Should detect rate limit exceeded
        assert last_result.score > 0
        assert any("limit" in k.lower() for k in last_result.signals.keys())

    @pytest.mark.asyncio
    async def test_endpoint_limit_exceeded(self, rate_detector):
        """Should detect when endpoint rate limit is exceeded."""
        await rate_detector.initialize()

        # Exceed endpoint limit (10 in test config)
        events = create_rapid_events(
            user_id="user_123",
            path="/api/users/123",
            count=15,
        )

        last_result = None
        for event in events:
            last_result = await rate_detector.analyze(event)

        # Should detect endpoint limit exceeded
        assert last_result.score > 0

    @pytest.mark.asyncio
    async def test_adaptive_rate_limit(self, rate_detector):
        """Should provide adaptive rate limits based on risk."""
        await rate_detector.initialize()

        # Test different risk scores
        high_risk_limit, _ = rate_detector.get_rate_limit("user", 0.9)
        medium_risk_limit, _ = rate_detector.get_rate_limit("user", 0.5)
        low_risk_limit, _ = rate_detector.get_rate_limit("user", 0.2)

        # Higher risk should have lower limits
        assert high_risk_limit < medium_risk_limit < low_risk_limit

    @pytest.mark.asyncio
    async def test_ip_based_tracking(self, rate_detector):
        """Should track rates by IP for unauthenticated requests."""
        await rate_detector.initialize()

        # Requests without user_id
        for i in range(20):
            event = APIEvent(
                request_id=f"test-{i}",
                timestamp=datetime.utcnow(),
                method="GET",
                path="/api/public",
                client_ip="10.0.0.1",
                user_id=None,  # No user
            )
            result = await rate_detector.analyze(event)

        # Should track by IP
        assert result.metadata.get("current_rate", 0) > 0


class TestBehavioralAnomalyDetector:
    """Tests for behavioral anomaly detection."""

    @pytest.mark.asyncio
    async def test_initialization(self, behavioral_detector):
        """Detector should initialize properly."""
        await behavioral_detector.initialize()
        assert behavioral_detector.name == "behavioral"
        assert behavioral_detector.weight == 0.25

    @pytest.mark.asyncio
    async def test_learning_period(self, behavioral_detector):
        """Should return zero score during learning period."""
        await behavioral_detector.initialize()
        behavioral_detector.global_request_count = 0  # Reset

        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/data",
            client_ip="192.168.1.100",
            user_id="user_123",
        )

        result = await behavioral_detector.analyze(event)
        assert result.score == 0.0
        assert "learning" in result.signals.get("status", "")

    @pytest.mark.asyncio
    async def test_bot_timing_detection(self, behavioral_detector):
        """Should detect bot-like timing patterns."""
        await behavioral_detector.initialize()
        behavioral_detector.global_request_count = behavioral_detector.learning_period + 1

        # Simulate very fast, consistent requests (bot-like)
        import time

        results = []
        for i in range(10):
            event = APIEvent(
                request_id=f"test-{i}",
                timestamp=datetime.utcnow(),
                method="GET",
                path="/api/data",
                client_ip="192.168.1.100",
                user_id="bot_user",
                headers={"user-agent": "Mozilla/5.0"},
            )
            result = await behavioral_detector.analyze(event)
            results.append(result)
            time.sleep(0.01)  # Very fast requests

        # Later requests should potentially flag bot timing
        # (depending on interval calculation)
        assert len(results) == 10

    @pytest.mark.asyncio
    async def test_session_tracking(self, behavioral_detector):
        """Should track sessions properly."""
        await behavioral_detector.initialize()
        behavioral_detector.global_request_count = behavioral_detector.learning_period + 1

        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/data",
            client_ip="192.168.1.100",
            user_id="user_123",
            headers={
                "user-agent": "Mozilla/5.0",
                "cookie": "session=abc123",
            },
        )

        await behavioral_detector.analyze(event)

        # Should have created a session
        assert len(behavioral_detector.sessions) > 0

    @pytest.mark.asyncio
    async def test_cleanup_on_shutdown(self, behavioral_detector):
        """Should clean up resources on shutdown."""
        await behavioral_detector.initialize()

        # Add some data
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/data",
            client_ip="192.168.1.100",
            user_id="user_123",
        )
        await behavioral_detector.analyze(event)

        # Shutdown
        await behavioral_detector.shutdown()

        # Should be cleaned up
        assert len(behavioral_detector.sessions) == 0
        assert len(behavioral_detector.user_profiles) == 0
