"""Tests for core types and interfaces."""

import pytest
from datetime import datetime

from api_shield.core import (
    ActionType,
    RiskScore,
    APIEvent,
    Action,
    AnalysisResult,
    Detector,
)


class TestRiskScore:
    """Tests for RiskScore dataclass."""

    def test_score_clamping_high(self):
        """Score should be clamped to 1.0 maximum."""
        score = RiskScore(score=1.5)
        assert score.score == 1.0

    def test_score_clamping_low(self):
        """Score should be clamped to 0.0 minimum."""
        score = RiskScore(score=-0.5)
        assert score.score == 0.0

    def test_score_valid_range(self):
        """Score within valid range should be preserved."""
        score = RiskScore(score=0.75)
        assert score.score == 0.75

    def test_signals_default_empty(self):
        """Signals should default to empty dict."""
        score = RiskScore(score=0.5)
        assert score.signals == {}

    def test_metadata_default_empty(self):
        """Metadata should default to empty dict."""
        score = RiskScore(score=0.5)
        assert score.metadata == {}

    def test_with_signals(self):
        """Score with signals should preserve them."""
        signals = {"brute_force": 0.8, "rate_limit": 0.3}
        score = RiskScore(score=0.6, signals=signals)
        assert score.signals == signals


class TestAPIEvent:
    """Tests for APIEvent dataclass."""

    def test_get_resource_type_standard_path(self):
        """Should extract resource type from standard API path."""
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/users/123",
            client_ip="127.0.0.1",
        )
        assert event.get_resource_type() == "users"

    def test_get_resource_type_versioned_path(self):
        """Should skip version prefix and get resource type."""
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/v1/orders/456",
            client_ip="127.0.0.1",
        )
        assert event.get_resource_type() == "orders"

    def test_get_resource_type_nested_path(self):
        """Should get first resource type from nested path."""
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/v2/customers/789/orders",
            client_ip="127.0.0.1",
        )
        assert event.get_resource_type() == "customers"

    def test_get_resource_id_numeric(self):
        """Should extract numeric resource ID."""
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/users/12345",
            client_ip="127.0.0.1",
        )
        assert event.get_resource_id() == "12345"

    def test_get_resource_id_uuid(self):
        """Should extract UUID resource ID."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path=f"/api/users/{uuid}",
            client_ip="127.0.0.1",
        )
        assert event.get_resource_id() == uuid

    def test_get_resource_id_none(self):
        """Should return None when no resource ID present."""
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/users",
            client_ip="127.0.0.1",
        )
        assert event.get_resource_id() is None


class TestAction:
    """Tests for Action dataclass."""

    def test_block_action(self):
        """Block action should have correct properties."""
        action = Action(
            type=ActionType.BLOCK,
            blocking=True,
            reason="Brute force detected",
            response_code=403,
        )
        assert action.type == ActionType.BLOCK
        assert action.blocking is True
        assert action.response_code == 403

    def test_rate_limit_action(self):
        """Rate limit action should include rate limit config."""
        action = Action(
            type=ActionType.RATE_LIMIT,
            blocking=False,
            rate_limit={"limit": 10, "window": 60},
        )
        assert action.type == ActionType.RATE_LIMIT
        assert action.rate_limit["limit"] == 10

    def test_challenge_action(self):
        """Challenge action should include challenge type."""
        action = Action(
            type=ActionType.CHALLENGE,
            blocking=False,
            challenge_type="captcha",
        )
        assert action.challenge_type == "captcha"


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_analysis_result_creation(self):
        """Should create analysis result with all fields."""
        action = Action(type=ActionType.ALLOW, blocking=False)
        result = AnalysisResult(
            request_id="test-123",
            timestamp=datetime.utcnow(),
            risk_score=0.25,
            signals={"test_signal": 0.25},
            action=action,
            detectors_triggered=["rate"],
            processing_time_ms=1.5,
        )
        assert result.request_id == "test-123"
        assert result.risk_score == 0.25
        assert result.processing_time_ms == 1.5
        assert "rate" in result.detectors_triggered


class TestDetectorBase:
    """Tests for Detector base class."""

    def test_detector_interface(self):
        """Detector should define required interface."""
        assert hasattr(Detector, "analyze")
        assert hasattr(Detector, "initialize")
        assert hasattr(Detector, "shutdown")

    def test_detector_defaults(self):
        """Detector should have default name and weight."""
        detector = Detector()
        assert detector.name == "base"
        assert detector.weight == 1.0

    @pytest.mark.asyncio
    async def test_analyze_not_implemented(self):
        """Base analyze should raise NotImplementedError."""
        detector = Detector()
        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/test",
            client_ip="127.0.0.1",
        )
        with pytest.raises(NotImplementedError):
            await detector.analyze(event)
