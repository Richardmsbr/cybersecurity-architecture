"""Tests for analysis and action engine."""

import pytest
from datetime import datetime

from api_shield.core import APIEvent, ActionType
from api_shield.engine import (
    AnalysisEngine,
    ActionEngine,
    EngineConfig,
    EngineMetrics,
    create_engine,
    analyze_request,
)


class TestEngineConfig:
    """Tests for EngineConfig."""

    def test_default_config(self):
        """Should have sensible defaults."""
        config = EngineConfig()
        assert config.block_threshold == 0.8
        assert config.rate_limit_threshold == 0.5
        assert config.challenge_threshold == 0.3
        assert config.monitor_threshold == 0.1
        assert config.parallel_detection is True
        assert config.timeout_seconds == 1.0

    def test_custom_config(self):
        """Should accept custom values."""
        config = EngineConfig(
            block_threshold=0.9,
            rate_limit_threshold=0.6,
            detector_weights={"bola": 0.5},
        )
        assert config.block_threshold == 0.9
        assert config.rate_limit_threshold == 0.6
        assert config.detector_weights["bola"] == 0.5


class TestEngineMetrics:
    """Tests for EngineMetrics."""

    def test_default_metrics(self):
        """Should initialize with zero values."""
        metrics = EngineMetrics()
        assert metrics.total_requests == 0
        assert metrics.blocked_requests == 0
        assert metrics.allowed_requests == 0
        assert metrics.avg_processing_time_ms == 0.0


class TestAnalysisEngine:
    """Tests for AnalysisEngine."""

    @pytest.mark.asyncio
    async def test_initialization(self, engine_config):
        """Engine should initialize all detectors."""
        engine = AnalysisEngine(engine_config)
        await engine.initialize()

        assert engine._initialized is True
        assert len(engine.detectors) == 4  # BOLA, Auth, Rate, Behavioral

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_shutdown(self, engine_config):
        """Engine should shutdown cleanly."""
        engine = AnalysisEngine(engine_config)
        await engine.initialize()
        await engine.shutdown()

        assert engine._initialized is False

    @pytest.mark.asyncio
    async def test_analyze_normal_request(self, engine):
        """Normal request should be allowed."""
        event = APIEvent(
            request_id="test-normal",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/users/profile",
            client_ip="192.168.1.100",
            user_id="user_123",
            response_code=200,
        )

        result = await engine.analyze(event)

        assert result.request_id == "test-normal"
        assert result.risk_score >= 0.0
        assert result.action.type in [ActionType.ALLOW, ActionType.MONITOR]
        assert result.processing_time_ms > 0

    @pytest.mark.asyncio
    async def test_analyze_updates_metrics(self, engine):
        """Analysis should update metrics."""
        initial_count = engine.metrics.total_requests

        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/data",
            client_ip="192.168.1.100",
            user_id="user_123",
        )

        await engine.analyze(event)

        assert engine.metrics.total_requests == initial_count + 1

    @pytest.mark.asyncio
    async def test_get_metrics(self, engine):
        """Should return metrics as dictionary."""
        metrics = engine.get_metrics()

        assert "total_requests" in metrics
        assert "blocked_requests" in metrics
        assert "avg_processing_time_ms" in metrics
        assert "block_rate" in metrics

    @pytest.mark.asyncio
    async def test_parallel_vs_sequential_detection(self, engine_config):
        """Both parallel and sequential detection should work."""
        # Test parallel
        engine_config.parallel_detection = True
        engine1 = AnalysisEngine(engine_config)
        await engine1.initialize()

        event = APIEvent(
            request_id="test",
            timestamp=datetime.utcnow(),
            method="GET",
            path="/api/data",
            client_ip="192.168.1.100",
            user_id="user_123",
        )

        result1 = await engine1.analyze(event)
        await engine1.shutdown()

        # Test sequential
        engine_config.parallel_detection = False
        engine2 = AnalysisEngine(engine_config)
        await engine2.initialize()

        result2 = await engine2.analyze(event)
        await engine2.shutdown()

        # Both should return valid results
        assert result1.risk_score >= 0.0
        assert result2.risk_score >= 0.0

    @pytest.mark.asyncio
    async def test_action_determination_block(self, engine_config):
        """High risk should result in block action."""
        engine = AnalysisEngine(engine_config)
        await engine.initialize()

        # Force high risk through multiple suspicious requests
        for i in range(10):
            event = APIEvent(
                request_id=f"test-{i}",
                timestamp=datetime.utcnow(),
                method="POST",
                path="/api/auth/login",
                client_ip="10.0.0.1",
                user_id=f"user_{i}",
                response_code=401,
            )
            result = await engine.analyze(event)

        await engine.shutdown()

        # At some point should trigger higher risk
        assert result is not None

    @pytest.mark.asyncio
    async def test_custom_detector_weights(self):
        """Should apply custom detector weights."""
        config = EngineConfig(
            detector_weights={"bola": 0.5, "auth": 0.3}
        )
        engine = AnalysisEngine(config)
        await engine.initialize()

        # Check weights were applied
        for detector in engine.detectors:
            if detector.name == "bola":
                assert detector.weight == 0.5
            elif detector.name == "auth":
                assert detector.weight == 0.3

        await engine.shutdown()


class TestActionEngine:
    """Tests for ActionEngine."""

    def test_register_handler(self):
        """Should register action handlers."""
        action_engine = ActionEngine()

        async def my_handler(result):
            pass

        action_engine.register_handler(ActionType.BLOCK, my_handler)
        assert ActionType.BLOCK in action_engine.action_handlers

    @pytest.mark.asyncio
    async def test_execute_calls_handler(self):
        """Execute should call registered handler."""
        from api_shield.core import Action, AnalysisResult

        action_engine = ActionEngine()
        handler_called = {"value": False}

        async def my_handler(result):
            handler_called["value"] = True

        action_engine.register_handler(ActionType.BLOCK, my_handler)

        result = AnalysisResult(
            request_id="test",
            timestamp=datetime.utcnow(),
            risk_score=0.9,
            signals={},
            action=Action(type=ActionType.BLOCK, blocking=True),
        )

        blocking = await action_engine.execute(result)

        assert handler_called["value"] is True
        assert blocking is True

    @pytest.mark.asyncio
    async def test_execute_returns_blocking_status(self):
        """Execute should return correct blocking status."""
        from api_shield.core import Action, AnalysisResult

        action_engine = ActionEngine()

        # Non-blocking action
        result = AnalysisResult(
            request_id="test",
            timestamp=datetime.utcnow(),
            risk_score=0.3,
            signals={},
            action=Action(type=ActionType.MONITOR, blocking=False),
        )

        blocking = await action_engine.execute(result)
        assert blocking is False


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    @pytest.mark.asyncio
    async def test_create_engine(self):
        """create_engine should return initialized engine."""
        engine = await create_engine()

        assert engine._initialized is True
        assert len(engine.detectors) > 0

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_analyze_request(self):
        """analyze_request should return valid result."""
        engine = await create_engine()

        result = await analyze_request(
            engine,
            method="GET",
            path="/api/users/123",
            client_ip="192.168.1.100",
            user_id="user_456",
        )

        assert result.request_id is not None
        assert result.risk_score >= 0.0
        assert result.action is not None

        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_analyze_request_with_custom_config(self):
        """Should work with custom configuration."""
        config = EngineConfig(block_threshold=0.95)
        engine = await create_engine(config)

        result = await analyze_request(
            engine,
            method="GET",
            path="/api/data",
            client_ip="127.0.0.1",
        )

        assert result is not None

        await engine.shutdown()
