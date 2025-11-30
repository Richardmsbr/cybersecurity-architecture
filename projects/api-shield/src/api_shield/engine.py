"""Analysis and action engine for API Shield."""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .core import (
    Action,
    ActionType,
    AnalysisResult,
    APIEvent,
    Detector,
    RiskScore,
)
from .detectors import (
    AuthAnomalyDetector,
    BehavioralAnomalyDetector,
    BOLADetector,
    RateAnomalyDetector,
)


@dataclass
class EngineConfig:
    """Configuration for the analysis engine."""

    # Risk thresholds
    block_threshold: float = 0.8
    rate_limit_threshold: float = 0.5
    challenge_threshold: float = 0.3
    monitor_threshold: float = 0.1

    # Action configuration
    default_rate_limit: int = 100
    challenge_types: List[str] = field(default_factory=lambda: ["captcha", "mfa"])

    # Processing
    parallel_detection: bool = True
    timeout_seconds: float = 1.0

    # Detector weights (override defaults)
    detector_weights: Dict[str, float] = field(default_factory=dict)


@dataclass
class EngineMetrics:
    """Metrics for the analysis engine."""

    total_requests: int = 0
    blocked_requests: int = 0
    rate_limited_requests: int = 0
    challenged_requests: int = 0
    allowed_requests: int = 0

    avg_processing_time_ms: float = 0.0
    max_processing_time_ms: float = 0.0

    detector_trigger_counts: Dict[str, int] = field(default_factory=dict)


class AnalysisEngine:
    """
    Core analysis engine that orchestrates all detectors.

    This engine:
    1. Routes events to appropriate detectors
    2. Aggregates risk scores with weighting
    3. Applies thresholds and policies
    4. Makes action decisions
    """

    def __init__(self, config: Optional[EngineConfig] = None):
        self.config = config or EngineConfig()
        self.detectors: List[Detector] = []
        self.metrics = EngineMetrics()
        self._initialized = False

    async def initialize(self):
        """Initialize the engine and all detectors."""
        if self._initialized:
            return

        # Create default detectors
        self.detectors = [
            BOLADetector(),
            AuthAnomalyDetector(),
            RateAnomalyDetector(),
            BehavioralAnomalyDetector(),
        ]

        # Apply custom weights if configured
        for detector in self.detectors:
            if detector.name in self.config.detector_weights:
                detector.weight = self.config.detector_weights[detector.name]

        # Initialize all detectors
        await asyncio.gather(*[d.initialize() for d in self.detectors])

        self._initialized = True

    async def shutdown(self):
        """Shutdown the engine and all detectors."""
        await asyncio.gather(*[d.shutdown() for d in self.detectors])
        self._initialized = False

    async def analyze(self, event: APIEvent) -> AnalysisResult:
        """
        Analyze an API event and determine the appropriate action.

        Args:
            event: The API event to analyze

        Returns:
            Complete analysis result with risk score and action
        """
        start_time = time.time()

        # Run all detectors
        if self.config.parallel_detection:
            detector_results = await self._run_detectors_parallel(event)
        else:
            detector_results = await self._run_detectors_sequential(event)

        # Aggregate results
        risk_score, signals, triggered = self._aggregate_results(detector_results)

        # Determine action
        action = self._determine_action(risk_score, signals, event)

        # Calculate processing time
        processing_time_ms = (time.time() - start_time) * 1000

        # Update metrics
        self._update_metrics(action.type, processing_time_ms, triggered)

        return AnalysisResult(
            request_id=event.request_id,
            timestamp=event.timestamp,
            risk_score=risk_score,
            signals=signals,
            action=action,
            detectors_triggered=triggered,
            processing_time_ms=processing_time_ms,
        )

    async def _run_detectors_parallel(
        self,
        event: APIEvent
    ) -> List[Tuple[Detector, RiskScore]]:
        """Run all detectors in parallel."""
        async def run_detector(detector: Detector) -> Tuple[Detector, RiskScore]:
            try:
                result = await asyncio.wait_for(
                    detector.analyze(event),
                    timeout=self.config.timeout_seconds
                )
                return (detector, result)
            except asyncio.TimeoutError:
                return (detector, RiskScore(score=0.0, signals={"timeout": 1.0}))
            except Exception as e:
                return (detector, RiskScore(score=0.0, signals={"error": str(e)}))

        results = await asyncio.gather(*[run_detector(d) for d in self.detectors])
        return list(results)

    async def _run_detectors_sequential(
        self,
        event: APIEvent
    ) -> List[Tuple[Detector, RiskScore]]:
        """Run detectors sequentially."""
        results = []
        for detector in self.detectors:
            try:
                result = await detector.analyze(event)
                results.append((detector, result))
            except Exception as e:
                results.append((detector, RiskScore(score=0.0, signals={"error": str(e)})))
        return results

    def _aggregate_results(
        self,
        detector_results: List[Tuple[Detector, RiskScore]]
    ) -> Tuple[float, Dict[str, float], List[str]]:
        """
        Aggregate detector results into a final risk score.

        Uses weighted average with additional logic for critical signals.
        """
        total_weight = 0.0
        weighted_score = 0.0
        all_signals: Dict[str, float] = {}
        triggered: List[str] = []

        for detector, result in detector_results:
            if result.score > 0:
                weighted_score += result.score * detector.weight
                total_weight += detector.weight
                triggered.append(detector.name)

                # Prefix signals with detector name
                for signal_name, signal_value in result.signals.items():
                    all_signals[f"{detector.name}:{signal_name}"] = signal_value

        # Calculate final score
        if total_weight > 0:
            final_score = weighted_score / total_weight
        else:
            final_score = 0.0

        # Apply critical signal boosts
        final_score = self._apply_critical_boosts(final_score, all_signals)

        return min(1.0, final_score), all_signals, triggered

    def _apply_critical_boosts(
        self,
        score: float,
        signals: Dict[str, float]
    ) -> float:
        """Apply boosts for critical signals."""
        # Critical signals that should increase score
        critical_patterns = [
            ("bola:enumeration", 0.2),
            ("auth:brute_force", 0.2),
            ("auth:credential_stuffing", 0.3),
            ("auth:impossible_travel", 0.2),
            ("rate:global_limit_exceeded", 0.1),
            ("behavioral:bot_timing_fast", 0.1),
        ]

        boost = 0.0
        for pattern, boost_value in critical_patterns:
            if pattern in signals and signals[pattern] > 0.5:
                boost += boost_value

        return min(1.0, score + boost)

    def _determine_action(
        self,
        risk_score: float,
        signals: Dict[str, float],
        event: APIEvent
    ) -> Action:
        """Determine the appropriate action based on risk score and signals."""

        # Block for high risk
        if risk_score >= self.config.block_threshold:
            return Action(
                type=ActionType.BLOCK,
                blocking=True,
                reason=self._generate_block_reason(signals),
                response_code=429 if "rate:" in str(signals) else 403,
                headers={"X-API-Shield-Action": "blocked"},
            )

        # Rate limit for medium-high risk
        if risk_score >= self.config.rate_limit_threshold:
            return Action(
                type=ActionType.RATE_LIMIT,
                blocking=False,
                reason="Rate limiting due to suspicious activity",
                rate_limit={
                    "limit": int(self.config.default_rate_limit * (1 - risk_score)),
                    "window": 60,
                },
                headers={"X-API-Shield-Action": "rate_limited"},
            )

        # Challenge for medium risk
        if risk_score >= self.config.challenge_threshold:
            return Action(
                type=ActionType.CHALLENGE,
                blocking=False,
                reason="Additional verification required",
                challenge_type=self.config.challenge_types[0],
                headers={"X-API-Shield-Action": "challenge"},
            )

        # Monitor for low risk
        if risk_score >= self.config.monitor_threshold:
            return Action(
                type=ActionType.MONITOR,
                blocking=False,
                reason="Monitoring suspicious patterns",
                headers={"X-API-Shield-Action": "monitored"},
            )

        # Allow for minimal risk
        return Action(
            type=ActionType.ALLOW,
            blocking=False,
            headers={"X-API-Shield-Action": "allowed"},
        )

    def _generate_block_reason(self, signals: Dict[str, float]) -> str:
        """Generate human-readable block reason from signals."""
        reasons = []

        if any("bola" in k for k in signals):
            reasons.append("unauthorized resource access pattern")
        if any("brute_force" in k for k in signals):
            reasons.append("authentication attack detected")
        if any("credential_stuffing" in k for k in signals):
            reasons.append("credential stuffing attack")
        if any("rate" in k and "limit" in k for k in signals):
            reasons.append("rate limit exceeded")
        if any("bot" in k for k in signals):
            reasons.append("automated attack pattern")

        if not reasons:
            reasons.append("suspicious activity detected")

        return "Blocked: " + ", ".join(reasons)

    def _update_metrics(
        self,
        action_type: ActionType,
        processing_time: float,
        triggered: List[str]
    ):
        """Update engine metrics."""
        self.metrics.total_requests += 1

        if action_type == ActionType.BLOCK:
            self.metrics.blocked_requests += 1
        elif action_type == ActionType.RATE_LIMIT:
            self.metrics.rate_limited_requests += 1
        elif action_type == ActionType.CHALLENGE:
            self.metrics.challenged_requests += 1
        else:
            self.metrics.allowed_requests += 1

        # Update processing time (exponential moving average)
        alpha = 0.1
        self.metrics.avg_processing_time_ms = (
            alpha * processing_time +
            (1 - alpha) * self.metrics.avg_processing_time_ms
        )
        self.metrics.max_processing_time_ms = max(
            self.metrics.max_processing_time_ms,
            processing_time
        )

        # Update detector triggers
        for detector_name in triggered:
            self.metrics.detector_trigger_counts[detector_name] = (
                self.metrics.detector_trigger_counts.get(detector_name, 0) + 1
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics as dictionary."""
        return {
            "total_requests": self.metrics.total_requests,
            "blocked_requests": self.metrics.blocked_requests,
            "rate_limited_requests": self.metrics.rate_limited_requests,
            "challenged_requests": self.metrics.challenged_requests,
            "allowed_requests": self.metrics.allowed_requests,
            "avg_processing_time_ms": round(self.metrics.avg_processing_time_ms, 2),
            "max_processing_time_ms": round(self.metrics.max_processing_time_ms, 2),
            "detector_triggers": self.metrics.detector_trigger_counts,
            "block_rate": (
                self.metrics.blocked_requests / self.metrics.total_requests
                if self.metrics.total_requests > 0 else 0
            ),
        }


class ActionEngine:
    """
    Executes actions determined by the analysis engine.

    This can be extended to integrate with:
    - API Gateways (Kong, APISIX, Envoy)
    - WAFs
    - Rate limiting systems
    - SIEM/SOAR
    """

    def __init__(self):
        self.action_handlers: Dict[ActionType, callable] = {}

    def register_handler(self, action_type: ActionType, handler: callable):
        """Register a handler for an action type."""
        self.action_handlers[action_type] = handler

    async def execute(self, result: AnalysisResult) -> bool:
        """
        Execute the action from an analysis result.

        Returns:
            True if the request should be blocked
        """
        handler = self.action_handlers.get(result.action.type)
        if handler:
            await handler(result)

        return result.action.blocking

    async def default_block_handler(self, result: AnalysisResult):
        """Default handler for block actions."""
        # Log the block
        print(f"[BLOCK] Request {result.request_id}: {result.action.reason}")
        print(f"  Risk Score: {result.risk_score:.2f}")
        print(f"  Signals: {result.signals}")

    async def default_rate_limit_handler(self, result: AnalysisResult):
        """Default handler for rate limit actions."""
        print(f"[RATE_LIMIT] Request {result.request_id}")
        print(f"  New Limit: {result.action.rate_limit}")

    async def default_challenge_handler(self, result: AnalysisResult):
        """Default handler for challenge actions."""
        print(f"[CHALLENGE] Request {result.request_id}")
        print(f"  Challenge Type: {result.action.challenge_type}")


# Convenience functions for quick setup

async def create_engine(config: Optional[EngineConfig] = None) -> AnalysisEngine:
    """Create and initialize an analysis engine."""
    engine = AnalysisEngine(config)
    await engine.initialize()
    return engine


async def analyze_request(
    engine: AnalysisEngine,
    method: str,
    path: str,
    client_ip: str,
    headers: Optional[Dict[str, str]] = None,
    user_id: Optional[str] = None,
    **kwargs
) -> AnalysisResult:
    """
    Convenience function to analyze a request.

    Example:
        result = await analyze_request(
            engine,
            method="GET",
            path="/api/users/123",
            client_ip="1.2.3.4",
            user_id="user_456"
        )
    """
    import uuid

    event = APIEvent(
        request_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        method=method,
        path=path,
        client_ip=client_ip,
        headers=headers or {},
        user_id=user_id,
        **kwargs
    )

    return await engine.analyze(event)
