"""Rate anomaly detector with adaptive rate limiting."""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from ..core import APIEvent, Detector, RiskScore


@dataclass
class RateWindow:
    """Sliding window for rate tracking."""
    timestamps: List[float] = field(default_factory=list)
    window_seconds: int = 60

    def add(self, timestamp: float = None):
        """Add a request timestamp."""
        ts = timestamp or time.time()
        self.timestamps.append(ts)
        self._cleanup(ts)

    def count(self) -> int:
        """Get current count in window."""
        self._cleanup()
        return len(self.timestamps)

    def _cleanup(self, now: float = None):
        """Remove timestamps outside the window."""
        now = now or time.time()
        cutoff = now - self.window_seconds
        self.timestamps = [ts for ts in self.timestamps if ts > cutoff]


@dataclass
class UserRateProfile:
    """Tracks rate patterns for a user."""

    user_id: str

    # Current rates by endpoint
    endpoint_rates: Dict[str, RateWindow] = field(default_factory=dict)

    # Global rate
    global_rate: RateWindow = field(default_factory=RateWindow)

    # Baseline statistics
    baseline_rates: Dict[str, float] = field(default_factory=dict)
    baseline_global: float = 0.0
    baseline_samples: int = 0

    def record_request(self, endpoint: str, timestamp: float = None):
        """Record a request."""
        ts = timestamp or time.time()

        # Global rate
        self.global_rate.add(ts)

        # Endpoint rate
        if endpoint not in self.endpoint_rates:
            self.endpoint_rates[endpoint] = RateWindow()
        self.endpoint_rates[endpoint].add(ts)

    def get_rate(self, endpoint: str = None) -> int:
        """Get current rate (requests per minute)."""
        if endpoint:
            window = self.endpoint_rates.get(endpoint)
            return window.count() if window else 0
        return self.global_rate.count()

    def update_baseline(self):
        """Update baseline with current rates."""
        # Exponential moving average
        alpha = 0.1

        current_global = self.global_rate.count()
        self.baseline_global = (
            alpha * current_global + (1 - alpha) * self.baseline_global
            if self.baseline_global > 0 else current_global
        )

        for endpoint, window in self.endpoint_rates.items():
            current = window.count()
            if endpoint in self.baseline_rates:
                self.baseline_rates[endpoint] = (
                    alpha * current + (1 - alpha) * self.baseline_rates[endpoint]
                )
            else:
                self.baseline_rates[endpoint] = current

        self.baseline_samples += 1


class RateAnomalyDetector(Detector):
    """
    Detect rate anomalies and provide adaptive rate limiting.

    Detection signals:
    1. Rate exceeds absolute threshold
    2. Rate exceeds user's baseline by significant factor
    3. Sudden rate spike (derivative)
    4. Endpoint-specific rate anomalies
    """

    name = "rate"
    weight = 0.20

    def __init__(
        self,
        global_limit: int = 1000,
        endpoint_limit: int = 100,
        baseline_factor: float = 5.0,
        spike_factor: float = 10.0,
        window_seconds: int = 60,
    ):
        self.global_limit = global_limit
        self.endpoint_limit = endpoint_limit
        self.baseline_factor = baseline_factor
        self.spike_factor = spike_factor
        self.window_seconds = window_seconds

        # User profiles
        self.profiles: Dict[str, UserRateProfile] = {}

        # IP-based rate tracking (for unauthenticated requests)
        self.ip_rates: Dict[str, RateWindow] = defaultdict(RateWindow)

        # Previous rates for spike detection
        self.previous_rates: Dict[str, int] = {}

    async def analyze(self, event: APIEvent) -> RiskScore:
        """Analyze an API event for rate anomalies."""
        signals: Dict[str, float] = {}
        metadata: Dict[str, any] = {}

        # Get identifier (user_id or IP)
        identifier = event.user_id or f"ip:{event.client_ip}"
        endpoint = f"{event.method}:{event.path}"

        # Record request
        if event.user_id:
            profile = self._get_or_create_profile(event.user_id)
            profile.record_request(endpoint)
            current_global = profile.get_rate()
            current_endpoint = profile.get_rate(endpoint)
            baseline_global = profile.baseline_global
            baseline_endpoint = profile.baseline_rates.get(endpoint, 0)
        else:
            # IP-based tracking
            self.ip_rates[event.client_ip].add()
            current_global = self.ip_rates[event.client_ip].count()
            current_endpoint = current_global  # Same for IP-based
            baseline_global = 0  # No baseline for IP
            baseline_endpoint = 0

        metadata["current_rate"] = current_global
        metadata["endpoint_rate"] = current_endpoint
        metadata["baseline_global"] = baseline_global

        # Check 1: Absolute global limit
        if current_global > self.global_limit:
            signals["global_limit_exceeded"] = min(
                0.9, current_global / (self.global_limit * 2)
            )

        # Check 2: Absolute endpoint limit
        if current_endpoint > self.endpoint_limit:
            signals["endpoint_limit_exceeded"] = min(
                0.8, current_endpoint / (self.endpoint_limit * 2)
            )

        # Check 3: Baseline anomaly (only for authenticated users with baseline)
        if event.user_id and baseline_global > 0:
            if current_global > baseline_global * self.baseline_factor:
                signals["baseline_anomaly"] = min(
                    0.7, current_global / (baseline_global * self.baseline_factor * 2)
                )

            if baseline_endpoint > 0 and current_endpoint > baseline_endpoint * self.baseline_factor:
                signals["endpoint_baseline_anomaly"] = min(
                    0.6, current_endpoint / (baseline_endpoint * self.baseline_factor * 2)
                )

        # Check 4: Rate spike
        prev_rate = self.previous_rates.get(identifier, 0)
        if prev_rate > 0 and current_global > prev_rate * self.spike_factor:
            signals["rate_spike"] = min(
                0.7, current_global / (prev_rate * self.spike_factor * 2)
            )

        # Update previous rate (every minute)
        self.previous_rates[identifier] = current_global

        # Update baseline if not anomalous
        total_score = sum(signals.values())
        if event.user_id and total_score < 0.3:
            profile = self.profiles.get(event.user_id)
            if profile:
                profile.update_baseline()

        # Calculate recommended rate limit adjustment
        if total_score > 0.5:
            # Recommend reducing rate limit
            reduction_factor = 1 - (total_score * 0.5)
            metadata["recommended_limit"] = int(self.global_limit * reduction_factor)

        return RiskScore(
            score=min(1.0, total_score),
            signals=signals,
            metadata=metadata,
        )

    def _get_or_create_profile(self, user_id: str) -> UserRateProfile:
        """Get or create user rate profile."""
        if user_id not in self.profiles:
            self.profiles[user_id] = UserRateProfile(user_id=user_id)
        return self.profiles[user_id]

    def get_rate_limit(self, user_id: str, risk_score: float) -> Tuple[int, int]:
        """
        Get adaptive rate limit based on risk score.

        Returns:
            (limit, window_seconds)
        """
        if risk_score > 0.8:
            return int(self.global_limit * 0.1), self.window_seconds
        elif risk_score > 0.6:
            return int(self.global_limit * 0.3), self.window_seconds
        elif risk_score > 0.4:
            return int(self.global_limit * 0.5), self.window_seconds
        else:
            return self.global_limit, self.window_seconds

    async def initialize(self) -> None:
        """Initialize the detector."""
        pass

    async def shutdown(self) -> None:
        """Clean up resources."""
        self.profiles.clear()
        self.ip_rates.clear()
