"""Behavioral anomaly detector using ML-based profiling."""

import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core import APIEvent, Detector, RiskScore


@dataclass
class SessionProfile:
    """Tracks behavior within a session."""

    session_id: str
    user_id: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)

    # Request patterns
    endpoints_visited: List[str] = field(default_factory=list)
    methods_used: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    response_codes: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Timing patterns
    request_intervals: List[float] = field(default_factory=list)
    last_request_time: Optional[datetime] = None

    # Content patterns
    payload_sizes: List[int] = field(default_factory=list)
    unique_parameters: Set[str] = field(default_factory=set)

    def add_request(self, event: APIEvent):
        """Record a request in this session."""
        now = event.timestamp

        # Track endpoints
        endpoint = f"{event.method}:{event.path}"
        self.endpoints_visited.append(endpoint)

        # Track methods
        self.methods_used[event.method] += 1

        # Track response codes
        if event.response_code:
            self.response_codes[event.response_code] += 1

        # Track timing
        if self.last_request_time:
            interval = (now - self.last_request_time).total_seconds()
            self.request_intervals.append(interval)
        self.last_request_time = now
        self.last_activity = now

        # Track payload
        if event.request_body:
            self.payload_sizes.append(len(event.request_body))

        # Track parameters
        self.unique_parameters.update(event.query_params.keys())

    def get_avg_interval(self) -> float:
        """Get average request interval."""
        if not self.request_intervals:
            return 0.0
        return sum(self.request_intervals) / len(self.request_intervals)

    def get_interval_stddev(self) -> float:
        """Get standard deviation of request intervals."""
        if len(self.request_intervals) < 2:
            return 0.0
        avg = self.get_avg_interval()
        variance = sum((x - avg) ** 2 for x in self.request_intervals) / len(self.request_intervals)
        return math.sqrt(variance)


@dataclass
class UserBehaviorProfile:
    """Long-term behavioral profile for a user."""

    user_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Endpoint preferences
    endpoint_frequency: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_requests: int = 0

    # Temporal patterns
    active_hours: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    active_days: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Request characteristics
    avg_payload_size: float = 0.0
    avg_request_interval: float = 0.0
    typical_parameters: Set[str] = field(default_factory=set)

    # Known good patterns
    known_user_agents: Set[str] = field(default_factory=set)
    known_referrers: Set[str] = field(default_factory=set)

    # Baseline statistics
    baseline_samples: int = 0

    def update_from_session(self, session: SessionProfile):
        """Update profile from a completed session."""
        # Update endpoint frequencies
        for endpoint in session.endpoints_visited:
            self.endpoint_frequency[endpoint] += 1
        self.total_requests += len(session.endpoints_visited)

        # Update temporal patterns
        hour = session.started_at.hour
        day = session.started_at.weekday()
        self.active_hours[hour] += 1
        self.active_days[day] += 1

        # Update request characteristics (exponential moving average)
        alpha = 0.1
        if session.payload_sizes:
            avg_size = sum(session.payload_sizes) / len(session.payload_sizes)
            self.avg_payload_size = (
                alpha * avg_size + (1 - alpha) * self.avg_payload_size
                if self.avg_payload_size > 0 else avg_size
            )

        if session.request_intervals:
            avg_interval = session.get_avg_interval()
            self.avg_request_interval = (
                alpha * avg_interval + (1 - alpha) * self.avg_request_interval
                if self.avg_request_interval > 0 else avg_interval
            )

        # Update known parameters
        self.typical_parameters.update(session.unique_parameters)

        self.baseline_samples += 1

    def get_endpoint_probability(self, endpoint: str) -> float:
        """Get probability of user accessing this endpoint."""
        if self.total_requests == 0:
            return 0.5  # Unknown user, neutral probability
        return self.endpoint_frequency.get(endpoint, 0) / self.total_requests

    def is_typical_hour(self, hour: int) -> bool:
        """Check if this hour is typical for the user."""
        if not self.active_hours:
            return True  # No data, assume typical
        max_activity = max(self.active_hours.values())
        if max_activity == 0:
            return True
        return self.active_hours.get(hour, 0) / max_activity > 0.1


class BehavioralAnomalyDetector(Detector):
    """
    Detect behavioral anomalies using user profiling.

    Detection signals:
    1. Unusual request timing patterns (bot-like behavior)
    2. Unusual endpoint access patterns
    3. Unusual temporal patterns (off-hours access)
    4. Session anomalies (long sessions, high velocity)
    5. Content anomalies (unusual payloads)
    """

    name = "behavioral"
    weight = 0.25

    def __init__(
        self,
        min_requests_for_profile: int = 50,
        bot_interval_threshold: float = 0.1,  # 100ms intervals = bot
        max_session_duration_hours: int = 24,
        unusual_endpoint_threshold: float = 0.01,
        learning_period_requests: int = 10000,
    ):
        self.min_requests_for_profile = min_requests_for_profile
        self.bot_interval_threshold = bot_interval_threshold
        self.max_session_duration = timedelta(hours=max_session_duration_hours)
        self.unusual_endpoint_threshold = unusual_endpoint_threshold
        self.learning_period = learning_period_requests

        # Profiles
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.sessions: Dict[str, SessionProfile] = {}

        # Global statistics
        self.global_request_count = 0
        self.global_endpoint_frequency: Dict[str, int] = defaultdict(int)

    async def analyze(self, event: APIEvent) -> RiskScore:
        """Analyze an API event for behavioral anomalies."""
        signals: Dict[str, float] = {}
        metadata: Dict[str, Any] = {}

        self.global_request_count += 1
        endpoint = f"{event.method}:{event.path}"
        self.global_endpoint_frequency[endpoint] += 1

        # Get or create session
        session_id = self._get_session_id(event)
        session = self._get_or_create_session(session_id, event.user_id)

        # Record request in session
        session.add_request(event)

        # Check if we're still in learning period
        if self.global_request_count < self.learning_period:
            return RiskScore(
                score=0.0,
                signals={"status": "learning"},
                metadata={"requests": self.global_request_count}
            )

        # Get user profile if available
        profile = None
        if event.user_id:
            profile = self.user_profiles.get(event.user_id)

        # Signal 1: Bot-like timing
        if len(session.request_intervals) >= 5:
            avg_interval = session.get_avg_interval()
            stddev = session.get_interval_stddev()

            # Very consistent timing = bot
            if avg_interval < self.bot_interval_threshold:
                signals["bot_timing_fast"] = 0.8
            elif stddev < 0.05 and len(session.request_intervals) > 10:
                # Very consistent intervals (low variance)
                signals["bot_timing_consistent"] = 0.6

            metadata["avg_interval"] = avg_interval
            metadata["interval_stddev"] = stddev

        # Signal 2: Unusual endpoint access
        endpoint_prob = self._get_endpoint_probability(endpoint, profile)
        if endpoint_prob < self.unusual_endpoint_threshold and profile:
            signals["unusual_endpoint"] = min(0.5, (self.unusual_endpoint_threshold - endpoint_prob) * 10)

        # Signal 3: Temporal anomaly (off-hours)
        if profile and profile.baseline_samples > 10:
            current_hour = event.timestamp.hour
            if not profile.is_typical_hour(current_hour):
                signals["off_hours_access"] = 0.3

        # Signal 4: Session anomalies
        session_duration = event.timestamp - session.started_at
        if session_duration > self.max_session_duration:
            signals["long_session"] = 0.4

        # High velocity within session
        request_count = len(session.endpoints_visited)
        session_minutes = max(1, session_duration.total_seconds() / 60)
        requests_per_minute = request_count / session_minutes

        if requests_per_minute > 60:  # More than 1 req/sec sustained
            signals["high_velocity"] = min(0.7, requests_per_minute / 120)

        # Signal 5: Unusual error rate
        if session.response_codes:
            total_responses = sum(session.response_codes.values())
            error_responses = sum(
                count for code, count in session.response_codes.items()
                if code >= 400
            )
            error_rate = error_responses / total_responses
            if error_rate > 0.5 and total_responses > 10:
                signals["high_error_rate"] = min(0.6, error_rate)

        # Signal 6: Unusual payload size
        if profile and profile.avg_payload_size > 0 and event.request_body:
            payload_size = len(event.request_body)
            if payload_size > profile.avg_payload_size * 10:
                signals["large_payload"] = min(0.4, payload_size / (profile.avg_payload_size * 20))

        # Update profile if not suspicious
        total_score = sum(signals.values())
        if total_score < 0.3 and event.user_id:
            self._update_user_profile(event.user_id, session)

        return RiskScore(
            score=min(1.0, total_score),
            signals=signals,
            metadata=metadata,
        )

    def _get_session_id(self, event: APIEvent) -> str:
        """Generate session ID from event."""
        # Try to get session from headers
        session_cookie = event.headers.get("cookie", "")
        if "session" in session_cookie.lower():
            # Extract session ID from cookie
            for part in session_cookie.split(";"):
                if "session" in part.lower():
                    return hashlib.sha256(part.strip().encode()).hexdigest()[:16]

        # Fall back to IP + User-Agent hash
        ua = event.headers.get("user-agent", "")
        combined = f"{event.client_ip}:{ua}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    def _get_or_create_session(self, session_id: str, user_id: Optional[str]) -> SessionProfile:
        """Get existing session or create new one."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionProfile(
                session_id=session_id,
                user_id=user_id,
            )
        return self.sessions[session_id]

    def _get_endpoint_probability(
        self,
        endpoint: str,
        profile: Optional[UserBehaviorProfile]
    ) -> float:
        """Get probability of endpoint access."""
        # User-specific probability
        if profile and profile.total_requests >= self.min_requests_for_profile:
            return profile.get_endpoint_probability(endpoint)

        # Fall back to global probability
        if self.global_request_count > 0:
            return self.global_endpoint_frequency.get(endpoint, 0) / self.global_request_count

        return 0.5  # Unknown

    def _update_user_profile(self, user_id: str, session: SessionProfile):
        """Update user profile from session."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserBehaviorProfile(user_id=user_id)

        profile = self.user_profiles[user_id]
        profile.update_from_session(session)

    def _cleanup_old_sessions(self):
        """Remove sessions older than max duration."""
        cutoff = datetime.utcnow() - self.max_session_duration
        self.sessions = {
            sid: session for sid, session in self.sessions.items()
            if session.last_activity > cutoff
        }

    async def initialize(self) -> None:
        """Initialize the detector."""
        pass

    async def shutdown(self) -> None:
        """Clean up resources."""
        self.user_profiles.clear()
        self.sessions.clear()
