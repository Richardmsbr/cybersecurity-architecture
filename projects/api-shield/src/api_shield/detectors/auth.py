"""Authentication anomaly detector."""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional, Set, Tuple

from ..core import APIEvent, Detector, RiskScore


@dataclass
class GeoLocation:
    """Geographic location."""
    latitude: float
    longitude: float
    city: Optional[str] = None
    country: Optional[str] = None


@dataclass
class AuthAttempt:
    """Record of an authentication attempt."""
    timestamp: datetime
    ip: str
    success: bool
    geo: Optional[GeoLocation] = None
    device_fingerprint: Optional[str] = None


@dataclass
class UserAuthProfile:
    """Tracks authentication patterns for a user."""

    user_id: str
    attempts: list = field(default_factory=list)
    known_ips: Set[str] = field(default_factory=set)
    known_devices: Set[str] = field(default_factory=set)
    known_geos: Set[Tuple[float, float]] = field(default_factory=set)
    last_successful_auth: Optional[AuthAttempt] = None

    def add_attempt(self, attempt: AuthAttempt):
        """Record an authentication attempt."""
        self.attempts.append(attempt)

        # Keep only last 7 days
        cutoff = datetime.utcnow() - timedelta(days=7)
        self.attempts = [a for a in self.attempts if a.timestamp > cutoff]

        if attempt.success:
            self.last_successful_auth = attempt
            self.known_ips.add(attempt.ip)
            if attempt.device_fingerprint:
                self.known_devices.add(attempt.device_fingerprint)
            if attempt.geo:
                self.known_geos.add((attempt.geo.latitude, attempt.geo.longitude))

    def get_failed_attempts(self, window: timedelta) -> int:
        """Count failed attempts in the time window."""
        cutoff = datetime.utcnow() - window
        return sum(1 for a in self.attempts if not a.success and a.timestamp > cutoff)

    def get_attempts_from_ip(self, ip: str, window: timedelta) -> int:
        """Count attempts from specific IP."""
        cutoff = datetime.utcnow() - window
        return sum(1 for a in self.attempts if a.ip == ip and a.timestamp > cutoff)


class AuthAnomalyDetector(Detector):
    """
    Detect authentication anomalies.

    Detection signals:
    1. Brute force (many failed attempts on same account)
    2. Credential stuffing (many failures from same IP)
    3. Impossible travel (logins from distant locations)
    4. New device/IP on sensitive operations
    5. Token replay (same token from multiple IPs)
    """

    name = "auth"
    weight = 0.25

    def __init__(
        self,
        failed_threshold: int = 5,
        lockout_window_minutes: int = 15,
        impossible_travel_kmh: float = 1000,
        credential_stuffing_threshold: int = 10,
    ):
        self.failed_threshold = failed_threshold
        self.lockout_window = timedelta(minutes=lockout_window_minutes)
        self.impossible_travel_speed = impossible_travel_kmh
        self.credential_stuffing_threshold = credential_stuffing_threshold

        # User profiles
        self.user_profiles: Dict[str, UserAuthProfile] = {}

        # IP tracking
        self.ip_failures: Dict[str, list] = defaultdict(list)

        # Token tracking (token_hash -> set of IPs)
        self.token_ips: Dict[str, Set[str]] = defaultdict(set)

    async def analyze(self, event: APIEvent) -> RiskScore:
        """Analyze an API event for authentication anomalies."""
        signals: Dict[str, float] = {}

        # Check if this is an auth-related endpoint
        is_auth_endpoint = self._is_auth_endpoint(event.path)

        # Extract authentication info
        auth_header = event.headers.get("authorization", "")
        is_failed_auth = event.response_code in (401, 403)

        # Parse geo from event if available
        geo = None
        if event.geo:
            geo = GeoLocation(
                latitude=event.geo.get("latitude", 0),
                longitude=event.geo.get("longitude", 0),
                city=event.geo.get("city"),
                country=event.geo.get("country"),
            )

        # Track IP-level failures (credential stuffing detection)
        if is_auth_endpoint and is_failed_auth:
            self.ip_failures[event.client_ip].append(event.timestamp)
            # Clean old entries
            cutoff = datetime.utcnow() - self.lockout_window
            self.ip_failures[event.client_ip] = [
                ts for ts in self.ip_failures[event.client_ip] if ts > cutoff
            ]

            ip_failure_count = len(self.ip_failures[event.client_ip])
            if ip_failure_count >= self.credential_stuffing_threshold:
                signals["credential_stuffing"] = min(
                    0.9, ip_failure_count / (self.credential_stuffing_threshold * 2)
                )

        # User-specific analysis
        if event.user_id:
            profile = self._get_or_create_profile(event.user_id)

            # Record attempt
            attempt = AuthAttempt(
                timestamp=event.timestamp,
                ip=event.client_ip,
                success=not is_failed_auth,
                geo=geo,
                device_fingerprint=event.device_fingerprint,
            )

            if is_auth_endpoint:
                profile.add_attempt(attempt)

            # Check for brute force
            failed_count = profile.get_failed_attempts(self.lockout_window)
            if failed_count >= self.failed_threshold:
                signals["brute_force"] = min(0.9, failed_count / (self.failed_threshold * 2))

            # Check for impossible travel
            if not is_failed_auth and geo and profile.last_successful_auth:
                last_auth = profile.last_successful_auth
                if last_auth.geo:
                    travel_result = self._check_impossible_travel(
                        last_auth.geo, geo,
                        last_auth.timestamp, event.timestamp
                    )
                    if travel_result[0]:
                        signals["impossible_travel"] = travel_result[1]
                        signals["travel_speed_kmh"] = travel_result[2]

            # Check for new device/IP
            if not is_failed_auth:
                if event.client_ip not in profile.known_ips:
                    signals["new_ip"] = 0.3
                if event.device_fingerprint and \
                   event.device_fingerprint not in profile.known_devices:
                    signals["new_device"] = 0.4

        # Token replay detection
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            token_hash = self._hash_token(token)
            self.token_ips[token_hash].add(event.client_ip)

            if len(self.token_ips[token_hash]) > 3:
                signals["token_multi_ip"] = min(
                    0.8, len(self.token_ips[token_hash]) / 10
                )

        return RiskScore(
            score=min(1.0, sum(signals.values())),
            signals=signals,
        )

    def _get_or_create_profile(self, user_id: str) -> UserAuthProfile:
        """Get or create user auth profile."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserAuthProfile(user_id=user_id)
        return self.user_profiles[user_id]

    def _is_auth_endpoint(self, path: str) -> bool:
        """Check if path is an authentication endpoint."""
        auth_keywords = [
            "/login", "/signin", "/auth",
            "/token", "/oauth", "/session",
            "/password", "/register", "/signup"
        ]
        path_lower = path.lower()
        return any(kw in path_lower for kw in auth_keywords)

    def _check_impossible_travel(
        self,
        geo1: GeoLocation,
        geo2: GeoLocation,
        time1: datetime,
        time2: datetime
    ) -> Tuple[bool, float, float]:
        """
        Check if travel between two locations is physically impossible.

        Returns:
            (is_impossible, risk_score, speed_kmh)
        """
        # Calculate distance using Haversine formula
        distance_km = self._haversine_distance(
            geo1.latitude, geo1.longitude,
            geo2.latitude, geo2.longitude
        )

        # Calculate time difference in hours
        time_diff_hours = (time2 - time1).total_seconds() / 3600

        if time_diff_hours <= 0:
            return False, 0.0, 0.0

        # Calculate required speed
        speed_kmh = distance_km / time_diff_hours

        if speed_kmh > self.impossible_travel_speed:
            # Impossible without supersonic travel
            risk_score = min(0.9, speed_kmh / (self.impossible_travel_speed * 2))
            return True, risk_score, speed_kmh

        return False, 0.0, speed_kmh

    def _haversine_distance(
        self,
        lat1: float, lon1: float,
        lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two points on Earth in km."""
        R = 6371  # Earth's radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def _hash_token(self, token: str) -> str:
        """Hash token for storage (don't store full tokens)."""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()[:16]

    async def initialize(self) -> None:
        """Initialize the detector."""
        pass

    async def shutdown(self) -> None:
        """Clean up resources."""
        self.user_profiles.clear()
        self.ip_failures.clear()
        self.token_ips.clear()
