"""BOLA (Broken Object Level Authorization) detector."""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from ..core import APIEvent, Detector, RiskScore


@dataclass
class UserResourceProfile:
    """Tracks a user's resource access patterns."""

    user_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Resource access tracking
    resource_accesses: Dict[str, List[Tuple[str, datetime]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    # Baseline statistics
    baseline_unique_per_hour: Dict[str, float] = field(default_factory=dict)
    baseline_samples: int = 0

    def add_access(self, resource_type: str, resource_id: str, timestamp: datetime):
        """Record a resource access."""
        self.resource_accesses[resource_type].append((resource_id, timestamp))

        # Keep only last 24 hours of data
        cutoff = timestamp - timedelta(hours=24)
        self.resource_accesses[resource_type] = [
            (rid, ts) for rid, ts in self.resource_accesses[resource_type]
            if ts > cutoff
        ]

    def get_unique_count(self, resource_type: str, window: timedelta) -> int:
        """Get count of unique resources accessed in the time window."""
        cutoff = datetime.utcnow() - window
        accesses = self.resource_accesses.get(resource_type, [])
        unique_ids = set(rid for rid, ts in accesses if ts > cutoff)
        return len(unique_ids)

    def get_recent_ids(self, resource_type: str, limit: int = 10) -> List[str]:
        """Get the most recent resource IDs accessed."""
        accesses = self.resource_accesses.get(resource_type, [])
        sorted_accesses = sorted(accesses, key=lambda x: x[1], reverse=True)
        return [rid for rid, _ in sorted_accesses[:limit]]

    def update_baseline(self, resource_type: str, unique_per_hour: float):
        """Update baseline statistics."""
        current = self.baseline_unique_per_hour.get(resource_type, unique_per_hour)
        # Exponential moving average
        alpha = 0.1
        self.baseline_unique_per_hour[resource_type] = (
            alpha * unique_per_hour + (1 - alpha) * current
        )
        self.baseline_samples += 1


class BOLADetector(Detector):
    """
    Detect Broken Object Level Authorization (BOLA/IDOR) attacks.

    Detection signals:
    1. High number of unique resource IDs accessed (enumeration)
    2. Sequential ID access patterns
    3. Access to unusual resource types
    4. High success rate on first-time resource access
    """

    name = "bola"
    weight = 0.30

    def __init__(
        self,
        min_sessions: int = 10000,
        unique_threshold: int = 100,
        sequential_score: float = 0.8,
        window_hours: int = 1,
    ):
        self.min_sessions = min_sessions
        self.unique_threshold = unique_threshold
        self.sequential_score = sequential_score
        self.window = timedelta(hours=window_hours)

        # User profiles
        self.profiles: Dict[str, UserResourceProfile] = {}

        # Global session counter
        self.session_count = 0

    async def analyze(self, event: APIEvent) -> RiskScore:
        """Analyze an API event for BOLA indicators."""
        if not event.user_id:
            return RiskScore(score=0.0, signals={"status": "no_user_id"})

        resource_type = event.get_resource_type()
        resource_id = event.get_resource_id()

        if not resource_type or not resource_id:
            return RiskScore(score=0.0, signals={"status": "no_resource"})

        # Get or create user profile
        profile = self._get_or_create_profile(event.user_id)

        # Record this access
        profile.add_access(resource_type, resource_id, event.timestamp)
        self.session_count += 1

        # Check if we have enough data for detection
        if self.session_count < self.min_sessions:
            return RiskScore(
                score=0.0,
                signals={"status": "learning", "sessions": self.session_count}
            )

        signals: Dict[str, float] = {}

        # Signal 1: Unique resource count anomaly
        unique_count = profile.get_unique_count(resource_type, self.window)
        baseline_avg = profile.baseline_unique_per_hour.get(resource_type, 10)

        if unique_count > self.unique_threshold:
            # Significant enumeration detected
            signals["enumeration"] = min(0.9, unique_count / (self.unique_threshold * 2))
        elif baseline_avg > 0 and unique_count > baseline_avg * 5:
            # Anomalous compared to user's baseline
            signals["unique_anomaly"] = min(0.7, unique_count / (baseline_avg * 10))

        # Signal 2: Sequential pattern detection
        recent_ids = profile.get_recent_ids(resource_type, limit=10)
        is_sequential, pattern_type, seq_score = self._detect_sequential_pattern(
            recent_ids + [resource_id]
        )
        if is_sequential:
            signals["sequential_pattern"] = seq_score
            signals[f"pattern_type_{pattern_type}"] = seq_score

        # Signal 3: First-time resource type
        if resource_type not in profile.baseline_unique_per_hour:
            signals["new_resource_type"] = 0.3

        # Signal 4: Response success on new resources
        if event.response_code and event.response_code == 200:
            # Check if this is a new resource for this user
            all_ids = set(rid for rid, _ in profile.resource_accesses.get(resource_type, []))
            if resource_id not in all_ids:
                # First successful access to this specific resource
                # High success rate on first accesses is suspicious
                recent_first_accesses = self._count_first_access_successes(profile, resource_type)
                if recent_first_accesses > 10:
                    signals["high_first_access_success"] = min(0.6, recent_first_accesses / 50)

        # Update baseline (if not suspicious)
        total_score = sum(signals.values())
        if total_score < 0.3:
            current_unique = profile.get_unique_count(resource_type, timedelta(hours=1))
            profile.update_baseline(resource_type, current_unique)

        return RiskScore(
            score=min(1.0, total_score),
            signals=signals,
            metadata={
                "resource_type": resource_type,
                "unique_count": unique_count,
                "baseline": baseline_avg,
            }
        )

    def _get_or_create_profile(self, user_id: str) -> UserResourceProfile:
        """Get existing profile or create new one."""
        if user_id not in self.profiles:
            self.profiles[user_id] = UserResourceProfile(user_id=user_id)
        return self.profiles[user_id]

    def _detect_sequential_pattern(
        self, ids: List[str]
    ) -> Tuple[bool, str, float]:
        """
        Detect if IDs follow a sequential or predictable pattern.

        Returns:
            (is_sequential, pattern_type, confidence_score)
        """
        if len(ids) < 3:
            return False, "insufficient", 0.0

        # Try to extract numeric components
        numeric_ids = []
        for id_str in ids:
            # Extract numbers from the ID
            numbers = re.findall(r'\d+', id_str)
            if numbers:
                numeric_ids.append(int(numbers[-1]))  # Use last number

        if len(numeric_ids) < 3:
            return False, "non_numeric", 0.0

        # Calculate differences
        diffs = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]

        # Check for perfect increment (1, 1, 1, ...)
        if all(d == 1 for d in diffs):
            return True, "incrementing", 0.95

        # Check for perfect decrement (-1, -1, -1, ...)
        if all(d == -1 for d in diffs):
            return True, "decrementing", 0.95

        # Check for constant step (10, 10, 10, ...)
        if len(set(diffs)) == 1 and abs(diffs[0]) <= 100:
            return True, f"step_{diffs[0]}", 0.85

        # Check for mostly sequential (80%+ are step 1)
        step_one_count = sum(1 for d in diffs if abs(d) == 1)
        if step_one_count / len(diffs) > 0.8:
            return True, "mostly_sequential", 0.75

        # Check for small range (all within 100 of each other)
        if max(numeric_ids) - min(numeric_ids) < len(numeric_ids) * 2:
            return True, "clustered", 0.60

        return False, "random", 0.0

    def _count_first_access_successes(
        self,
        profile: UserResourceProfile,
        resource_type: str
    ) -> int:
        """Count successful first-time accesses in the last hour."""
        # This is a simplified version - in production, track success/failure
        return profile.get_unique_count(resource_type, timedelta(hours=1))

    async def initialize(self) -> None:
        """Initialize the detector."""
        pass

    async def shutdown(self) -> None:
        """Clean up resources."""
        self.profiles.clear()
