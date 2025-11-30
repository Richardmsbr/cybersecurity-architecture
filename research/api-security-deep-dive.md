# API Security Deep Dive: Real-Time Protection Architecture

## Executive Summary

This document provides an in-depth analysis of API security challenges and proposes "API Shield" - an open-source, ML-powered API security platform for real-time threat detection and auto-remediation.

---

## Table of Contents

1. [The API Security Crisis](#the-api-security-crisis)
2. [OWASP API Security Top 10 Analysis](#owasp-api-security-top-10-analysis)
3. [Detection Algorithms](#detection-algorithms)
4. [API Shield Architecture](#api-shield-architecture)
5. [Implementation Details](#implementation-details)
6. [Deployment Patterns](#deployment-patterns)

---

## The API Security Crisis

### Statistics (2024-2025)

| Metric | Value | Source |
|--------|-------|--------|
| Organizations with API security incidents | 95% | Salt Security 2025 |
| Average cost per API incident | $591,404 | Akamai 2024 |
| APIs experiencing BOLA attacks | 78% | Cequence 2024 |
| Organizations with shadow APIs | 67% | Noname Security |
| AI-enhanced attacks on APIs | 25% already experienced | Kong 2024 |
| Projected API attack growth | 996% since 2021 | Salt Security |

### Why Traditional Tools Fail

```
┌─────────────────────────────────────────────────────────────────┐
│                    Traditional Security Stack                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WAF (Web Application Firewall)                                 │
│  ├── Signature-based detection                                  │
│  ├── Cannot understand API business logic                       │
│  ├── High false positive rate for APIs                          │
│  └── Blind to BOLA, business logic abuse                        │
│                                                                  │
│  API Gateway                                                     │
│  ├── Rate limiting (basic)                                      │
│  ├── Authentication enforcement                                 │
│  ├── No behavioral analysis                                     │
│  └── No threat intelligence                                     │
│                                                                  │
│  SAST/DAST                                                       │
│  ├── Point-in-time scanning                                     │
│  ├── Cannot detect runtime attacks                              │
│  ├── No context of normal behavior                              │
│  └── BOLA has no signature to detect                            │
│                                                                  │
│  Result: 95% of organizations still have API security problems  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### The Detection Gap

BOLA (Broken Object Level Authorization) is ranked #1 in OWASP API Top 10, yet:

1. **No Signature**: Unlike SQLi or XSS, BOLA has no malicious payload
2. **Valid Requests**: Exploit requests look identical to legitimate ones
3. **Business Logic**: Requires understanding of authorization context
4. **Low and Slow**: Attackers spread requests over time to avoid detection

```
Legitimate Request:
GET /api/orders/12345
Authorization: Bearer <user_token>
Response: 200 OK

BOLA Attack (identical format):
GET /api/orders/12346  # Different user's order
Authorization: Bearer <user_token>
Response: 200 OK  # Should be 403, but authorization is broken
```

---

## OWASP API Security Top 10 Analysis

### API1:2023 - Broken Object Level Authorization (BOLA)

**Detection Approach**:

```python
class BOLADetector:
    """
    Detect BOLA by analyzing access patterns.

    Key signals:
    1. User accessing many unique object IDs (enumeration)
    2. Sequential ID access patterns
    3. Access to objects outside user's normal scope
    4. Sudden access to new resource types
    """

    def __init__(self, baseline_period_days: int = 14):
        self.baseline_period = baseline_period_days
        self.user_profiles: Dict[str, UserProfile] = {}

    def analyze_request(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        response_code: int
    ) -> RiskScore:
        profile = self.get_or_create_profile(user_id)

        # Signal 1: Unique resource count anomaly
        unique_count = profile.get_unique_count(resource_type, window="1h")
        baseline_avg = profile.get_baseline_unique_avg(resource_type)
        count_score = self._calculate_deviation(unique_count, baseline_avg)

        # Signal 2: Sequential ID pattern
        recent_ids = profile.get_recent_ids(resource_type, limit=10)
        sequential_score = self._detect_sequential_pattern(recent_ids + [resource_id])

        # Signal 3: First-time resource type access
        first_access_score = 0.0
        if not profile.has_accessed_type(resource_type):
            first_access_score = 0.3

        # Signal 4: Success rate on new resources
        # High success rate on first-access resources is suspicious
        success_on_new = profile.get_success_rate_new_resources()
        success_score = success_on_new * 0.4 if success_on_new > 0.9 else 0

        total_score = min(1.0, count_score + sequential_score +
                          first_access_score + success_score)

        return RiskScore(
            score=total_score,
            signals={
                "unique_count_anomaly": count_score,
                "sequential_pattern": sequential_score,
                "first_access_risk": first_access_score,
                "success_rate_risk": success_score
            }
        )

    def _detect_sequential_pattern(self, ids: List[str]) -> float:
        """Detect if IDs follow a sequential or predictable pattern."""
        try:
            numeric_ids = [int(id) for id in ids if id.isdigit()]
            if len(numeric_ids) < 3:
                return 0.0

            # Check for incrementing pattern
            diffs = [numeric_ids[i+1] - numeric_ids[i]
                     for i in range(len(numeric_ids)-1)]

            # If all differences are 1 (or -1), highly suspicious
            if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
                return 0.8

            # If differences are consistent (e.g., all 10s)
            if len(set(diffs)) == 1:
                return 0.6

            return 0.0
        except:
            return 0.0
```

### API2:2023 - Broken Authentication

**Detection Signals**:

| Signal | Detection Method | Risk Weight |
|--------|------------------|-------------|
| Credential stuffing | High volume of failed auths from IP | 0.8 |
| Brute force | Many attempts on same account | 0.9 |
| Token replay | Same token from multiple IPs | 0.7 |
| Session hijacking | Sudden geo/device change | 0.6 |
| Expired token usage | Attempts with expired tokens | 0.4 |

```python
class AuthenticationAnomalyDetector:
    def analyze_auth_attempt(
        self,
        ip: str,
        user_identifier: str,
        success: bool,
        token: Optional[str] = None,
        geo: Optional[GeoLocation] = None,
        device_fingerprint: Optional[str] = None
    ) -> RiskScore:
        signals = {}

        # Credential stuffing detection
        ip_failure_rate = self.get_ip_failure_rate(ip, window="5m")
        if ip_failure_rate > 0.8 and self.get_ip_attempt_count(ip) > 10:
            signals["credential_stuffing"] = 0.8

        # Brute force detection
        account_failures = self.get_account_failures(user_identifier, window="15m")
        if account_failures > 5:
            signals["brute_force"] = min(0.9, account_failures * 0.1)

        # Impossible travel detection
        if success and geo:
            last_auth = self.get_last_successful_auth(user_identifier)
            if last_auth and last_auth.geo:
                travel_speed = self.calculate_travel_speed(
                    last_auth.geo, geo, last_auth.timestamp
                )
                if travel_speed > 1000:  # km/h - impossible without flight
                    signals["impossible_travel"] = 0.7

        # Device change detection
        if success and device_fingerprint:
            known_devices = self.get_known_devices(user_identifier)
            if device_fingerprint not in known_devices:
                signals["new_device"] = 0.3

        return RiskScore(
            score=min(1.0, sum(signals.values())),
            signals=signals
        )
```

### API3:2023 - Broken Object Property Level Authorization

**Detection**: Monitor for mass assignment attempts

```python
class PropertyLevelAuthorizationDetector:
    def __init__(self, openapi_spec: dict):
        self.spec = openapi_spec
        self.readonly_fields = self._extract_readonly_fields()
        self.sensitive_fields = self._extract_sensitive_fields()

    def analyze_request(
        self,
        endpoint: str,
        method: str,
        request_body: dict,
        user_role: str
    ) -> RiskScore:
        signals = {}

        # Get expected schema for endpoint
        expected_fields = self._get_writable_fields(endpoint, method, user_role)

        # Check for unexpected fields
        submitted_fields = set(self._flatten_keys(request_body))
        unexpected = submitted_fields - expected_fields

        if unexpected:
            # Check if attempting to modify sensitive fields
            sensitive_attempted = unexpected & self.sensitive_fields
            if sensitive_attempted:
                signals["sensitive_field_attempt"] = 0.9
                signals["fields"] = list(sensitive_attempted)
            else:
                signals["mass_assignment_attempt"] = 0.5
                signals["fields"] = list(unexpected)

        return RiskScore(
            score=signals.get("sensitive_field_attempt",
                            signals.get("mass_assignment_attempt", 0)),
            signals=signals
        )
```

### API4:2023 - Unrestricted Resource Consumption

**Detection**: Adaptive rate limiting with behavioral baselines

```python
class ResourceConsumptionDetector:
    def __init__(self):
        self.user_baselines: Dict[str, ResourceBaseline] = {}

    def analyze_request(
        self,
        user_id: str,
        endpoint: str,
        request_size: int,
        query_params: dict
    ) -> Tuple[RiskScore, Optional[RateLimit]]:
        baseline = self.get_or_create_baseline(user_id)
        signals = {}

        # Check request size anomaly
        avg_size = baseline.get_avg_request_size(endpoint)
        if request_size > avg_size * 10:
            signals["large_request"] = min(0.8, request_size / (avg_size * 100))

        # Check pagination abuse
        if "limit" in query_params:
            limit = int(query_params.get("limit", 20))
            if limit > 1000:
                signals["pagination_abuse"] = 0.7

        # Check request rate
        current_rate = self.get_current_rate(user_id, endpoint)
        baseline_rate = baseline.get_baseline_rate(endpoint)
        if current_rate > baseline_rate * 5:
            signals["rate_spike"] = min(0.9, current_rate / (baseline_rate * 10))

        # Calculate adaptive rate limit
        risk_score = min(1.0, sum(signals.values()))
        if risk_score > 0.5:
            # Reduce allowed rate based on risk
            new_limit = int(baseline_rate * (1 - risk_score))
            rate_limit = RateLimit(
                requests_per_minute=max(10, new_limit),
                duration_seconds=300
            )
        else:
            rate_limit = None

        return RiskScore(score=risk_score, signals=signals), rate_limit
```

---

## Detection Algorithms

### 1. Sliding Window Rate Limiter

```python
import time
from typing import Tuple
import redis

class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter using Redis sorted sets.

    Advantages over fixed window:
    - No burst at window boundaries
    - Smooth rate limiting
    - Accurate request counting
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        window_seconds: int = 60,
        max_requests: int = 100
    ):
        self.redis = redis_client
        self.window = window_seconds
        self.max_requests = max_requests

    def is_allowed(self, key: str) -> Tuple[bool, dict]:
        now = time.time()
        window_start = now - self.window

        pipe = self.redis.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)

        # Count current entries
        pipe.zcard(key)

        # Add current request
        pipe.zadd(key, {f"{now}:{id(self)}": now})

        # Set expiration
        pipe.expire(key, self.window)

        results = pipe.execute()
        current_count = results[1]

        allowed = current_count < self.max_requests
        remaining = max(0, self.max_requests - current_count - 1)

        return allowed, {
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": int(now + self.window),
            "window": self.window
        }
```

### 2. Token Bucket with Burst Control

```python
import time
from dataclasses import dataclass
from typing import Tuple

@dataclass
class TokenBucket:
    """
    Token bucket rate limiter with configurable burst.

    Use case: Allow short bursts while enforcing average rate.
    """

    capacity: int  # Maximum tokens (burst size)
    refill_rate: float  # Tokens per second
    tokens: float = None
    last_refill: float = None

    def __post_init__(self):
        if self.tokens is None:
            self.tokens = float(self.capacity)
        if self.last_refill is None:
            self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> Tuple[bool, dict]:
        now = time.time()

        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate
        )
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, {
                "remaining": int(self.tokens),
                "capacity": self.capacity,
                "refill_rate": self.refill_rate
            }
        else:
            # Calculate wait time
            deficit = tokens - self.tokens
            wait_seconds = deficit / self.refill_rate
            return False, {
                "remaining": 0,
                "retry_after": wait_seconds,
                "capacity": self.capacity
            }
```

### 3. Behavioral Anomaly Detection

```python
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta

@dataclass
class BehaviorProfile:
    """User behavior profile for anomaly detection."""

    user_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Request patterns
    hourly_request_counts: List[int] = field(default_factory=lambda: [0] * 24)
    endpoint_frequency: Dict[str, int] = field(default_factory=dict)

    # Timing patterns
    avg_request_interval_ms: float = 0.0
    request_interval_stddev: float = 0.0

    # Resource access
    unique_resources_per_day: List[int] = field(default_factory=list)
    resource_access_pattern: Dict[str, List[str]] = field(default_factory=dict)

    # Session patterns
    avg_session_duration: float = 0.0
    avg_requests_per_session: float = 0.0

    # Geo/Device
    known_ips: set = field(default_factory=set)
    known_devices: set = field(default_factory=set)
    known_geos: set = field(default_factory=set)


class BehavioralAnomalyDetector:
    """
    Detect anomalies by comparing current behavior to established baseline.

    Uses statistical methods:
    - Z-score for numerical deviations
    - Entropy for pattern changes
    - Isolation Forest for multivariate anomalies
    """

    def __init__(self, baseline_days: int = 14, min_samples: int = 100):
        self.baseline_days = baseline_days
        self.min_samples = min_samples
        self.profiles: Dict[str, BehaviorProfile] = {}

    def analyze_request(
        self,
        user_id: str,
        endpoint: str,
        timestamp: datetime,
        ip: str,
        device_fingerprint: str,
        response_time_ms: float,
        response_size: int
    ) -> RiskScore:
        profile = self.profiles.get(user_id)

        if not profile or profile.get_sample_count() < self.min_samples:
            # Learning phase - record but don't score
            self._update_profile(user_id, endpoint, timestamp, ip,
                                device_fingerprint, response_time_ms)
            return RiskScore(score=0.0, signals={"status": "learning"})

        signals = {}

        # 1. Time-of-day anomaly
        hour = timestamp.hour
        expected_rate = profile.hourly_request_counts[hour]
        current_rate = self._get_current_hour_rate(user_id)
        if expected_rate > 0:
            time_zscore = (current_rate - expected_rate) / max(1, np.std(profile.hourly_request_counts))
            if time_zscore > 3:
                signals["unusual_time_activity"] = min(0.8, time_zscore / 10)

        # 2. Endpoint frequency anomaly
        endpoint_freq = profile.endpoint_frequency.get(endpoint, 0)
        total_requests = sum(profile.endpoint_frequency.values())
        expected_probability = endpoint_freq / total_requests if total_requests > 0 else 0
        if expected_probability < 0.01:  # Rarely accessed endpoint
            signals["rare_endpoint_access"] = 0.4

        # 3. Request interval anomaly
        last_request_time = self._get_last_request_time(user_id)
        if last_request_time:
            interval_ms = (timestamp - last_request_time).total_seconds() * 1000
            interval_zscore = abs(interval_ms - profile.avg_request_interval_ms) / max(1, profile.request_interval_stddev)
            if interval_zscore > 4:  # Very unusual timing
                signals["timing_anomaly"] = min(0.6, interval_zscore / 10)

        # 4. New IP/Device/Geo
        if ip not in profile.known_ips:
            signals["new_ip"] = 0.3
        if device_fingerprint not in profile.known_devices:
            signals["new_device"] = 0.4

        # 5. Resource access velocity
        unique_today = self._get_unique_resources_today(user_id)
        avg_unique = np.mean(profile.unique_resources_per_day) if profile.unique_resources_per_day else 0
        if avg_unique > 0 and unique_today > avg_unique * 3:
            signals["high_resource_velocity"] = min(0.7, unique_today / (avg_unique * 10))

        total_score = min(1.0, sum(signals.values()))

        return RiskScore(score=total_score, signals=signals)

    def _calculate_zscore(self, value: float, mean: float, stddev: float) -> float:
        if stddev == 0:
            return 0.0
        return abs(value - mean) / stddev
```

### 4. Sequential Pattern Detection (for BOLA)

```python
from typing import List, Tuple
import re

class SequentialPatternDetector:
    """
    Detect sequential/enumeration patterns in resource access.

    Patterns detected:
    - Incrementing integers (1, 2, 3, 4...)
    - Decrementing integers (100, 99, 98...)
    - Fixed step (10, 20, 30...)
    - UUID enumeration attempts
    - Encoded sequence patterns
    """

    def detect_pattern(self, ids: List[str]) -> Tuple[bool, str, float]:
        if len(ids) < 3:
            return False, "insufficient_data", 0.0

        # Try numeric detection
        numeric_result = self._detect_numeric_pattern(ids)
        if numeric_result[0]:
            return numeric_result

        # Try base64/hex encoded detection
        decoded_result = self._detect_encoded_pattern(ids)
        if decoded_result[0]:
            return decoded_result

        # Try UUID enumeration
        uuid_result = self._detect_uuid_pattern(ids)
        if uuid_result[0]:
            return uuid_result

        return False, "no_pattern", 0.0

    def _detect_numeric_pattern(self, ids: List[str]) -> Tuple[bool, str, float]:
        try:
            nums = [int(id) for id in ids]
        except ValueError:
            return False, "not_numeric", 0.0

        diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]

        # Check for constant difference (arithmetic sequence)
        if len(set(diffs)) == 1:
            step = diffs[0]
            if step == 1:
                return True, "incrementing", 0.95
            elif step == -1:
                return True, "decrementing", 0.95
            elif abs(step) <= 100:
                return True, f"step_{step}", 0.85

        # Check for mostly sequential (allows some noise)
        sequential_count = sum(1 for d in diffs if abs(d) == 1)
        if sequential_count / len(diffs) > 0.8:
            return True, "mostly_sequential", 0.75

        return False, "random_numeric", 0.0

    def _detect_uuid_pattern(self, ids: List[str]) -> Tuple[bool, str, float]:
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )

        if not all(uuid_pattern.match(id) for id in ids):
            return False, "not_uuid", 0.0

        # Check if UUIDs share common prefixes (brute force attempt)
        prefixes = [id[:8] for id in ids]
        if len(set(prefixes)) == 1:
            return True, "uuid_prefix_enumeration", 0.8

        # Check for sequential UUID v1 timestamps
        # UUID v1 has timestamp in first segments
        try:
            timestamps = []
            for uuid in ids:
                # Extract timestamp from UUID v1
                parts = uuid.split('-')
                time_low = int(parts[0], 16)
                timestamps.append(time_low)

            diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if len(set(diffs)) == 1:
                return True, "uuid_v1_sequential", 0.7
        except:
            pass

        return False, "random_uuid", 0.0

    def _detect_encoded_pattern(self, ids: List[str]) -> Tuple[bool, str, float]:
        import base64

        decoded = []
        for id in ids:
            try:
                # Try base64 decode
                decoded_bytes = base64.b64decode(id)
                decoded.append(int.from_bytes(decoded_bytes[-4:], 'big'))
            except:
                try:
                    # Try hex decode
                    decoded.append(int(id, 16))
                except:
                    return False, "not_encoded", 0.0

        if len(decoded) == len(ids):
            return self._detect_numeric_pattern([str(d) for d in decoded])

        return False, "decode_failed", 0.0
```

---

## API Shield Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           API Shield                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    Ingestion Layer                          │    │
│  ├────────────────────────────────────────────────────────────┤    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │    │
│  │  │  Kong    │ │  APISIX  │ │  Envoy   │ │  Nginx   │      │    │
│  │  │  Plugin  │ │  Plugin  │ │  Filter  │ │  Module  │      │    │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │    │
│  │       └────────────┴────────────┴────────────┘             │    │
│  │                           │                                 │    │
│  │                    ┌──────▼──────┐                         │    │
│  │                    │   Kafka /   │                         │    │
│  │                    │   NATS      │                         │    │
│  │                    └──────┬──────┘                         │    │
│  └───────────────────────────┼────────────────────────────────┘    │
│                              │                                      │
│  ┌───────────────────────────▼────────────────────────────────┐    │
│  │                    Analysis Engine                          │    │
│  ├─────────────────────────────────────────────────────────────┤    │
│  │                                                              │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │    │
│  │  │   BOLA      │  │   Auth      │  │  Rate       │         │    │
│  │  │  Detector   │  │  Anomaly    │  │  Anomaly    │         │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │    │
│  │         │                │                │                 │    │
│  │         └────────────────┼────────────────┘                 │    │
│  │                          │                                  │    │
│  │                   ┌──────▼──────┐                          │    │
│  │                   │   Risk      │                          │    │
│  │                   │  Scorer     │                          │    │
│  │                   └──────┬──────┘                          │    │
│  │                          │                                  │    │
│  │  ┌─────────────┐  ┌──────▼──────┐  ┌─────────────┐         │    │
│  │  │  Behavior   │  │     ML      │  │   Threat    │         │    │
│  │  │  Profiler   │──│   Models    │──│   Intel     │         │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘         │    │
│  │                                                              │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                    Action Engine                             │   │
│  ├──────────────────────────────────────────────────────────────┤   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │   │
│  │  │   Block     │  │   Rate      │  │   Alert     │          │   │
│  │  │   Request   │  │   Limit     │  │   Generate  │          │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘          │   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │   │
│  │  │   Require   │  │   Log &     │  │   Auto      │          │   │
│  │  │   MFA       │  │   Audit     │  │   Remediate │          │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘          │   │
│  │                                                               │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Data Layer                                   │ │
│  ├────────────────────────────────────────────────────────────────┤ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │ │
│  │  │  Redis   │  │ ClickHse │  │ Postgres │  │  S3/Minio│       │ │
│  │  │ (Cache)  │  │ (Logs)   │  │ (Config) │  │ (Archive)│       │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Component Details

#### 1. Ingestion Layer

Gateway plugins that capture API traffic with minimal latency:

```go
// Kong Plugin (Go)
package main

import (
    "github.com/Kong/go-pdk"
    "github.com/nats-io/nats.go"
)

type Config struct {
    NatsURL string `json:"nats_url"`
    Topic   string `json:"topic"`
}

func New() interface{} {
    return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
    // Capture request metadata
    headers, _ := kong.Request.GetHeaders(-1)
    path, _ := kong.Request.GetPath()
    method, _ := kong.Request.GetMethod()
    clientIP, _ := kong.Client.GetIp()

    // Get user identity
    consumer, _ := kong.Client.GetConsumer()

    event := APIEvent{
        Timestamp:  time.Now(),
        Method:     method,
        Path:       path,
        ClientIP:   clientIP,
        UserID:     consumer.Id,
        Headers:    headers,
        Phase:      "request",
    }

    // Async publish to NATS (non-blocking)
    go publishEvent(conf.NatsURL, conf.Topic, event)
}

func (conf Config) Response(kong *pdk.PDK) {
    status, _ := kong.ServiceResponse.GetStatus()
    latency, _ := kong.Kong.GetPluginLatency()

    event := APIEvent{
        Timestamp:    time.Now(),
        ResponseCode: status,
        Latency:      latency,
        Phase:        "response",
    }

    go publishEvent(conf.NatsURL, conf.Topic, event)
}
```

#### 2. Analysis Engine

Real-time stream processing:

```python
# analysis_engine.py
import asyncio
from nats.aio.client import Client as NATS
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class AnalysisResult:
    request_id: str
    risk_score: float
    signals: Dict[str, float]
    recommended_action: str
    blocking: bool

class AnalysisEngine:
    def __init__(self):
        self.detectors = [
            BOLADetector(),
            AuthAnomalyDetector(),
            RateAnomalyDetector(),
            BehavioralAnomalyDetector(),
            PropertyAuthorizationDetector(),
        ]
        self.risk_aggregator = RiskAggregator()
        self.action_decider = ActionDecider()

    async def start(self, nats_url: str, subject: str):
        nc = NATS()
        await nc.connect(nats_url)

        async def message_handler(msg):
            event = APIEvent.from_json(msg.data)
            result = await self.analyze(event)

            # Publish result for action engine
            await nc.publish(
                "shield.actions",
                result.to_json().encode()
            )

        await nc.subscribe(subject, cb=message_handler)

    async def analyze(self, event: APIEvent) -> AnalysisResult:
        # Run all detectors concurrently
        tasks = [
            detector.analyze(event)
            for detector in self.detectors
        ]
        results = await asyncio.gather(*tasks)

        # Aggregate risk scores
        aggregated = self.risk_aggregator.aggregate(results)

        # Decide action
        action = self.action_decider.decide(aggregated)

        return AnalysisResult(
            request_id=event.request_id,
            risk_score=aggregated.score,
            signals=aggregated.signals,
            recommended_action=action.type,
            blocking=action.blocking
        )


class RiskAggregator:
    """Combine multiple detector outputs into single risk score."""

    DETECTOR_WEIGHTS = {
        "bola": 0.30,
        "auth_anomaly": 0.25,
        "rate_anomaly": 0.20,
        "behavioral": 0.15,
        "property_auth": 0.10
    }

    def aggregate(self, results: List[RiskScore]) -> RiskScore:
        weighted_sum = 0.0
        all_signals = {}

        for detector_name, result in zip(self.DETECTOR_WEIGHTS.keys(), results):
            weight = self.DETECTOR_WEIGHTS[detector_name]
            weighted_sum += result.score * weight

            # Prefix signals with detector name
            for signal, value in result.signals.items():
                all_signals[f"{detector_name}.{signal}"] = value

        return RiskScore(
            score=min(1.0, weighted_sum),
            signals=all_signals
        )


class ActionDecider:
    """Decide what action to take based on risk score."""

    THRESHOLDS = {
        "block": 0.85,
        "challenge": 0.70,
        "rate_limit": 0.50,
        "monitor": 0.30,
        "allow": 0.0
    }

    def decide(self, risk: RiskScore) -> Action:
        if risk.score >= self.THRESHOLDS["block"]:
            return Action(
                type="block",
                blocking=True,
                reason=self._get_top_signal(risk.signals),
                response_code=403
            )
        elif risk.score >= self.THRESHOLDS["challenge"]:
            return Action(
                type="challenge",
                blocking=True,
                challenge_type="captcha",
                reason=self._get_top_signal(risk.signals)
            )
        elif risk.score >= self.THRESHOLDS["rate_limit"]:
            return Action(
                type="rate_limit",
                blocking=False,
                rate_limit_factor=1 - risk.score,  # Reduce limit proportionally
                reason=self._get_top_signal(risk.signals)
            )
        elif risk.score >= self.THRESHOLDS["monitor"]:
            return Action(
                type="monitor",
                blocking=False,
                alert=True,
                reason=self._get_top_signal(risk.signals)
            )
        else:
            return Action(type="allow", blocking=False)

    def _get_top_signal(self, signals: Dict[str, float]) -> str:
        if not signals:
            return "unknown"
        return max(signals.items(), key=lambda x: x[1])[0]
```

#### 3. ML Models

Anomaly detection using Isolation Forest:

```python
# ml_models.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class APIAnomalyModel:
    """
    Isolation Forest model for detecting anomalous API behavior.

    Features used:
    - Request rate (per minute)
    - Unique endpoints accessed
    - Average response time
    - Error rate
    - Request size
    - Time of day (cyclical encoding)
    - Day of week (cyclical encoding)
    """

    def __init__(self, contamination: float = 0.01):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def extract_features(self, user_data: dict) -> np.ndarray:
        """Extract numerical features from user session data."""
        hour = user_data.get('hour', 12)
        dow = user_data.get('day_of_week', 0)

        features = [
            user_data.get('request_rate', 0),
            user_data.get('unique_endpoints', 0),
            user_data.get('avg_response_time_ms', 0),
            user_data.get('error_rate', 0),
            user_data.get('avg_request_size', 0),
            np.sin(2 * np.pi * hour / 24),  # Cyclical hour encoding
            np.cos(2 * np.pi * hour / 24),
            np.sin(2 * np.pi * dow / 7),    # Cyclical day encoding
            np.cos(2 * np.pi * dow / 7),
            user_data.get('unique_resources', 0),
            user_data.get('session_duration_min', 0),
        ]

        return np.array(features).reshape(1, -1)

    def fit(self, training_data: List[dict]):
        """Train the model on historical normal traffic."""
        X = np.vstack([
            self.extract_features(d) for d in training_data
        ])

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

    def predict(self, user_data: dict) -> Tuple[bool, float]:
        """
        Predict if behavior is anomalous.

        Returns:
            (is_anomaly, anomaly_score)
            anomaly_score: -1 (most anomalous) to 1 (most normal)
        """
        if not self.is_fitted:
            return False, 0.0

        features = self.extract_features(user_data)
        features_scaled = self.scaler.transform(features)

        # Get prediction (-1 for anomaly, 1 for normal)
        prediction = self.model.predict(features_scaled)[0]

        # Get anomaly score (lower = more anomalous)
        score = self.model.decision_function(features_scaled)[0]

        # Normalize score to 0-1 range (1 = most anomalous)
        normalized_score = 1 - (score - self.model.offset_) / (2 * abs(self.model.offset_))
        normalized_score = max(0, min(1, normalized_score))

        is_anomaly = prediction == -1

        return is_anomaly, normalized_score

    def save(self, path: str):
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler
        }, path)

    def load(self, path: str):
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_fitted = True
```

---

## Deployment Patterns

### Pattern 1: Inline (Blocking Mode)

```yaml
# docker-compose.yml for inline deployment
version: '3.8'

services:
  api-shield:
    image: api-shield:latest
    ports:
      - "8080:8080"  # Shield proxy
      - "9090:9090"  # Admin API
    environment:
      - MODE=inline
      - UPSTREAM_URL=http://api:8000
      - REDIS_URL=redis://redis:6379
      - NATS_URL=nats://nats:4222
    depends_on:
      - redis
      - nats
      - analysis-engine

  api:
    image: your-api:latest
    # Not exposed directly - traffic goes through shield

  analysis-engine:
    image: api-shield-analysis:latest
    environment:
      - NATS_URL=nats://nats:4222
      - CLICKHOUSE_URL=http://clickhouse:8123
      - MODEL_PATH=/models/anomaly_model.joblib

  redis:
    image: redis:7-alpine

  nats:
    image: nats:latest

  clickhouse:
    image: clickhouse/clickhouse-server:latest
```

### Pattern 2: Sidecar (Kubernetes)

```yaml
# kubernetes deployment with shield sidecar
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-with-shield
spec:
  template:
    spec:
      containers:
        # Your API container
        - name: api
          image: your-api:latest
          ports:
            - containerPort: 8000

        # API Shield sidecar
        - name: api-shield
          image: api-shield:latest
          ports:
            - containerPort: 8080
          env:
            - name: MODE
              value: "sidecar"
            - name: UPSTREAM_URL
              value: "http://localhost:8000"
            - name: NATS_URL
              valueFrom:
                configMapKeyRef:
                  name: shield-config
                  key: nats_url
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"

      # Init container to wait for dependencies
      initContainers:
        - name: wait-for-nats
          image: busybox
          command: ['sh', '-c', 'until nc -z nats 4222; do sleep 1; done']
```

### Pattern 3: Out-of-Band (Monitoring Only)

```yaml
# Mirror traffic for analysis without blocking
services:
  traffic-mirror:
    image: api-shield-mirror:latest
    environment:
      - MIRROR_SOURCE=kong  # or envoy, nginx
      - NATS_URL=nats://nats:4222
    # Receives mirrored traffic, doesn't block

  analysis-engine:
    image: api-shield-analysis:latest
    environment:
      - MODE=monitor  # Alert only, no blocking
      - ALERT_WEBHOOK=https://slack.webhook.url
```

---

## Configuration Reference

```yaml
# api-shield.yaml
version: "1.0"

mode: inline  # inline, sidecar, monitor

# Detection modules
detection:
  bola:
    enabled: true
    min_sessions_for_detection: 10000
    unique_resource_threshold: 100  # per hour
    sequential_pattern_score: 0.8

  authentication:
    enabled: true
    failed_login_threshold: 5
    lockout_duration: 900  # seconds
    impossible_travel_enabled: true
    impossible_travel_speed_kmh: 1000

  rate_limiting:
    enabled: true
    algorithm: sliding_window  # token_bucket, leaky_bucket
    default_limit: 100
    window_seconds: 60
    adaptive: true  # Adjust limits based on behavior

  behavioral:
    enabled: true
    baseline_period_days: 14
    min_samples: 100
    anomaly_threshold: 0.7

  property_authorization:
    enabled: true
    openapi_spec_path: /specs/api.yaml
    sensitive_fields:
      - role
      - permissions
      - is_admin
      - balance
      - credit_limit

# Action policies
actions:
  block:
    threshold: 0.85
    response_code: 403
    response_body: '{"error": "Access denied"}'

  challenge:
    threshold: 0.70
    type: captcha  # captcha, mfa, email_verification
    redirect_url: /verify

  rate_limit:
    threshold: 0.50
    reduction_factor: 0.5  # Reduce limit by 50%
    duration: 300  # seconds

  alert:
    threshold: 0.30
    channels:
      - slack
      - pagerduty
      - email

# Integrations
integrations:
  gateway:
    type: kong  # kong, apisix, envoy, nginx
    admin_url: http://kong-admin:8001

  message_queue:
    type: nats  # nats, kafka, redis
    url: nats://nats:4222
    subject: api.events

  storage:
    cache:
      type: redis
      url: redis://redis:6379
    logs:
      type: clickhouse
      url: http://clickhouse:8123
    config:
      type: postgres
      url: postgres://user:pass@postgres:5432/shield

# Observability
observability:
  metrics:
    enabled: true
    port: 9090
    path: /metrics

  tracing:
    enabled: true
    provider: jaeger
    endpoint: http://jaeger:14268/api/traces

  logging:
    level: info
    format: json
```

---

## References

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/)
- [Cloudflare BOLA Detection](https://developers.cloudflare.com/api-shield/security/bola-vulnerability-detection/)
- [Salt Security - API1:2023](https://salt.security/blog/api1-2023-broken-object-level-authentication)
- [MITRE D3FEND - Resource Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis/)
- [Kong Rate Limiting](https://konghq.com/blog/engineering/how-to-design-a-scalable-rate-limiting-algorithm)
- [Rate Limiting Algorithms](https://blog.algomaster.io/p/rate-limiting-algorithms-explained-with-code)
- [Open-appsec ML WAF](https://www.openappsec.io/)

---

*Document Version: 1.0*
*Last Updated: November 2025*
