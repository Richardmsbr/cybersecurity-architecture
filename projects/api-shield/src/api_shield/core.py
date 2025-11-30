"""Core types and interfaces for API Shield."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionType(Enum):
    """Types of actions API Shield can take."""
    ALLOW = "allow"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    MONITOR = "monitor"


@dataclass
class RiskScore:
    """Risk assessment result from a detector."""

    score: float  # 0.0 to 1.0
    signals: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.score = max(0.0, min(1.0, self.score))


@dataclass
class APIEvent:
    """Represents an API request/response event."""

    request_id: str
    timestamp: datetime
    method: str
    path: str
    client_ip: str
    user_id: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[bytes] = None
    response_code: Optional[int] = None
    response_body: Optional[bytes] = None
    latency_ms: Optional[float] = None
    geo: Optional[Dict[str, Any]] = None
    device_fingerprint: Optional[str] = None

    def get_resource_type(self) -> Optional[str]:
        """Extract resource type from path (e.g., /api/orders/123 -> orders)."""
        parts = self.path.strip("/").split("/")
        if len(parts) >= 2:
            # Skip 'api' or 'v1' prefixes
            for i, part in enumerate(parts):
                if part not in ("api", "v1", "v2", "v3"):
                    return part
        return None

    def get_resource_id(self) -> Optional[str]:
        """Extract resource ID from path (e.g., /api/orders/123 -> 123)."""
        parts = self.path.strip("/").split("/")
        if len(parts) >= 2:
            # Return last numeric or UUID-like segment
            for part in reversed(parts):
                if part.isdigit() or len(part) == 36:  # UUID length
                    return part
        return None


@dataclass
class Action:
    """Action to take based on analysis."""

    type: ActionType
    blocking: bool = False
    reason: str = ""
    response_code: int = 200
    response_body: Optional[str] = None
    rate_limit: Optional[Dict[str, Any]] = None
    challenge_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Complete analysis result for an API event."""

    request_id: str
    timestamp: datetime
    risk_score: float
    signals: Dict[str, float]
    action: Action
    detectors_triggered: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0


class Detector:
    """Base class for all detectors."""

    name: str = "base"
    weight: float = 1.0

    async def analyze(self, event: APIEvent) -> RiskScore:
        """Analyze an API event and return a risk score."""
        raise NotImplementedError

    async def initialize(self) -> None:
        """Initialize the detector (load models, connect to storage, etc.)."""
        pass

    async def shutdown(self) -> None:
        """Clean up resources."""
        pass
