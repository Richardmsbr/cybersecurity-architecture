"""API Shield - Real-time API security with ML-powered threat detection."""

__version__ = "0.1.0"

from .core import (
    Action,
    ActionType,
    AnalysisResult,
    APIEvent,
    Detector,
    RiskScore,
)
from .engine import (
    ActionEngine,
    AnalysisEngine,
    EngineConfig,
    analyze_request,
    create_engine,
)
from .detectors import (
    AuthAnomalyDetector,
    BehavioralAnomalyDetector,
    BOLADetector,
    RateAnomalyDetector,
)

__all__ = [
    # Version
    "__version__",
    # Core types
    "Action",
    "ActionType",
    "AnalysisResult",
    "APIEvent",
    "Detector",
    "RiskScore",
    # Engine
    "ActionEngine",
    "AnalysisEngine",
    "EngineConfig",
    "analyze_request",
    "create_engine",
    # Detectors
    "AuthAnomalyDetector",
    "BehavioralAnomalyDetector",
    "BOLADetector",
    "RateAnomalyDetector",
]
