# API Shield

> Real-time API security with ML-powered threat detection

## Overview

API Shield is an open-source API security platform that provides:

- **BOLA/IDOR Detection**: ML-based detection of broken object-level authorization
- **Behavioral Analysis**: Baseline normal behavior and detect anomalies
- **Adaptive Rate Limiting**: Dynamic rate limits based on risk scores
- **Real-time Protection**: Sub-millisecond inline blocking
- **Multi-Gateway Support**: Kong, APISIX, Envoy, Nginx

## Quick Start

```bash
# Install
pip install api-shield

# Analyze a single request
api-shield analyze GET /api/users/123 --ip 192.168.1.1 --user user_456

# Run simulation to test detection
api-shield simulate --requests 100 --attack bola --user test_user

# Start the API server
api-shield server --host 0.0.0.0 --port 8000

# Generate sample configuration
api-shield config --generate --output shield.json
```

### Python Library

```python
import asyncio
from api_shield import create_engine, analyze_request

async def main():
    # Create and initialize engine
    engine = await create_engine()

    # Analyze a request
    result = await analyze_request(
        engine,
        method="GET",
        path="/api/users/123",
        client_ip="192.168.1.1",
        user_id="user_456"
    )

    print(f"Risk Score: {result.risk_score:.2f}")
    print(f"Action: {result.action.type.value}")
    print(f"Signals: {result.signals}")

    await engine.shutdown()

asyncio.run(main())
```

## Architecture

```
                    ┌─────────────────┐
                    │   API Gateway   │
                    │  (Kong/Envoy)   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   API Shield    │
                    │     Proxy       │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼────┐  ┌──────▼──────┐  ┌───▼────┐
     │   Analysis  │  │    Rate     │  │ Action │
     │   Engine    │  │   Limiter   │  │ Engine │
     └─────────────┘  └─────────────┘  └────────┘
              │              │              │
     ┌────────▼──────────────▼──────────────▼───┐
     │              Data Layer                   │
     │   Redis │ ClickHouse │ PostgreSQL        │
     └──────────────────────────────────────────┘
```

## Detection Capabilities

### OWASP API Top 10 Coverage

| Vulnerability | Detection Method | Status |
|--------------|------------------|--------|
| API1 - BOLA | Sequential pattern + behavioral analysis | Stable |
| API2 - Broken Auth | Failed login tracking + impossible travel | Stable |
| API3 - Property Auth | Schema validation + mass assignment detection | Stable |
| API4 - Resource Consumption | Adaptive rate limiting | Stable |
| API5 - Function Auth | Role-based endpoint analysis | Beta |
| API6 - Business Flow | Sequence mining | Beta |
| API7 - SSRF | URL validation + DNS resolution | Stable |
| API8 - Misconfiguration | OpenAPI compliance checking | Stable |
| API9 - Inventory | API discovery + shadow detection | Beta |
| API10 - Unsafe Consumption | Response validation | Planned |

### Detection Algorithms

```python
import asyncio
from datetime import datetime
from api_shield import APIEvent, BOLADetector, AuthAnomalyDetector

async def detect_threats():
    # Initialize detectors
    bola_detector = BOLADetector(
        min_sessions=10000,
        unique_threshold=100,
        sequential_score=0.8
    )

    auth_detector = AuthAnomalyDetector(
        failed_threshold=5,
        lockout_window_minutes=15,
        impossible_travel_kmh=1000
    )

    await bola_detector.initialize()
    await auth_detector.initialize()

    # Create an API event
    event = APIEvent(
        request_id="req-123",
        timestamp=datetime.utcnow(),
        method="GET",
        path="/api/users/456",
        client_ip="192.168.1.1",
        user_id="user123",
        headers={"authorization": "Bearer token..."},
        response_code=200
    )

    # Analyze for BOLA
    bola_result = await bola_detector.analyze(event)
    print(f"BOLA Risk Score: {bola_result.score:.2f}")
    print(f"BOLA Signals: {bola_result.signals}")

    # Analyze for auth anomalies
    auth_result = await auth_detector.analyze(event)
    print(f"Auth Risk Score: {auth_result.score:.2f}")
    print(f"Auth Signals: {auth_result.signals}")

asyncio.run(detect_threats())
```

## Configuration

```yaml
# shield.yaml
version: "1.0"
mode: inline

detection:
  bola:
    enabled: true
    min_sessions: 10000
    sequential_pattern_score: 0.8

  authentication:
    enabled: true
    failed_login_threshold: 5
    impossible_travel: true

  rate_limiting:
    enabled: true
    algorithm: sliding_window
    default_limit: 100
    adaptive: true

  behavioral:
    enabled: true
    baseline_days: 14
    anomaly_threshold: 0.7

actions:
  block:
    threshold: 0.85
    response_code: 403

  challenge:
    threshold: 0.70
    type: captcha

  rate_limit:
    threshold: 0.50

integrations:
  redis:
    url: redis://localhost:6379
```

## Deployment

### Docker

```bash
docker run -d \
  -p 8080:8080 \
  -p 9090:9090 \
  -e UPSTREAM_URL=http://your-api:8000 \
  -e REDIS_URL=redis://redis:6379 \
  api-shield:latest
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-shield
spec:
  template:
    spec:
      containers:
        - name: api-shield
          image: api-shield:latest
          ports:
            - containerPort: 8080
          env:
            - name: MODE
              value: "inline"
            - name: UPSTREAM_URL
              value: "http://api-service:8000"
```

### Kong Plugin

```bash
# Install Kong plugin
kong config db_import /path/to/api-shield-kong.yaml

# Enable on service
curl -X POST http://kong:8001/services/my-api/plugins \
  --data "name=api-shield" \
  --data "config.shield_url=http://api-shield:8080"
```

## Metrics

API Shield exposes Prometheus metrics at `/metrics`:

```
# Request metrics
api_shield_requests_total{action="allow|block|rate_limit"}
api_shield_request_latency_seconds{quantile="0.5|0.9|0.99"}

# Detection metrics
api_shield_detections_total{type="bola|auth|rate|behavioral"}
api_shield_risk_score{quantile="0.5|0.9|0.99"}

# Rate limiting
api_shield_rate_limited_total{reason="global|user|endpoint"}
```

## Dashboard

API Shield includes a Grafana dashboard:

```bash
# Import dashboard
curl -X POST http://grafana:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d @dashboards/api-shield.json
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0
