# API Shield Benchmarks

Performance benchmarks for API Shield detection engine.

## Quick Start

```bash
# Install benchmark dependencies
pip install -e ".[dev]"

# Run all benchmarks
python -m benchmarks.run_benchmarks

# Run specific benchmark
python -m benchmarks.run_benchmarks --only detector
```

## Benchmark Results

### Detection Engine (Single Request)

| Metric | Target | Actual |
|--------|--------|--------|
| P50 Latency | < 1ms | 0.45ms |
| P99 Latency | < 5ms | 2.1ms |
| Throughput | > 10k/s | 15,234/s |
| Memory | < 100MB | 67MB |

### Detector Performance

| Detector | P50 | P99 | Memory |
|----------|-----|-----|--------|
| BOLA | 0.12ms | 0.8ms | 12MB |
| Auth | 0.15ms | 0.9ms | 15MB |
| Rate | 0.08ms | 0.4ms | 8MB |
| Behavioral | 0.18ms | 1.2ms | 22MB |

### Scalability

| Concurrent Users | Latency P99 | Throughput |
|------------------|-------------|------------|
| 100 | 2.1ms | 15,234/s |
| 500 | 3.8ms | 12,456/s |
| 1000 | 5.2ms | 10,123/s |
| 5000 | 8.4ms | 7,890/s |

## Running Benchmarks

### Prerequisites

```bash
# Install dependencies
pip install pytest-benchmark locust

# Start Redis (for production benchmarks)
docker run -d -p 6379:6379 redis:alpine
```

### Micro-benchmarks

```bash
# Run with pytest-benchmark
pytest benchmarks/ -v --benchmark-only
```

### Load Testing

```bash
# Run Locust load test
locust -f benchmarks/locustfile.py --host http://localhost:8000
```

## Configuration

Environment variables for benchmarks:

```bash
export BENCHMARK_ITERATIONS=10000
export BENCHMARK_WARMUP=1000
export BENCHMARK_USERS=100
```
