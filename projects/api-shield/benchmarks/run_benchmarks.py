#!/usr/bin/env python3
"""
API Shield Performance Benchmarks

Run comprehensive benchmarks for the detection engine.
"""

import argparse
import asyncio
import gc
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional

# Add parent to path
sys.path.insert(0, str(__file__).replace("/benchmarks/run_benchmarks.py", "/src"))

from api_shield.core import APIEvent
from api_shield.engine import AnalysisEngine, EngineConfig, create_engine
from api_shield.detectors import (
    BOLADetector,
    AuthAnomalyDetector,
    RateAnomalyDetector,
    BehavioralAnomalyDetector,
)


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    iterations: int
    total_time_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    throughput: float  # requests/second
    memory_mb: float


class Benchmark:
    """Benchmark runner for API Shield."""

    def __init__(self, iterations: int = 10000, warmup: int = 1000):
        self.iterations = iterations
        self.warmup = warmup
        self.results: List[BenchmarkResult] = []

    async def run_async_benchmark(
        self,
        name: str,
        func: Callable,
        *args,
        **kwargs
    ) -> BenchmarkResult:
        """Run an async benchmark."""
        print(f"\n🔄 Running: {name}")
        print(f"   Iterations: {self.iterations}, Warmup: {self.warmup}")

        # Warmup
        print("   Warming up...", end="", flush=True)
        for _ in range(self.warmup):
            await func(*args, **kwargs)
        print(" done")

        # Collect garbage before measurement
        gc.collect()

        # Start memory tracking
        tracemalloc.start()

        # Run benchmark
        times: List[float] = []
        print(f"   Benchmarking... ", end="", flush=True)

        start_total = time.perf_counter()
        for i in range(self.iterations):
            start = time.perf_counter()
            await func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000  # Convert to ms
            times.append(elapsed)

            if i % (self.iterations // 10) == 0:
                print(".", end="", flush=True)

        total_time = (time.perf_counter() - start_total) * 1000
        print(" done")

        # Get memory usage
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        memory_mb = peak / 1024 / 1024

        # Calculate statistics
        times.sort()
        result = BenchmarkResult(
            name=name,
            iterations=self.iterations,
            total_time_ms=total_time,
            mean_ms=statistics.mean(times),
            median_ms=statistics.median(times),
            p95_ms=times[int(len(times) * 0.95)],
            p99_ms=times[int(len(times) * 0.99)],
            min_ms=min(times),
            max_ms=max(times),
            throughput=self.iterations / (total_time / 1000),
            memory_mb=memory_mb,
        )

        self.results.append(result)
        self._print_result(result)
        return result

    def _print_result(self, result: BenchmarkResult):
        """Print benchmark result."""
        print(f"\n   📊 Results for {result.name}:")
        print(f"      Mean:       {result.mean_ms:.3f} ms")
        print(f"      Median:     {result.median_ms:.3f} ms")
        print(f"      P95:        {result.p95_ms:.3f} ms")
        print(f"      P99:        {result.p99_ms:.3f} ms")
        print(f"      Min/Max:    {result.min_ms:.3f} / {result.max_ms:.3f} ms")
        print(f"      Throughput: {result.throughput:,.0f} req/s")
        print(f"      Memory:     {result.memory_mb:.1f} MB")

    def print_summary(self):
        """Print summary of all benchmarks."""
        print("\n" + "=" * 70)
        print("📈 BENCHMARK SUMMARY")
        print("=" * 70)

        print(f"\n{'Benchmark':<30} {'Mean':<10} {'P99':<10} {'Throughput':<15} {'Memory':<10}")
        print("-" * 70)

        for r in self.results:
            print(f"{r.name:<30} {r.mean_ms:>6.3f} ms  {r.p99_ms:>6.3f} ms  {r.throughput:>10,.0f}/s  {r.memory_mb:>6.1f} MB")

        print("-" * 70)


def create_test_event(seq: int = 0) -> APIEvent:
    """Create a test event for benchmarking."""
    return APIEvent(
        request_id=f"bench-{seq}",
        timestamp=datetime.utcnow(),
        method="GET",
        path=f"/api/users/{1000 + seq}",
        client_ip="192.168.1.100",
        user_id="bench_user",
        headers={
            "user-agent": "Mozilla/5.0 Benchmark",
            "authorization": "Bearer test-token",
        },
        response_code=200,
    )


async def benchmark_detector(detector, event: APIEvent):
    """Benchmark a single detector."""
    await detector.analyze(event)


async def benchmark_engine(engine: AnalysisEngine, event: APIEvent):
    """Benchmark the full analysis engine."""
    await engine.analyze(event)


async def run_detector_benchmarks(benchmark: Benchmark):
    """Run benchmarks for individual detectors."""
    print("\n" + "=" * 70)
    print("🔍 DETECTOR BENCHMARKS")
    print("=" * 70)

    event = create_test_event()

    # BOLA Detector
    bola = BOLADetector(min_sessions=10)
    await bola.initialize()
    bola.session_count = 100  # Skip learning
    await benchmark.run_async_benchmark(
        "BOLA Detector",
        benchmark_detector,
        bola,
        event,
    )

    # Auth Detector
    auth = AuthAnomalyDetector()
    await auth.initialize()
    await benchmark.run_async_benchmark(
        "Auth Detector",
        benchmark_detector,
        auth,
        event,
    )

    # Rate Detector
    rate = RateAnomalyDetector()
    await rate.initialize()
    await benchmark.run_async_benchmark(
        "Rate Detector",
        benchmark_detector,
        rate,
        event,
    )

    # Behavioral Detector
    behavioral = BehavioralAnomalyDetector(learning_period_requests=10)
    await behavioral.initialize()
    behavioral.global_request_count = 100  # Skip learning
    await benchmark.run_async_benchmark(
        "Behavioral Detector",
        benchmark_detector,
        behavioral,
        event,
    )


async def run_engine_benchmarks(benchmark: Benchmark):
    """Run benchmarks for the full engine."""
    print("\n" + "=" * 70)
    print("⚙️  ENGINE BENCHMARKS")
    print("=" * 70)

    event = create_test_event()

    # Sequential detection
    config_seq = EngineConfig(parallel_detection=False)
    engine_seq = AnalysisEngine(config_seq)
    await engine_seq.initialize()

    # Skip learning period for all detectors
    for detector in engine_seq.detectors:
        if hasattr(detector, 'session_count'):
            detector.session_count = 100000
        if hasattr(detector, 'global_request_count'):
            detector.global_request_count = 100000

    await benchmark.run_async_benchmark(
        "Engine (Sequential)",
        benchmark_engine,
        engine_seq,
        event,
    )
    await engine_seq.shutdown()

    # Parallel detection
    config_par = EngineConfig(parallel_detection=True)
    engine_par = AnalysisEngine(config_par)
    await engine_par.initialize()

    # Skip learning period
    for detector in engine_par.detectors:
        if hasattr(detector, 'session_count'):
            detector.session_count = 100000
        if hasattr(detector, 'global_request_count'):
            detector.global_request_count = 100000

    await benchmark.run_async_benchmark(
        "Engine (Parallel)",
        benchmark_engine,
        engine_par,
        event,
    )
    await engine_par.shutdown()


async def run_throughput_benchmark(benchmark: Benchmark):
    """Run throughput benchmark with varying load."""
    print("\n" + "=" * 70)
    print("📈 THROUGHPUT BENCHMARKS")
    print("=" * 70)

    engine = await create_engine()

    # Skip learning period
    for detector in engine.detectors:
        if hasattr(detector, 'session_count'):
            detector.session_count = 100000
        if hasattr(detector, 'global_request_count'):
            detector.global_request_count = 100000

    # Test different batch sizes
    for batch_size in [100, 500, 1000]:
        events = [create_test_event(i) for i in range(batch_size)]

        async def process_batch():
            await asyncio.gather(*[engine.analyze(e) for e in events])

        await benchmark.run_async_benchmark(
            f"Batch Processing ({batch_size} req)",
            process_batch,
        )

    await engine.shutdown()


async def main():
    """Run all benchmarks."""
    parser = argparse.ArgumentParser(description="API Shield Benchmarks")
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--warmup", type=int, default=1000)
    parser.add_argument("--only", choices=["detector", "engine", "throughput"])
    args = parser.parse_args()

    benchmark = Benchmark(iterations=args.iterations, warmup=args.warmup)

    print("\n" + "=" * 70)
    print("🚀 API SHIELD PERFORMANCE BENCHMARKS")
    print("=" * 70)
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Iterations: {args.iterations}")
    print(f"Warmup: {args.warmup}")

    if args.only is None or args.only == "detector":
        await run_detector_benchmarks(benchmark)

    if args.only is None or args.only == "engine":
        await run_engine_benchmarks(benchmark)

    if args.only is None or args.only == "throughput":
        await run_throughput_benchmark(benchmark)

    benchmark.print_summary()

    # Check if we meet targets
    print("\n" + "=" * 70)
    print("✅ TARGET VALIDATION")
    print("=" * 70)

    passed = True
    for result in benchmark.results:
        if "Engine" in result.name and "Parallel" in result.name:
            if result.p99_ms > 5.0:
                print(f"❌ {result.name}: P99 {result.p99_ms:.2f}ms > 5ms target")
                passed = False
            else:
                print(f"✅ {result.name}: P99 {result.p99_ms:.2f}ms < 5ms target")

            if result.throughput < 10000:
                print(f"❌ {result.name}: {result.throughput:.0f}/s < 10,000/s target")
                passed = False
            else:
                print(f"✅ {result.name}: {result.throughput:.0f}/s > 10,000/s target")

    return 0 if passed else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
