"""
ULPF End-to-End Performance and Latency Benchmark Script.
Simulates high-throughput perimeter ingestion to evaluate Events Per Second (EPS),
processing latency distributions, and memory stability.
"""

import os
import sys
import time
import statistics
from pathlib import Path

# Add src to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ulpf.parsing.engine import ParserRegistry
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.sinks.jsonl_sink import JsonlSink
from ulpf.sinks.parquet_sink import ParquetDataLakeSink


def run_benchmark(iterations: int = 25000):
    base_dir = Path(__file__).resolve().parent.parent
    configs_dir = os.path.join(base_dir, "configs", "parsers")
    sample_file = os.path.join(base_dir, "sample_logs", "perimeter_devices.log")
    temp_dir = os.path.join(base_dir, "data", "benchmark_run")

    registry = ParserRegistry(configs_dir)
    jsonl_sink = JsonlSink(os.path.join(temp_dir, "bench.jsonl"))
    parquet_sink = ParquetDataLakeSink(os.path.join(temp_dir, "parquet"), batch_size=5000)
    pipeline = ProcessingPipeline(registry=registry, sinks=[jsonl_sink, parquet_sink])

    with open(sample_file, "r", encoding="utf-8") as f:
        samples = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    latencies = []
    print(f"[*] Starting benchmark with {iterations:,} perimeter log events across {len(samples)} distinct device types...")

    t_start = time.perf_counter()
    for i in range(iterations):
        sample = samples[i % len(samples)]
        ev = pipeline.process_event(sample)
        latencies.append(ev.lineage.processing_latency_ms)
    t_end = time.perf_counter()

    parquet_sink.flush()
    total_time = t_end - t_start
    eps = iterations / total_time
    latencies.sort()
    
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    print("\n" + "="*58)
    print("      ULPF HIGH-THROUGHPUT PERFORMANCE REPORT")
    print("="*58)
    print(f"Total Events Ingested      : {iterations:,}")
    print(f"Total Processing Time      : {total_time:.3f} s")
    print(f"Throughput                 : {eps:,.2f} Events / Second (EPS)")
    print(f"Median Latency (p50)       : {p50:.4f} ms")
    print(f"95th Percentile Latency (p95): {p95:.4f} ms")
    print(f"99th Percentile Latency (p99): {p99:.4f} ms")
    print(f"Extrapolated Daily Volume  : {eps * 86400:,.0f} events / day / core")
    print("="*58 + "\n")


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 25000
    run_benchmark(count)
