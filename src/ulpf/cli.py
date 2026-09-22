"""
ULPF Command Line Interface (CLI).
Industrial-grade tooling for log normalization, benchmarking, server execution,
and parser testing.
"""

from __future__ import annotations
import os
import sys
import time
import json
import argparse
from pathlib import Path

from ulpf.parsing.engine import ParserRegistry
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.ml.feature_extractor import MLFeatureExtractor
from ulpf.sinks.jsonl_sink import JsonlSink
from ulpf.sinks.parquet_sink import ParquetDataLakeSink
from ulpf.sinks.sqlite_sink import SqliteForensicSink
from ulpf.ingestion.file_reader import FileIngestionReader


def get_default_paths():
    base = Path(__file__).resolve().parent.parent.parent
    configs = os.path.join(base, "configs", "parsers")
    data = os.path.join(base, "data")
    samples = os.path.join(base, "sample_logs", "perimeter_devices.log")
    return configs, data, samples


def cmd_parse(args):
    configs_dir, _, _ = get_default_paths()
    registry = ParserRegistry(configs_dir)
    pipeline = ProcessingPipeline(registry=registry)

    if args.log:
        raw_lines = [args.log]
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            raw_lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        print("Error: Specify --log '<text>' or --file <path>")
        sys.exit(1)

    for line in raw_lines:
        event = pipeline.process_event(line, parser_id=args.parser)
        if args.features:
            features = MLFeatureExtractor.extract_features(event)
            vector = MLFeatureExtractor.to_vector(event)
            print(json.dumps({"event": event.model_dump(), "features": features, "vector": vector}, indent=2))
        else:
            print(event.model_dump_json(indent=2))


def cmd_serve(args):
    import uvicorn
    print(f"[*] Starting ULPF Dashboard & REST API on http://{args.host}:{args.port}")
    uvicorn.run("ulpf.ui.app:app", host=args.host, port=args.port, reload=args.reload)


def cmd_benchmark(args):
    configs_dir, _, sample_file = get_default_paths()
    registry = ParserRegistry(configs_dir)
    pipeline = ProcessingPipeline(registry=registry)

    if not os.path.exists(sample_file):
        print(f"Sample file not found at {sample_file}")
        sys.exit(1)

    with open(sample_file, "r", encoding="utf-8") as f:
        samples = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    total_events = args.count
    print(f"[*] Benchmarking ULPF Pipeline across {total_events:,} perimeter device events...")

    t0 = time.perf_counter()
    for i in range(total_events):
        raw = samples[i % len(samples)]
        pipeline.process_event(raw)
    total_time = time.perf_counter() - t0

    eps = total_events / total_time
    telemetry = pipeline.get_telemetry()
    avg_lat = telemetry["average_latency_ms"]

    print("\n" + "="*50)
    print("           ULPF BENCHMARK RESULTS")
    print("="*50)
    print(f"Total Processed      : {total_events:,} events")
    print(f"Total Elapsed Time   : {total_time:.3f} seconds")
    print(f"Throughput           : {eps:,.2f} Events / Second (EPS)")
    print(f"Avg Parsing Latency  : {avg_lat:.4f} ms per event")
    print(f"Total Errors         : {telemetry['total_errors']}")
    print(f"Daily Extrapolation  : {eps * 86400:,.0f} events / day / core")
    print("="*50 + "\n")


def cmd_test_parsers(args):
    configs_dir, _, sample_file = get_default_paths()
    registry = ParserRegistry(configs_dir)
    pipeline = ProcessingPipeline(registry=registry)

    print(f"[*] Testing {len(registry.parsers)} active declarative parsers against sample perimeter logs...\n")
    with open(sample_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    success = 0
    for idx, line in enumerate(lines, 1):
        event = pipeline.process_event(line)
        verified = event.verify_integrity()
        status = "PASS" if verified and event.lineage.is_valid else "FAIL"
        if status == "PASS":
            success += 1
        print(f"[{status}] Event #{idx:02d} | Vendor: {event.product.vendor_name:18s} | Action: {event.disposition.value:8s} | Hash: {event.lineage.raw_hash[:10]}... | Latency: {event.lineage.processing_latency_ms:.3f}ms")

    print(f"\nResult: {success}/{len(lines)} tests passed ({success/len(lines)*100:.1f}%)")


def cmd_test(args):
    import pytest
    base_dir = Path(__file__).resolve().parent.parent.parent
    tests_dir = os.path.join(base_dir, "tests")
    print(f"[*] Running automated test suite in {tests_dir}...\n")
    ret = pytest.main(["-v", tests_dir])
    sys.exit(ret)


def main():
    parser = argparse.ArgumentParser(description="Universal Log Pre-processing Framework (ULPF) CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # test
    subparsers.add_parser("test", help="Run automated unit & integration tests")

    # parse
    p_parse = subparsers.add_parser("parse", help="Parse and normalize logs")
    p_parse.add_argument("--log", "-l", type=str, help="Single raw log line")
    p_parse.add_argument("--file", "-f", type=str, help="Path to raw log file")
    p_parse.add_argument("--parser", "-p", type=str, help="Force specific parser ID")
    p_parse.add_argument("--features", action="store_true", help="Include AI/ML feature vectors")

    # serve
    p_serve = subparsers.add_parser("serve", help="Run FastAPI web UI and REST service")
    p_serve.add_argument("--host", default="0.0.0.0", help="Binding host")
    p_serve.add_argument("--port", type=int, default=8000, help="Port to listen on")
    p_serve.add_argument("--reload", action="store_true", help="Enable reload")

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run performance benchmark")
    p_bench.add_argument("--count", "-c", type=int, default=5000, help="Number of events to benchmark")

    # test-parsers
    subparsers.add_parser("test-parsers", help="Validate loaded parsers against perimeter dataset")

    args = parser.parse_args()
    if args.command == "test":
        cmd_test(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "serve":
        cmd_serve(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "test-parsers":
        cmd_test_parsers(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
