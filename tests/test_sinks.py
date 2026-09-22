"""
Tests for Requirement (g): SIEM & Data Lake Sinks (Parquet, JSON-L, SQLite).
"""

import os
import json
import tempfile
import pytest
from ulpf.core.models import UniversalEvent, EventDisposition
from ulpf.sinks.jsonl_sink import JsonlSink
from ulpf.sinks.parquet_sink import ParquetDataLakeSink
from ulpf.sinks.sqlite_sink import SqliteForensicSink


@pytest.fixture
def sample_event():
    ev = UniversalEvent(raw_event="dummy raw perimeter log")
    ev.lineage.raw_hash = ev.calculate_raw_hash()
    ev.src_endpoint.ip = "192.168.1.100"
    ev.src_endpoint.port = 45123
    ev.dst_endpoint.ip = "8.8.8.8"
    ev.dst_endpoint.port = 53
    ev.disposition = EventDisposition.ALLOWED
    return ev


def test_jsonl_sink(sample_event):
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "output.jsonl")
        sink = JsonlSink(out_file)
        sink.write(sample_event)
        sink.close()

        with open(out_file, "r") as f:
            lines = f.readlines()
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["raw_event"] == "dummy raw perimeter log"
            assert data["src_endpoint"]["ip"] == "192.168.1.100"


def test_parquet_sink(sample_event):
    with tempfile.TemporaryDirectory() as tmpdir:
        sink = ParquetDataLakeSink(tmpdir, batch_size=2)
        sink.write(sample_event)
        sink.write(sample_event)
        sink.flush()
        sink.close()

        files = os.listdir(tmpdir)
        assert len(files) >= 1
        assert any(f.endswith(".parquet") for f in files)


def test_sqlite_forensic_sink(sample_event):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "forensics.db")
        sink = SqliteForensicSink(db_path)
        sink.write(sample_event)

        results = sink.query("src_ip = ?", ("192.168.1.100",))
        assert len(results) == 1
        assert results[0]["raw_hash"] == sample_event.lineage.raw_hash
        assert results[0]["action"] == "Allowed"
        sink.close()
