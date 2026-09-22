"""
ULPF Sinks Package.
"""

from ulpf.sinks.base import BaseSink
from ulpf.sinks.jsonl_sink import JsonlSink
from ulpf.sinks.parquet_sink import ParquetDataLakeSink
from ulpf.sinks.sqlite_sink import SqliteForensicSink
from ulpf.sinks.siem_sink import SiemForwarderSink

__all__ = [
    "BaseSink",
    "JsonlSink",
    "ParquetDataLakeSink",
    "SqliteForensicSink",
    "SiemForwarderSink",
]
