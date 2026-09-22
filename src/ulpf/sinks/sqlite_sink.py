"""
ULPF SQLite Relational & Forensic Search Sink.
Provides indexed forensic lookup, fast queryability, and audit trail storage.
"""

from __future__ import annotations
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from ulpf.core.models import UniversalEvent
from ulpf.sinks.base import BaseSink


class SqliteForensicSink(BaseSink):
    """
    Persists events to SQLite with indexing on forensic keys:
    event_id, raw_hash, src_ip, dst_ip, action, vendor.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    raw_hash TEXT NOT NULL,
                    raw_event TEXT NOT NULL,
                    ingestion_timestamp TEXT,
                    event_timestamp TEXT,
                    parser_id TEXT,
                    vendor TEXT,
                    product TEXT,
                    src_ip TEXT,
                    src_port INTEGER,
                    src_country TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    dst_country TEXT,
                    protocol TEXT,
                    direction TEXT,
                    bytes_in INTEGER,
                    bytes_out INTEGER,
                    total_bytes INTEGER,
                    action TEXT,
                    severity TEXT,
                    app_name TEXT,
                    threat_signature TEXT,
                    normalized_json TEXT NOT NULL
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_hash ON security_events(raw_hash)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON security_events(src_ip)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON security_events(dst_ip)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor ON security_events(vendor)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON security_events(action)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON security_events(severity)")

    def write(self, event: UniversalEvent) -> None:
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO security_events VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                event.lineage.event_id,
                event.lineage.raw_hash,
                event.raw_event,
                event.lineage.ingestion_timestamp,
                event.lineage.event_timestamp or "",
                event.lineage.parser_id,
                event.product.vendor_name,
                event.product.product_name,
                event.src_endpoint.ip,
                event.src_endpoint.port,
                event.src_endpoint.country,
                event.dst_endpoint.ip,
                event.dst_endpoint.port,
                event.dst_endpoint.country,
                event.connection_info.protocol_name,
                event.connection_info.direction.value,
                event.traffic.bytes_in,
                event.traffic.bytes_out,
                event.traffic.total_bytes,
                event.disposition.value,
                event.severity.value,
                event.app_name,
                event.threat.signature_name if event.threat else None,
                event.model_dump_json()
            ))

    def write_batch(self, events: List[UniversalEvent]) -> None:
        records = [
            (
                ev.lineage.event_id,
                ev.lineage.raw_hash,
                ev.raw_event,
                ev.lineage.ingestion_timestamp,
                ev.lineage.event_timestamp or "",
                ev.lineage.parser_id,
                ev.product.vendor_name,
                ev.product.product_name,
                ev.src_endpoint.ip,
                ev.src_endpoint.port,
                ev.src_endpoint.country,
                ev.dst_endpoint.ip,
                ev.dst_endpoint.port,
                ev.dst_endpoint.country,
                ev.connection_info.protocol_name,
                ev.connection_info.direction.value,
                ev.traffic.bytes_in,
                ev.traffic.bytes_out,
                ev.traffic.total_bytes,
                ev.disposition.value,
                ev.severity.value,
                ev.app_name,
                ev.threat.signature_name if ev.threat else None,
                ev.model_dump_json()
            )
            for ev in events
        ]
        with self.conn:
            self.conn.executemany("""
                INSERT OR REPLACE INTO security_events VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, records)

    def query(self, where_clause: str = "1=1", params: Tuple = (), limit: int = 50) -> List[Dict[str, Any]]:
        """Queries stored events."""
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT * FROM security_events WHERE {where_clause} ORDER BY ingestion_timestamp DESC LIMIT {limit}", params)
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        if self.conn:
            self.conn.close()
