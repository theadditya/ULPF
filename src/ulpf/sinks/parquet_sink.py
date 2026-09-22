"""
ULPF Columnar Apache Parquet Sink for Big Data Lakes.
Generates highly-compressed, partitionable Parquet datasets compatible with
AWS Athena, Snowflake, Databricks, and Apache Spark.
"""

from __future__ import annotations
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from ulpf.core.models import UniversalEvent
from ulpf.sinks.base import BaseSink

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False


class ParquetDataLakeSink(BaseSink):
    """
    Batches UniversalEvents and flushes them to compressed Apache Parquet files.
    """
    def __init__(self, output_dir: str, batch_size: int = 1000):
        self.output_dir = output_dir
        self.batch_size = batch_size
        self._buffer: List[Dict[str, Any]] = []
        self._file_counter = 0
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def _event_to_flat_dict(self, event: UniversalEvent) -> Dict[str, Any]:
        """Flattens UniversalEvent for tabular columnar storage."""
        return {
            "event_id": event.lineage.event_id,
            "raw_hash": event.lineage.raw_hash,
            "raw_event": event.raw_event,
            "ingestion_timestamp": event.lineage.ingestion_timestamp,
            "event_timestamp": event.lineage.event_timestamp or "",
            "parser_id": event.lineage.parser_id,
            "vendor_name": event.product.vendor_name,
            "product_name": event.product.product_name,
            "src_ip": event.src_endpoint.ip or "",
            "src_port": event.src_endpoint.port or 0,
            "src_zone": event.src_endpoint.zone or "",
            "src_country": event.src_endpoint.country or "",
            "src_asn": event.src_endpoint.asn or "",
            "src_is_internal": bool(event.src_endpoint.is_internal),
            "dst_ip": event.dst_endpoint.ip or "",
            "dst_port": event.dst_endpoint.port or 0,
            "dst_zone": event.dst_endpoint.zone or "",
            "dst_country": event.dst_endpoint.country or "",
            "dst_asn": event.dst_endpoint.asn or "",
            "dst_is_internal": bool(event.dst_endpoint.is_internal),
            "direction": event.connection_info.direction.value,
            "protocol": event.connection_info.protocol_name or "unknown",
            "bytes_in": event.traffic.bytes_in or 0,
            "bytes_out": event.traffic.bytes_out or 0,
            "total_bytes": event.traffic.total_bytes or 0,
            "packets_in": event.traffic.packets_in or 0,
            "packets_out": event.traffic.packets_out or 0,
            "duration_ms": event.traffic.duration_ms or 0,
            "action": event.disposition.value,
            "severity": event.severity.value,
            "app_name": event.app_name or "",
            "threat_signature": event.threat.signature_name if event.threat else "",
            "unmapped_json": json.dumps(event.unmapped),
        }

    def write(self, event: UniversalEvent) -> None:
        self._buffer.append(self._event_to_flat_dict(event))
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def write_batch(self, events: List[UniversalEvent]) -> None:
        for ev in events:
            self._buffer.append(self._event_to_flat_dict(ev))
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> Optional[str]:
        """Flushes buffered records to a parquet file."""
        if not self._buffer:
            return None
        
        self._file_counter += 1
        file_name = f"ulpf_events_batch_{self._file_counter:04d}.parquet"
        file_path = os.path.join(self.output_dir, file_name)

        if HAS_PYARROW:
            table = pa.Table.from_pylist(self._buffer)
            pq.write_table(table, file_path, compression="snappy")
        else:
            # Fallback JSON-Lines with parquet extension note if pyarrow missing
            with open(file_path + ".json", "w", encoding="utf-8") as f:
                for row in self._buffer:
                    f.write(json.dumps(row) + "\n")
            file_path = file_path + ".json"

        self._buffer.clear()
        return file_path

    def close(self) -> None:
        self.flush()
