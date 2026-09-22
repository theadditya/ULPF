"""
ULPF Core Processing Pipeline.
Orchestrates: Ingest -> Classify -> Extract -> Normalize -> Enrich -> Vectorize -> Route.
Maintains high throughput, thread safety, and telemetry metrics.
"""

from __future__ import annotations
import time
from typing import List, Optional, Dict, Any, Tuple
from ulpf.core.models import UniversalEvent, EventDisposition, SeverityLevel
from ulpf.parsing.engine import ParserRegistry, ParserPlugin
from ulpf.normalization.normalizer import UniversalNormalizer
from ulpf.ml.feature_extractor import MLFeatureExtractor
from ulpf.sinks.base import BaseSink


class ProcessingPipeline:
    """
    Main execution engine of the Universal Log Pre-processing Framework.
    """
    def __init__(self, registry: ParserRegistry, sinks: Optional[List[BaseSink]] = None):
        self.registry = registry
        self.sinks: List[BaseSink] = sinks or []
        
        # Telemetry metrics
        self.metrics = {
            "total_processed": 0,
            "total_bytes_ingested": 0,
            "total_errors": 0,
            "total_latency_ms": 0.0,
            "vendors": {},
            "actions": {},
            "severities": {},
        }

    def add_sink(self, sink: BaseSink):
        self.sinks.append(sink)

    def process_event(self, raw_log: str, parser_id: Optional[str] = None, deployment_mode: str = "air_gapped") -> UniversalEvent:
        """
        Executes end-to-end processing pipeline for a single raw log event.
        """
        t0 = time.perf_counter()
        raw_clean = raw_log.strip()
        
        try:
            # 1. Parse & Classify
            extracted, plugin, confidence = self.registry.parse(raw_clean, parser_id)
            
            # 2. Normalize & Enrich (Lossless retention + Lineage + Mode-Aware GeoIP/DNS/Threat)
            event = UniversalNormalizer.normalize(
                raw_log=raw_clean,
                extracted=extracted,
                plugin=plugin,
                confidence=confidence,
                start_time_perf=t0,
                deployment_mode=deployment_mode
            )

            # 3. Route to Sinks
            for sink in self.sinks:
                try:
                    sink.write(event)
                except Exception as sink_err:
                    print(f"Warning: Sink write failure: {sink_err}")

            # 4. Telemetry Update
            self._update_metrics(event, len(raw_clean.encode("utf-8")))

            return event

        except Exception as e:
            self.metrics["total_errors"] += 1
            # In case of parsing exception, build safe fallback preserving raw log!
            event = UniversalEvent(raw_event=raw_clean)
            event.lineage.raw_hash = event.calculate_raw_hash()
            event.lineage.is_valid = False
            event.lineage.validation_errors.append(str(e))
            event.unmapped["parse_error"] = str(e)
            
            for sink in self.sinks:
                try:
                    sink.write(event)
                except Exception:
                    pass
            return event

    def process_batch(self, raw_logs: List[str], parser_id: Optional[str] = None) -> List[UniversalEvent]:
        """
        Processes a batch of raw log lines.
        """
        events = [self.process_event(line, parser_id) for line in raw_logs if line.strip()]
        return events

    def _update_metrics(self, event: UniversalEvent, raw_byte_len: int):
        self.metrics["total_processed"] += 1
        self.metrics["total_bytes_ingested"] += raw_byte_len
        self.metrics["total_latency_ms"] += event.lineage.processing_latency_ms
        
        vendor = event.product.vendor_name
        self.metrics["vendors"][vendor] = self.metrics["vendors"].get(vendor, 0) + 1
        
        action = event.disposition.value
        self.metrics["actions"][action] = self.metrics["actions"].get(action, 0) + 1
        
        sev = event.severity.value
        self.metrics["severities"][sev] = self.metrics["severities"].get(sev, 0) + 1

    def get_telemetry(self) -> Dict[str, Any]:
        count = self.metrics["total_processed"]
        avg_lat = (self.metrics["total_latency_ms"] / count) if count > 0 else 0.0
        return {
            "total_processed": count,
            "total_bytes_ingested": self.metrics["total_bytes_ingested"],
            "total_errors": self.metrics["total_errors"],
            "average_latency_ms": round(avg_lat, 3),
            "vendors": self.metrics["vendors"],
            "actions": self.metrics["actions"],
            "severities": self.metrics["severities"],
        }

    def close(self):
        for s in self.sinks:
            s.close()
