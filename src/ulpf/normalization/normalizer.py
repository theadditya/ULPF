"""
ULPF Schema Normalizer.
Transforms heterogeneous extracted dictionary data into standardized OCSF v1.2 UniversalEvent.
Ensures zero data loss, strict typing, and full cryptographic provenance.
"""

from __future__ import annotations
import time
from typing import Dict, Any, Optional, Set
from ulpf.core.models import (
    UniversalEvent,
    LineageInfo,
    ProductInfo,
    EndpointInfo,
    ConnectionInfo,
    TrafficMetrics,
    ThreatInfo,
    EventDisposition,
    SeverityLevel,
)
from ulpf.normalization.taxonomy import (
    normalize_action,
    normalize_severity,
    normalize_protocol,
)
from ulpf.enrichment.network import enrich_endpoints
from ulpf.enrichment.threat import lookup_threat
from ulpf.parsing.engine import ParserPlugin


def safe_int(val: Any, default: Optional[int] = None) -> Optional[int]:
    """Safely converts value to int."""
    if val is None or val == "":
        return default
    try:
        # Handle string floats like "120.0"
        return int(float(str(val).strip()))
    except (ValueError, TypeError):
        return default


def safe_float(val: Any, default: Optional[float] = None) -> Optional[float]:
    """Safely converts value to float."""
    if val is None or val == "":
        return default
    try:
        return float(str(val).strip())
    except (ValueError, TypeError):
        return default


class UniversalNormalizer:
    """
    Normalizes extracted raw field dictionaries to UniversalEvent.
    """

    @classmethod
    def normalize(
        cls,
        raw_log: str,
        extracted: Dict[str, Any],
        plugin: ParserPlugin,
        confidence: float = 1.0,
        start_time_perf: Optional[float] = None,
    ) -> UniversalEvent:
        """
        Main normalization routine.
        """
        # 1. Initialize Event
        event = UniversalEvent(raw_event=raw_log)
        
        # 2. Cryptographic Lineage & Provenance
        event.lineage.raw_hash = event.calculate_raw_hash()
        event.lineage.parser_id = plugin.id
        event.lineage.parser_version = plugin.version
        
        # 3. Product & Source
        event.product.vendor_name = plugin.vendor
        event.product.product_name = plugin.product
        
        # Track mapped keys so unmapped can be isolated
        mapped_keys: Set[str] = set()

        # Helper to extract value from source keys (supports single string or list of fallback keys)
        def get_source_val(source_spec: Any) -> Tuple[Any, Optional[str]]:
            if isinstance(source_spec, str):
                if source_spec in extracted:
                    return extracted[source_spec], source_spec
            elif isinstance(source_spec, list):
                for candidate in source_spec:
                    if candidate in extracted and extracted[candidate] is not None:
                        return extracted[candidate], candidate
            return None, None

        # 4. Map Attributes via Declarative Mapping
        mapping = plugin.mapping
        value_maps = plugin.value_maps

        # Source Endpoint
        src_ip, s_key = get_source_val(mapping.get("src_endpoint.ip", ["src_ip", "srcip", "src", "source_ip", "suser"]))
        if s_key: mapped_keys.add(s_key)
        src_port, sp_key = get_source_val(mapping.get("src_endpoint.port", ["src_port", "srcport", "spt", "source_port"]))
        if sp_key: mapped_keys.add(sp_key)
        src_zone, sz_key = get_source_val(mapping.get("src_endpoint.zone", ["src_zone", "from_zone", "srcintf"]))
        if sz_key: mapped_keys.add(sz_key)

        event.src_endpoint.ip = str(src_ip).strip() if src_ip else None
        event.src_endpoint.port = safe_int(src_port)
        event.src_endpoint.zone = str(src_zone).strip() if src_zone else None

        # Destination Endpoint
        dst_ip, d_key = get_source_val(mapping.get("dst_endpoint.ip", ["dst_ip", "dstip", "dst", "destination_ip"]))
        if d_key: mapped_keys.add(d_key)
        dst_port, dp_key = get_source_val(mapping.get("dst_endpoint.port", ["dst_port", "dstport", "dpt", "destination_port"]))
        if dp_key: mapped_keys.add(dp_key)
        dst_zone, dz_key = get_source_val(mapping.get("dst_endpoint.zone", ["dst_zone", "to_zone", "dstintf"]))
        if dz_key: mapped_keys.add(dz_key)

        event.dst_endpoint.ip = str(dst_ip).strip() if dst_ip else None
        event.dst_endpoint.port = safe_int(dst_port)
        event.dst_endpoint.zone = str(dst_zone).strip() if dst_zone else None

        # Connection Info & Protocol
        proto_raw, pr_key = get_source_val(mapping.get("connection_info.protocol", ["proto", "protocol", "proto_name"]))
        if pr_key: mapped_keys.add(pr_key)
        if not proto_raw and (event.dst_endpoint.port == 22 or event.src_endpoint.port == 22):
            proto_raw = "tcp"
        p_name, p_num = normalize_protocol(proto_raw)
        event.connection_info.protocol_name = p_name
        event.connection_info.protocol_num = p_num

        session_id, sess_key = get_source_val(mapping.get("connection_info.session_id", ["sessionid", "session_id", "conn_id"]))
        if sess_key: mapped_keys.add(sess_key)
        event.connection_info.session_id = str(session_id) if session_id else None

        # Traffic Metrics
        bytes_in, bi_key = get_source_val(mapping.get("traffic.bytes_in", ["bytes_in", "bytes_received", "rcvdbyte", "rcvdbytes"]))
        if bi_key: mapped_keys.add(bi_key)
        bytes_out, bo_key = get_source_val(mapping.get("traffic.bytes_out", ["bytes_out", "bytes_sent", "sentbyte", "sentbytes"]))
        if bo_key: mapped_keys.add(bo_key)
        bytes_tot, bt_key = get_source_val(mapping.get("traffic.total_bytes", ["bytes", "total_bytes", "byte_count"]))
        if bt_key: mapped_keys.add(bt_key)

        pkts_in, pi_key = get_source_val(mapping.get("traffic.packets_in", ["packets_in", "pkts_received", "rcvdpkt"]))
        if pi_key: mapped_keys.add(pi_key)
        pkts_out, po_key = get_source_val(mapping.get("traffic.packets_out", ["packets_out", "pkts_sent", "sentpkt"]))
        if po_key: mapped_keys.add(po_key)

        dur_ms, dur_key = get_source_val(mapping.get("traffic.duration_ms", ["duration_ms", "elapsed", "duration"]))
        if dur_key: mapped_keys.add(dur_key)

        b_in = safe_int(bytes_in, 0)
        b_out = safe_int(bytes_out, 0)
        b_total = safe_int(bytes_tot, (b_in or 0) + (b_out or 0))

        event.traffic.bytes_in = b_in
        event.traffic.bytes_out = b_out
        event.traffic.total_bytes = b_total
        event.traffic.packets_in = safe_int(pkts_in, 0)
        event.traffic.packets_out = safe_int(pkts_out, 0)
        event.traffic.total_packets = (event.traffic.packets_in or 0) + (event.traffic.packets_out or 0)
        event.traffic.duration_ms = safe_int(dur_ms, 0)

        # Disposition / Action
        action_val, act_key = get_source_val(mapping.get("disposition.action", ["action", "act", "status", "disposition"]))
        if act_key: mapped_keys.add(act_key)
        if action_val:
            # Check plugin custom value map
            custom_map = value_maps.get("disposition.action", {})
            if str(action_val).lower() in custom_map:
                mapped_action = custom_map[str(action_val).lower()]
                try:
                    event.disposition = EventDisposition(mapped_action)
                except ValueError:
                    event.disposition = normalize_action(mapped_action)
            else:
                event.disposition = normalize_action(str(action_val))
        else:
            event.disposition = EventDisposition.UNKNOWN

        # Severity
        sev_val, sev_key = get_source_val(mapping.get("severity.level", ["severity", "level", "priority"]))
        if sev_key: mapped_keys.add(sev_key)
        event.vendor_severity = str(sev_val) if sev_val else None
        event.severity = normalize_severity(sev_val)

        # Application
        app_val, app_key = get_source_val(mapping.get("app_name", ["app", "application", "service", "proto_name"]))
        if app_key: mapped_keys.add(app_key)
        if not app_val and (event.dst_endpoint.port == 22 or event.src_endpoint.port == 22):
            app_val = "ssh"
        event.app_name = str(app_val).strip() if app_val else None

        # Threat Signatures
        sig_id, sig_key = get_source_val(mapping.get("threat.signature_id", ["signature_id", "threat_id", "rule_id"]))
        if sig_key: mapped_keys.add(sig_key)
        sig_name, sign_key = get_source_val(mapping.get("threat.signature_name", ["signature", "threat_name", "alert_signature"]))
        if sign_key: mapped_keys.add(sign_key)
        threat_cat, tcat_key = get_source_val(mapping.get("threat.category", ["category", "threat_category", "classification"]))
        if tcat_key: mapped_keys.add(tcat_key)

        if sig_id or sig_name:
            event.threat = ThreatInfo(
                signature_id=str(sig_id) if sig_id else None,
                signature_name=str(sig_name) if sig_name else None,
                category=str(threat_cat) if threat_cat else None,
            )

        # Timestamp
        ts_val, ts_key = get_source_val(mapping.get("timestamp", ["timestamp", "time", "date_time", "datetime", "generated_time"]))
        if ts_key: mapped_keys.add(ts_key)
        if ts_val:
            event.lineage.event_timestamp = str(ts_val)

        # 5. ZERO DATA LOSS: Catch all unmapped attributes
        for k, v in extracted.items():
            if k not in mapped_keys and not k.startswith("_syslog"):
                event.unmapped[k] = v

        # 6. Air-Gapped Enrichment
        # Classify RFC 1918 internal/external & direction & GeoIP/ASN
        direction = enrich_endpoints(event.src_endpoint, event.dst_endpoint)
        event.connection_info.direction = direction

        # Offline Threat Intelligence matching (if not already set by firewall)
        if not event.threat:
            threat_match = lookup_threat(event.src_endpoint.ip, event.dst_endpoint.ip)
            if threat_match:
                event.threat = threat_match
                # If high-confidence threat found, escalate disposition or severity
                if event.disposition == EventDisposition.UNKNOWN:
                    event.disposition = EventDisposition.ALERTED
                if event.severity in [SeverityLevel.INFORMATIONAL, SeverityLevel.LOW]:
                    event.severity = SeverityLevel.HIGH

        # 7. Processing Performance Latency Calculation
        if start_time_perf is not None:
            elapsed = (time.perf_counter() - start_time_perf) * 1000.0
            event.lineage.processing_latency_ms = round(elapsed, 3)

        return event
