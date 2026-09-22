"""
ULPF Multi-Schema Exporter.
Transforms standardized OCSF v1.2 events into:
1. Wazuh 4.x SIEM/XDR Alert Format
2. Elastic Common Schema (ECS) v8.x Format
3. OCSF v1.2 Standard Format
"""

from __future__ import annotations
from typing import Dict, Any
from ulpf.core.models import UniversalEvent, EventDisposition


class MultiSchemaExporter:
    """
    Exports UniversalEvent into multiple industry SIEM/XDR standards.
    """

    @staticmethod
    def to_wazuh_format(event: UniversalEvent, risk_score: int = 25) -> Dict[str, Any]:
        """
        Converts to Wazuh 4.x JSON Alert standard.
        """
        wazuh_level = min(max(int(risk_score / 6.5), 1), 15)
        sig_name = (event.threat.signature_name or "") if event.threat else ""
        return {
            "timestamp": event.lineage.event_timestamp or event.lineage.ingestion_timestamp,
            "rule": {
                "id": event.threat.signature_id if event.threat else "100201",
                "level": wazuh_level,
                "description": sig_name if sig_name else f"Perimeter firewall traffic: {event.disposition.value}",
                "groups": ["firewall", "network", "ulpf_normalized"],
                "mitre": {
                    "id": ["T1046" if "scan" in sig_name.lower() else "T1071"],
                    "tactic": ["Reconnaissance"]
                }
            },
            "agent": {
                "id": "000",
                "name": f"ulpf-{event.product.vendor_name.lower().replace(' ', '-')}",
                "ip": "127.0.0.1"
            },
            "manager": {"name": "ulpf-core-manager"},
            "id": event.lineage.event_id,
            "decoder": {
                "name": event.lineage.parser_id,
                "parent": "ulpf-universal-decoder"
            },
            "data": {
                "srcip": event.src_endpoint.ip,
                "srcport": str(event.src_endpoint.port or ""),
                "dstip": event.dst_endpoint.ip,
                "dstport": str(event.dst_endpoint.port or ""),
                "proto": event.connection_info.protocol_name,
                "action": event.disposition.value,
                "app": event.app_name,
                "bytes": str(event.traffic.total_bytes or 0),
                "vendor": event.product.vendor_name
            },
            "location": f"network-perimeter:{event.lineage.parser_id}",
            "sha256": event.lineage.raw_hash,
            "full_log": event.raw_event
        }

    @staticmethod
    def to_ecs_format(event: UniversalEvent) -> Dict[str, Any]:
        """
        Converts to Elastic Common Schema (ECS) v8.x standard.
        """
        return {
            "@timestamp": event.lineage.event_timestamp or event.lineage.ingestion_timestamp,
            "ecs": {"version": "8.11.0"},
            "event": {
                "id": event.lineage.event_id,
                "kind": "event",
                "category": ["network"],
                "type": ["connection", "access"],
                "outcome": "success" if event.disposition == EventDisposition.ALLOWED else "failure",
                "action": event.disposition.value.lower(),
                "duration": (event.traffic.duration_ms or 0) * 1_000_000,  # nanoseconds in ECS
                "original": event.raw_event,
                "hash": {"sha256": event.lineage.raw_hash}
            },
            "source": {
                "ip": event.src_endpoint.ip,
                "port": event.src_endpoint.port,
                "geo": {"country_iso_code": event.src_endpoint.country}
            },
            "destination": {
                "ip": event.dst_endpoint.ip,
                "port": event.dst_endpoint.port,
                "geo": {"country_iso_code": event.dst_endpoint.country}
            },
            "network": {
                "transport": (event.connection_info.protocol_name or "tcp").lower(),
                "direction": event.connection_info.direction.value.lower(),
                "bytes": event.traffic.total_bytes or 0
            },
            "observer": {
                "vendor": event.product.vendor_name,
                "product": event.product.product_name,
                "type": "firewall"
            },
            "labels": {
                "unmapped_count": len(event.unmapped)
            }
        }
