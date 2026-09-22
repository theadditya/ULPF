"""
ULPF AI/ML-Ready Feature Engineering Engine.
Transforms normalized cybersecurity events into numerical feature vectors and tabular matrices
optimized for machine learning models (Isolation Forests, Autoencoders, XGBoost, Clustering).
"""

from __future__ import annotations
import math
from typing import Dict, List, Any
from ulpf.core.models import UniversalEvent, NetworkDirection, EventDisposition, SeverityLevel


FEATURE_NAMES = [
    "src_port",
    "dst_port",
    "is_well_known_port",
    "is_ephemeral_src_port",
    "is_internal_src",
    "is_internal_dst",
    "direction_inbound",
    "direction_outbound",
    "direction_lateral",
    "direction_external",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_other",
    "bytes_in_log",
    "bytes_out_log",
    "total_bytes_log",
    "bytes_ratio_out_in",
    "packets_total_log",
    "duration_sec",
    "bytes_per_second",
    "action_blocked",
    "action_allowed",
    "severity_level",
    "threat_flag",
    "threat_confidence",
]


class MLFeatureExtractor:
    """
    Extracts high-dimensional numerical feature representations from UniversalEvent instances.
    """

    @staticmethod
    def extract_features(event: UniversalEvent) -> Dict[str, float]:
        """
        Converts a UniversalEvent into a dictionary of numerical features.
        """
        src_port = float(event.src_endpoint.port or 0)
        dst_port = float(event.dst_endpoint.port or 0)
        
        is_well_known = 1.0 if (0 < dst_port < 1024) else 0.0
        is_ephemeral = 1.0 if (src_port >= 49152) else 0.0
        is_int_src = 1.0 if event.src_endpoint.is_internal else 0.0
        is_int_dst = 1.0 if event.dst_endpoint.is_internal else 0.0
        
        dir_in = 1.0 if event.connection_info.direction == NetworkDirection.INBOUND else 0.0
        dir_out = 1.0 if event.connection_info.direction == NetworkDirection.OUTBOUND else 0.0
        dir_lat = 1.0 if event.connection_info.direction == NetworkDirection.LATERAL else 0.0
        dir_ext = 1.0 if event.connection_info.direction == NetworkDirection.EXTERNAL else 0.0
        
        proto = (event.connection_info.protocol_name or "").lower()
        proto_tcp = 1.0 if "tcp" in proto else 0.0
        proto_udp = 1.0 if "udp" in proto else 0.0
        proto_icmp = 1.0 if "icmp" in proto else 0.0
        proto_other = 1.0 if (proto_tcp == 0 and proto_udp == 0 and proto_icmp == 0) else 0.0
        
        b_in = float(event.traffic.bytes_in or 0)
        b_out = float(event.traffic.bytes_out or 0)
        b_tot = float(event.traffic.total_bytes or (b_in + b_out))
        p_tot = float(event.traffic.total_packets or (event.traffic.packets_in or 0) + (event.traffic.packets_out or 0))
        
        # Log-transformed traffic metrics (handles extreme skews in network volume)
        bytes_in_log = math.log1p(b_in)
        bytes_out_log = math.log1p(b_out)
        total_bytes_log = math.log1p(b_tot)
        packets_total_log = math.log1p(p_tot)
        
        # Outbound/Inbound ratio (exfiltration indicator)
        bytes_ratio = (bytes_out_log) / (bytes_in_log + 1.0)
        
        duration_sec = float((event.traffic.duration_ms or 0)) / 1000.0
        bytes_per_sec = b_tot / (duration_sec + 0.001)
        
        action_blocked = 1.0 if event.disposition in [
            EventDisposition.BLOCKED, EventDisposition.DROPPED, EventDisposition.RESET
        ] else 0.0
        action_allowed = 1.0 if event.disposition == EventDisposition.ALLOWED else 0.0
        
        sev_map = {
            SeverityLevel.INFORMATIONAL: 0.0,
            SeverityLevel.LOW: 1.0,
            SeverityLevel.MEDIUM: 2.0,
            SeverityLevel.HIGH: 3.0,
            SeverityLevel.CRITICAL: 4.0,
            SeverityLevel.FATAL: 5.0,
            SeverityLevel.UNKNOWN: 0.0,
        }
        severity_val = sev_map.get(event.severity, 0.0)
        
        threat_flag = 1.0 if (event.threat is not None) else 0.0
        threat_conf = float(event.threat.confidence_score or 0.0) if event.threat else 0.0
        
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "is_well_known_port": is_well_known,
            "is_ephemeral_src_port": is_ephemeral,
            "is_internal_src": is_int_src,
            "is_internal_dst": is_int_dst,
            "direction_inbound": dir_in,
            "direction_outbound": dir_out,
            "direction_lateral": dir_lat,
            "direction_external": dir_ext,
            "proto_tcp": proto_tcp,
            "proto_udp": proto_udp,
            "proto_icmp": proto_icmp,
            "proto_other": proto_other,
            "bytes_in_log": round(bytes_in_log, 4),
            "bytes_out_log": round(bytes_out_log, 4),
            "total_bytes_log": round(total_bytes_log, 4),
            "bytes_ratio_out_in": round(bytes_ratio, 4),
            "packets_total_log": round(packets_total_log, 4),
            "duration_sec": round(duration_sec, 4),
            "bytes_per_second": round(bytes_per_sec, 2),
            "action_blocked": action_blocked,
            "action_allowed": action_allowed,
            "severity_level": severity_val,
            "threat_flag": threat_flag,
            "threat_confidence": threat_conf,
        }

    @classmethod
    def to_vector(cls, event: UniversalEvent) -> List[float]:
        """Returns ordered float vector according to FEATURE_NAMES."""
        features = cls.extract_features(event)
        return [features.get(name, 0.0) for name in FEATURE_NAMES]

    @classmethod
    def get_feature_names(cls) -> List[str]:
        return list(FEATURE_NAMES)
