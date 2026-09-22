"""
ULPF Common Cybersecurity Taxonomy & Normalization Dictionaries.
Standardizes heterogeneous vendor terminologies into unified OCSF v1.2 / ECS classes.
"""

from __future__ import annotations
from typing import Optional
from ulpf.core.models import EventDisposition, SeverityLevel


ACTION_TAXONOMY_MAP = {
    # Allowed actions
    "allow": EventDisposition.ALLOWED,
    "allowed": EventDisposition.ALLOWED,
    "accept": EventDisposition.ALLOWED,
    "accepted": EventDisposition.ALLOWED,
    "permit": EventDisposition.ALLOWED,
    "permitted": EventDisposition.ALLOWED,
    "pass": EventDisposition.ALLOWED,
    "success": EventDisposition.ALLOWED,
    "open": EventDisposition.ALLOWED,
    "built": EventDisposition.ALLOWED,
    
    # Blocked / Denied actions
    "deny": EventDisposition.BLOCKED,
    "denied": EventDisposition.BLOCKED,
    "block": EventDisposition.BLOCKED,
    "blocked": EventDisposition.BLOCKED,
    "reject": EventDisposition.BLOCKED,
    "rejected": EventDisposition.BLOCKED,
    "disallowed": EventDisposition.BLOCKED,
    
    # Dropped actions
    "drop": EventDisposition.DROPPED,
    "dropped": EventDisposition.DROPPED,
    
    # Reset actions
    "reset": EventDisposition.RESET,
    "reset-server": EventDisposition.RESET,
    "reset-client": EventDisposition.RESET,
    "reset-both": EventDisposition.RESET,
    "teardown": EventDisposition.ALLOWED,  # In Cisco ASA, teardown means completed session
    
    # Alert / Alarm
    "alert": EventDisposition.ALERTED,
    "alerted": EventDisposition.ALERTED,
    "alarm": EventDisposition.ALERTED,
    "quarantine": EventDisposition.QUARANTINED,
    "quarantined": EventDisposition.QUARANTINED,
}


SEVERITY_TAXONOMY_MAP = {
    # Numerical Syslog 0-7
    "0": SeverityLevel.FATAL,
    "1": SeverityLevel.CRITICAL,
    "2": SeverityLevel.CRITICAL,
    "3": SeverityLevel.HIGH,
    "4": SeverityLevel.MEDIUM,
    "5": SeverityLevel.LOW,
    "6": SeverityLevel.INFORMATIONAL,
    "7": SeverityLevel.INFORMATIONAL,
    
    # Common text levels
    "emerg": SeverityLevel.FATAL,
    "emergency": SeverityLevel.FATAL,
    "fatal": SeverityLevel.FATAL,
    "alert": SeverityLevel.CRITICAL,
    "crit": SeverityLevel.CRITICAL,
    "critical": SeverityLevel.CRITICAL,
    "err": SeverityLevel.HIGH,
    "error": SeverityLevel.HIGH,
    "high": SeverityLevel.HIGH,
    "warn": SeverityLevel.MEDIUM,
    "warning": SeverityLevel.MEDIUM,
    "medium": SeverityLevel.MEDIUM,
    "notice": SeverityLevel.LOW,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.INFORMATIONAL,
    "informational": SeverityLevel.INFORMATIONAL,
    "debug": SeverityLevel.INFORMATIONAL,
}


PROTOCOL_NUM_TO_NAME = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
    132: "SCTP",
}


def normalize_action(vendor_action: Optional[str]) -> EventDisposition:
    """Standardizes vendor action string to OCSF EventDisposition."""
    if not vendor_action:
        return EventDisposition.UNKNOWN
    cleaned = str(vendor_action).strip().lower()
    return ACTION_TAXONOMY_MAP.get(cleaned, EventDisposition.UNKNOWN)


def normalize_severity(vendor_sev: Optional[str]) -> SeverityLevel:
    """Standardizes vendor severity string or code to OCSF SeverityLevel."""
    if not vendor_sev:
        return SeverityLevel.INFORMATIONAL
    cleaned = str(vendor_sev).strip().lower()
    return SEVERITY_TAXONOMY_MAP.get(cleaned, SeverityLevel.INFORMATIONAL)


def normalize_protocol(proto: Any) -> tuple[str, Optional[int]]:
    """
    Standardizes protocol to (protocol_name, protocol_num).
    Accepts both numeric codes (6, '6') and names ('TCP', 'udp').
    """
    if not proto:
        return "unknown", None
    proto_str = str(proto).strip()
    if proto_str.isdigit():
        p_num = int(proto_str)
        p_name = PROTOCOL_NUM_TO_NAME.get(p_num, f"IP-{p_num}")
        return p_name.upper(), p_num
    else:
        p_name = proto_str.upper()
        # Reverse lookup number if common
        reverse_map = {v: k for k, v in PROTOCOL_NUM_TO_NAME.items()}
        return p_name, reverse_map.get(p_name)
