"""
ULPF Offline Threat Intelligence and IoC Matcher.
Enriches events with threat context completely offline (air-gapped compliant).
"""

from __future__ import annotations
from typing import Optional
from ulpf.core.models import ThreatInfo

# Embedded local threat intelligence cache (e.g. known malicious scanners, C2, botnets)
OFFLINE_IOC_DATABASE = {
    "185.220.101.5": {
        "signature_id": "IOC-TOR-EXIT",
        "signature_name": "Traffic Originating from Known Tor Exit Node",
        "category": "Anonymization Network",
        "cve": None,
        "threat_actor": "Unknown / Anonymized",
        "confidence_score": 0.95,
    },
    "194.26.29.112": {
        "signature_id": "IOC-MIRAI-SCANNER",
        "signature_name": "Mirai Botnet Telnet/SSH Scanner",
        "category": "Botnet Activity",
        "cve": "CVE-2017-17215",
        "threat_actor": "Mirai Variant",
        "confidence_score": 0.99,
    },
    "45.33.32.156": {
        "signature_id": "IOC-LOG4J-PROBE",
        "signature_name": "Exploitation Probe: Apache Log4j RCE (Log4Shell)",
        "category": "Exploit Attempt",
        "cve": "CVE-2021-44228",
        "threat_actor": "Mass Scanner",
        "confidence_score": 0.92,
    },
}


def lookup_threat(src_ip: Optional[str], dst_ip: Optional[str]) -> Optional[ThreatInfo]:
    """
    Checks if src_ip or dst_ip matches local offline threat intelligence signatures.
    """
    matched_ip = None
    if src_ip and src_ip in OFFLINE_IOC_DATABASE:
        matched_ip = src_ip
    elif dst_ip and dst_ip in OFFLINE_IOC_DATABASE:
        matched_ip = dst_ip
        
    if not matched_ip:
        return None
        
    ioc = OFFLINE_IOC_DATABASE[matched_ip]
    return ThreatInfo(
        signature_id=ioc["signature_id"],
        signature_name=ioc["signature_name"],
        category=ioc["category"],
        cve=ioc["cve"],
        threat_actor=ioc["threat_actor"],
        indicator_matched=matched_ip,
        confidence_score=ioc["confidence_score"]
    )
