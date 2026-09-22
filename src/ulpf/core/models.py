"""
Universal Log Pre-processing Framework (ULPF) - Core Data Models.
Aligned with OCSF v1.2 (Open Cybersecurity Schema Framework) and ECS.
Preserves raw events losslessly, tracks cryptographic lineage, and standardizes
perimeter network activity.
"""

from __future__ import annotations
import uuid
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, ConfigDict


class EventDisposition(str, Enum):
    ALLOWED = "Allowed"
    BLOCKED = "Blocked"
    DROPPED = "Dropped"
    RESET = "Reset"
    ALERTED = "Alerted"
    QUARANTINED = "Quarantined"
    UNKNOWN = "Unknown"


class SeverityLevel(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    FATAL = "Fatal"
    UNKNOWN = "Unknown"


class NetworkDirection(str, Enum):
    INBOUND = "Inbound"
    OUTBOUND = "Outbound"
    LATERAL = "Lateral"
    INTERNAL = "Internal"
    EXTERNAL = "External"
    UNKNOWN = "Unknown"


class EndpointInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    zone: Optional[str] = None
    interface: Optional[str] = None
    is_internal: Optional[bool] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None


class TrafficMetrics(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    bytes_in: Optional[int] = 0
    bytes_out: Optional[int] = 0
    total_bytes: Optional[int] = 0
    packets_in: Optional[int] = 0
    packets_out: Optional[int] = 0
    total_packets: Optional[int] = 0
    duration_ms: Optional[int] = 0


class ConnectionInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    protocol_name: Optional[str] = "unknown"
    protocol_num: Optional[int] = None
    direction: NetworkDirection = NetworkDirection.UNKNOWN
    session_id: Optional[str] = None
    tcp_flags: Optional[str] = None
    state: Optional[str] = None


class ThreatInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None
    category: Optional[str] = None
    cve: Optional[str] = None
    threat_actor: Optional[str] = None
    indicator_matched: Optional[str] = None
    confidence_score: Optional[float] = None


class ProductInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    vendor_name: str = "Unknown"
    product_name: str = "Unknown"
    product_version: Optional[str] = None
    feature: Optional[str] = None


class LineageInfo(BaseModel):
    """
    Forensic Lineage and Traceability Metadata.
    Guarantees non-repudiation, tamper-evidence, and processing transparency.
    """
    model_config = ConfigDict(extra="ignore")
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_hash: str = ""
    collector_id: str = "ulpf-default-collector"
    parser_id: str = "unknown"
    parser_version: str = "1.0.0"
    schema_version: str = "ocsf-1.2.0-network"
    ingestion_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_timestamp: Optional[str] = None
    processing_latency_ms: float = 0.0
    is_valid: bool = True
    validation_errors: List[str] = Field(default_factory=list)


class UniversalEvent(BaseModel):
    """
    Universal Log Pre-processing Framework (ULPF) Unified Event Schema.
    OCSF Class: Network Activity (Class UID: 4001).
    Preserves verbatim raw data, provides strict typing, and captures unmapped fields.
    """
    model_config = ConfigDict(extra="ignore")
    
    # 1. Forensic Raw Data Preservation (Lossless Guarantee)
    raw_event: str
    
    # 2. Lineage & Traceability
    lineage: LineageInfo = Field(default_factory=LineageInfo)
    
    # 3. Product & Source
    product: ProductInfo = Field(default_factory=ProductInfo)
    
    # 4. Endpoints (Source & Destination)
    src_endpoint: EndpointInfo = Field(default_factory=EndpointInfo)
    dst_endpoint: EndpointInfo = Field(default_factory=EndpointInfo)
    
    # 5. Network Connection
    connection_info: ConnectionInfo = Field(default_factory=ConnectionInfo)
    
    # 6. Volume & Traffic Metrics
    traffic: TrafficMetrics = Field(default_factory=TrafficMetrics)
    
    # 7. Security Action & Disposition
    disposition: EventDisposition = EventDisposition.UNKNOWN
    disposition_reason: Optional[str] = None
    
    # 8. Severity
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    vendor_severity: Optional[str] = None
    
    # 9. Application Layer & Classification
    app_name: Optional[str] = None
    url: Optional[str] = None
    domain: Optional[str] = None
    
    # 10. Threat Intelligence & Signatures
    threat: Optional[ThreatInfo] = None
    
    # 11. Zero Data Loss Catch-All: Unmapped Attributes
    unmapped: Dict[str, Any] = Field(default_factory=dict)

    def calculate_raw_hash(self) -> str:
        """Calculates SHA-256 hash of the verbatim raw event string."""
        return hashlib.sha256(self.raw_event.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verifies if the current raw_event matches the stored raw_hash."""
        return self.lineage.raw_hash == self.calculate_raw_hash()
