"""
ULPF MITRE ATT&CK®, Compliance Frameworks, and Dynamic Risk Scoring Engine.
Maps normalized perimeter network events to:
1. MITRE ATT&CK Enterprise Matrix (Tactics & Techniques)
2. Regulatory Compliance Frameworks (PCI-DSS, NIST 800-53, ISO 27001, HIPAA, GDPR)
3. Threat Risk Score (0-100 composite index)
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from ulpf.core.models import UniversalEvent, EventDisposition, SeverityLevel, NetworkDirection


class MitreAttackInfo(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    url: str


class ComplianceFramework(BaseModel):
    pci_dss: List[str] = Field(default_factory=list)
    nist_800_53: List[str] = Field(default_factory=list)
    iso_27001: List[str] = Field(default_factory=list)
    hipaa: List[str] = Field(default_factory=list)
    gdpr: List[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    score: int = 10  # 0 to 100
    level: str = "Low"  # Low, Medium, High, Critical
    factors: List[str] = Field(default_factory=list)


class SecurityIntelligenceEngine:
    """
    Evaluates events to inject MITRE ATT&CK context, compliance citations,
    and compute an objective threat risk index.
    """

    @classmethod
    def evaluate(cls, event: UniversalEvent) -> tuple[MitreAttackInfo, ComplianceFramework, RiskAssessment]:
        dst_port = event.dst_endpoint.port or 0
        proto = (event.connection_info.protocol_name or "").upper()
        action = event.disposition
        threat = event.threat
        is_blocked = action in [EventDisposition.BLOCKED, EventDisposition.DROPPED, EventDisposition.RESET]
        bytes_out = event.traffic.bytes_out or 0
        bytes_in = event.traffic.bytes_in or 0
        app = (event.app_name or "").lower()

        # -------------------------------------------------------------
        # 1. MITRE ATT&CK Mapping
        # -------------------------------------------------------------
        if threat and ("scan" in (threat.signature_name or "").lower() or dst_port in [23, 2323]):
            mitre = MitreAttackInfo(
                tactic_id="TA0043",
                tactic_name="Reconnaissance",
                technique_id="T1046",
                technique_name="Network Service Discovery",
                url="https://attack.mitre.org/techniques/T1046/"
            )
        elif dst_port in [3389, 22] and is_blocked:
            mitre = MitreAttackInfo(
                tactic_id="TA0001",
                tactic_name="Initial Access",
                technique_id="T1021.001" if dst_port == 3389 else "T1021.004",
                technique_name="Remote Services: Remote Desktop Protocol" if dst_port == 3389 else "Remote Services: SSH",
                url="https://attack.mitre.org/techniques/T1021/"
            )
        elif threat and "tor" in (threat.signature_name or "").lower():
            mitre = MitreAttackInfo(
                tactic_id="TA0011",
                tactic_name="Command and Control",
                technique_id="T1090.003",
                technique_name="Proxy: Multi-hop Proxy (Tor)",
                url="https://attack.mitre.org/techniques/T1090/003/"
            )
        elif bytes_out > 50000 and (bytes_out / (bytes_in + 1) > 3.0):
            mitre = MitreAttackInfo(
                tactic_id="TA0010",
                tactic_name="Exfiltration",
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                url="https://attack.mitre.org/techniques/T1048/"
            )
        elif dst_port in [80, 443, 8080]:
            mitre = MitreAttackInfo(
                tactic_id="TA0011",
                tactic_name="Command and Control",
                technique_id="T1071.001",
                technique_name="Application Layer Protocol: Web Protocols",
                url="https://attack.mitre.org/techniques/T1071/001/"
            )
        else:
            mitre = MitreAttackInfo(
                tactic_id="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1562.004",
                technique_name="Impair Defenses: Disable or Modify System Firewall",
                url="https://attack.mitre.org/techniques/T1562/004/"
            )

        # -------------------------------------------------------------
        # 2. Regulatory Compliance Framework Mapping
        # -------------------------------------------------------------
        compliance = ComplianceFramework(
            pci_dss=[
                "Req 10.2.1 (Audit log generation for perimeter ingress/egress)",
                "Req 10.2.4 (Log access to all firewall and perimeter security functions)",
                "Req 1.3 (Prohibit direct public access between Internet and Cardholder Data)",
            ],
            nist_800_53=[
                "AC-4 (Information Flow Enforcement via Perimeter Gateways)",
                "AU-12 (Audit Record Generation & Non-Repudiation)",
                "SC-7 (Boundary Protection)",
            ],
            iso_27001=[
                "Control A.12.4.1 (Event Logging & System Activity Monitoring)",
                "Control A.13.1.1 (Network Controls & Segregation)",
            ],
            hipaa=[
                "164.312(b) (Audit Controls on Network Transmission)",
                "164.312(e)(1) (Transmission Security across Public Networks)",
            ],
            gdpr=[
                "Article 32(1)(b) (Ability to ensure ongoing confidentiality and resilience)",
                "Article 33 (Breach notification and audit trail traceability)",
            ]
        )

        # -------------------------------------------------------------
        # 3. Dynamic Threat Risk Score (0 - 100)
        # -------------------------------------------------------------
        score = 15
        factors: List[str] = []

        if threat:
            score += 50
            factors.append(f"Threat Match: {threat.signature_name} (+50)")

        if is_blocked:
            score += 20
            factors.append("Security Policy Enforced: Connection Blocked/Dropped (+20)")

        # Port sensitivity
        if dst_port in [3389, 22, 23, 445, 139]:
            score += 15
            factors.append(f"Sensitive Remote Management Port ({dst_port}) Targeted (+15)")

        # Public to Internal ingress probe
        if event.connection_info.direction == NetworkDirection.INBOUND:
            score += 10
            factors.append("Inbound Public Traffic into Internal Perimeter (+10)")

        # Byte exfiltration skew
        if bytes_out > 20000 and (bytes_out / (bytes_in + 1) > 2.5):
            score += 15
            factors.append("Abnormal Outbound/Inbound Byte Volume Ratio (+15)")

        # Cap at 100
        score = min(max(score, 5), 100)
        
        if score >= 75:
            level = "Critical"
        elif score >= 50:
            level = "High"
        elif score >= 30:
            level = "Medium"
        else:
            level = "Low"

        risk = RiskAssessment(score=score, level=level, factors=factors)

        return mitre, compliance, risk
