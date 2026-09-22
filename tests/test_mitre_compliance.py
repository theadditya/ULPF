"""
Tests for Wazuh-inspired MITRE ATT&CK, Compliance, and Multi-Schema Exporter.
"""

import pytest
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.parsing.engine import ParserRegistry
from ulpf.enrichment.mitre_compliance import SecurityIntelligenceEngine
from ulpf.normalization.exporters import MultiSchemaExporter


@pytest.fixture
def pipeline():
    registry = ParserRegistry("configs/parsers")
    return ProcessingPipeline(registry=registry)


def test_mitre_attack_and_compliance_mapping(pipeline):
    # Suricata Mirai alert
    log = '{"timestamp":"2026-09-22T18:03:00.000123+0000","flow_id":981273412,"event_type":"alert","src_ip":"194.26.29.112","src_port":44122,"dest_ip":"10.0.0.15","dest_port":23,"proto":"TCP","app_proto":"telnet","alert":{"action":"blocked","gid":1,"signature_id":2010935,"rev":2,"signature":"ET SCAN Mirai Botnet Telnet Scan","category":"Attempted Information Leak","severity":1},"flow":{"pkts_toserver":3,"pkts_toclient":0,"bytes_toserver":180,"bytes_toclient":0}}'
    event = pipeline.process_event(log)
    
    mitre, compliance, risk = SecurityIntelligenceEngine.evaluate(event)
    
    # 1. MITRE ATT&CK
    assert mitre.tactic_id == "TA0043"
    assert mitre.tactic_name == "Reconnaissance"
    assert mitre.technique_id == "T1046"
    assert "Network Service Discovery" in mitre.technique_name
    
    # 2. Regulatory Compliance
    assert len(compliance.pci_dss) >= 2
    assert any("10.2" in c for c in compliance.pci_dss)
    assert any("AC-4" in c for c in compliance.nist_800_53)
    
    # 3. Dynamic Threat Risk Index
    assert risk.score >= 50
    assert risk.level in ["High", "Critical"]
    assert len(risk.factors) >= 2


def test_multi_schema_exporter(pipeline):
    log = '<166>Sep 22 18:01:05 firewall-edge-01 %ASA-6-302013: Built outbound TCP connection 987654 for outside:198.51.100.20/443 (198.51.100.20/443) to inside:192.168.1.100/54321 (192.168.1.100/54321)'
    event = pipeline.process_event(log)
    
    # Export to Wazuh JSON
    wazuh_alert = MultiSchemaExporter.to_wazuh_format(event, risk_score=35)
    assert "rule" in wazuh_alert
    assert "data" in wazuh_alert
    assert wazuh_alert["data"]["srcip"] == "192.168.1.100"
    assert wazuh_alert["data"]["dstip"] == "198.51.100.20"
    assert wazuh_alert["data"]["action"] == "Allowed"
    
    # Export to Elastic Common Schema (ECS)
    ecs_event = MultiSchemaExporter.to_ecs_format(event)
    assert "ecs" in ecs_event
    assert ecs_event["source"]["ip"] == "192.168.1.100"
    assert ecs_event["destination"]["ip"] == "198.51.100.20"
    assert ecs_event["network"]["transport"] == "tcp"
