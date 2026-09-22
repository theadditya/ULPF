"""
Tests for Requirements (b), (c), (e): Multi-vendor Perimeter Device Parsing and Normalization.
"""

import pytest
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.core.models import EventDisposition, SeverityLevel, NetworkDirection
from ulpf.parsing.engine import ParserRegistry


@pytest.fixture
def pipeline():
    registry = ParserRegistry("configs/parsers")
    return ProcessingPipeline(registry=registry)


def test_palo_alto_traffic_parser(pipeline):
    log = '<134>1,2026/09/22 18:00:15,001801000001,TRAFFIC,drop,1,2026/09/22 18:00:15,198.51.100.42,10.0.1.50,198.51.100.42,10.0.1.50,BLOCK_SUSPICIOUS,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,default,2026/09/22 18:00:15,14205,1,54123,80,54123,80,0x0,tcp,deny,64,64,0,1,2026/09/22 18:00:15,0,any'
    event = pipeline.process_event(log)
    
    assert event.product.vendor_name == "Palo Alto Networks"
    assert event.src_endpoint.ip == "198.51.100.42"
    assert event.src_endpoint.port == 54123
    assert event.dst_endpoint.ip == "10.0.1.50"
    assert event.dst_endpoint.port == 80
    assert event.connection_info.protocol_name == "TCP"
    assert event.disposition == EventDisposition.BLOCKED
    assert event.app_name == "web-browsing"


def test_cisco_asa_built(pipeline):
    log = '<166>Sep 22 18:01:05 firewall-edge-01 %ASA-6-302013: Built outbound TCP connection 987654 for outside:198.51.100.20/443 (198.51.100.20/443) to inside:192.168.1.100/54321 (192.168.1.100/54321)'
    event = pipeline.process_event(log)
    
    assert event.product.vendor_name == "Cisco Systems"
    assert event.disposition == EventDisposition.ALLOWED
    assert event.src_endpoint.ip == "192.168.1.100"
    assert event.src_endpoint.port == 54321
    assert event.dst_endpoint.ip == "198.51.100.20"
    assert event.dst_endpoint.port == 443
    assert event.connection_info.protocol_name == "TCP"


def test_cisco_asa_deny(pipeline):
    log = '<164>Sep 22 18:01:10 firewall-edge-01 %ASA-4-106023: Deny tcp src outside:203.0.113.50/51234 dst inside:192.168.1.10/22 by access-group "OUTSIDE_IN" [0x0, 0x0]'
    event = pipeline.process_event(log)
    
    assert event.product.vendor_name == "Cisco Systems"
    assert event.disposition == EventDisposition.BLOCKED
    assert event.src_endpoint.ip == "203.0.113.50"
    assert event.dst_endpoint.ip == "192.168.1.10"
    assert event.dst_endpoint.port == 22


def test_fortinet_fortios(pipeline):
    log = '<189>date=2026-09-22 time=18:02:22 devname="FGT-EDGE-01" devid="FG60E12345" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.45 srcport=49823 srcintf="port1" dstip=104.16.24.1 dstport=443 dstintf="wan1" proto=6 action="accept" policyid=1 app="HTTPS" sentbyte=2450 rcvdbyte=8120 duration=45'
    event = pipeline.process_event(log)
    
    assert event.product.vendor_name == "Fortinet"
    assert event.src_endpoint.ip == "192.168.1.45"
    assert event.dst_endpoint.ip == "104.16.24.1"
    assert event.dst_endpoint.port == 443
    assert event.traffic.bytes_out == 2450
    assert event.traffic.bytes_in == 8120
    assert event.disposition == EventDisposition.ALLOWED


def test_suricata_eve_json(pipeline):
    log = '{"timestamp":"2026-09-22T18:03:00.000123+0000","flow_id":981273412,"event_type":"alert","src_ip":"194.26.29.112","src_port":44122,"dest_ip":"10.0.0.15","dest_port":23,"proto":"TCP","app_proto":"telnet","alert":{"action":"blocked","gid":1,"signature_id":2010935,"rev":2,"signature":"ET SCAN Mirai Botnet Telnet Scan","category":"Attempted Information Leak","severity":1},"flow":{"pkts_toserver":3,"pkts_toclient":0,"bytes_toserver":180,"bytes_toclient":0}}'
    event = pipeline.process_event(log)
    
    assert event.src_endpoint.ip == "194.26.29.112"
    assert event.dst_endpoint.ip == "10.0.0.15"
    assert event.threat is not None
    assert "Mirai" in event.threat.signature_name
    assert event.disposition == EventDisposition.BLOCKED


def test_arcsight_cef(pipeline):
    log = 'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop packet|High|src=185.220.101.5 dst=10.0.0.22 spt=44123 dpt=22 proto=6 act=drop in=0 out=0 app=ssh'
    event = pipeline.process_event(log)
    
    assert event.src_endpoint.ip == "185.220.101.5"
    assert event.dst_endpoint.ip == "10.0.0.22"
    assert event.dst_endpoint.port == 22
    assert event.disposition == EventDisposition.DROPPED
