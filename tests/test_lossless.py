"""
Tests for Requirement (a) and (d): Lossless Raw Event Preservation and Cryptographic Lineage.
"""

import hashlib
import pytest
from ulpf.core.models import UniversalEvent
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.parsing.engine import ParserRegistry


@pytest.fixture
def pipeline():
    registry = ParserRegistry("configs/parsers")
    return ProcessingPipeline(registry=registry)


def test_lossless_raw_preservation(pipeline):
    raw_sample = '<189>date=2026-09-22 time=18:02:22 devname="FGT-EDGE-01" devid="FG60E12345" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.45 srcport=49823 srcintf="port1" dstip=104.16.24.1 dstport=443 dstintf="wan1" proto=6 action="accept" policyid=1 app="HTTPS" sentbyte=2450 rcvdbyte=8120 duration=45'
    
    event = pipeline.process_event(raw_sample)
    
    # 1. Verbatim raw event equality
    assert event.raw_event == raw_sample
    
    # 2. Cryptographic SHA-256 hash match
    expected_hash = hashlib.sha256(raw_sample.encode("utf-8")).hexdigest()
    assert event.lineage.raw_hash == expected_hash
    assert event.verify_integrity() is True
    
    # 3. Non-empty event_id
    assert len(event.lineage.event_id) > 10


def test_unmapped_attributes_lossless_retention(pipeline):
    # Log with extra arbitrary custom attributes
    raw_sample = 'date=2026-09-22 time=18:00:00 devname="FGT-01" custom_threat_score="99.4" proprietary_token="XYZ-987" type="traffic" srcip=10.0.0.1 dstip=10.0.0.2 proto=6 action="accept"'
    
    event = pipeline.process_event(raw_sample)
    
    # Check that custom attributes were captured into unmapped dictionary
    assert "custom_threat_score" in event.unmapped
    assert event.unmapped["custom_threat_score"] == "99.4"
    assert "proprietary_token" in event.unmapped
    assert event.unmapped["proprietary_token"] == "XYZ-987"
