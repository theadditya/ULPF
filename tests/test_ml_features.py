"""
Tests for Requirement (h): AI/ML-Ready Feature Extraction.
"""

import pytest
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.parsing.engine import ParserRegistry
from ulpf.ml.feature_extractor import MLFeatureExtractor, FEATURE_NAMES


@pytest.fixture
def pipeline():
    registry = ParserRegistry("configs/parsers")
    return ProcessingPipeline(registry=registry)


def test_ml_feature_vector_generation(pipeline):
    log = '<189>date=2026-09-22 time=18:02:22 devname="FGT-EDGE-01" devid="FG60E12345" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.45 srcport=49823 srcintf="port1" dstip=104.16.24.1 dstport=443 dstintf="wan1" proto=6 action="accept" policyid=1 app="HTTPS" sentbyte=2450 rcvdbyte=8120 duration=45'
    event = pipeline.process_event(log)
    
    features = MLFeatureExtractor.extract_features(event)
    vector = MLFeatureExtractor.to_vector(event)
    
    # Verify dimensions
    assert len(vector) == len(FEATURE_NAMES)
    assert len(features) == len(FEATURE_NAMES)
    
    # Verify specific feature attributes
    assert features["src_port"] == 49823.0
    assert features["dst_port"] == 443.0
    assert features["is_well_known_port"] == 1.0  # 443 < 1024
    assert features["is_ephemeral_src_port"] == 1.0  # 49823 >= 49152
    assert features["is_internal_src"] == 1.0  # 192.168.1.45 is RFC 1918
    assert features["is_internal_dst"] == 0.0  # 104.16.24.1 is public
    assert features["direction_outbound"] == 1.0
    assert features["proto_tcp"] == 1.0
    assert features["action_allowed"] == 1.0
    assert features["action_blocked"] == 0.0
    assert features["bytes_out_log"] > 0.0
    assert features["bytes_in_log"] > 0.0
