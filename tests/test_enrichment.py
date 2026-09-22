"""
Tests for Requirement (j): Air-Gapped Network Enrichment and Offline Classification.
"""

from ulpf.enrichment.network import is_private_or_internal, determine_direction, get_offline_geo_asn
from ulpf.enrichment.threat import lookup_threat
from ulpf.core.models import NetworkDirection


def test_rfc1918_classification():
    assert is_private_or_internal("192.168.1.1") is True
    assert is_private_or_internal("10.50.12.1") is True
    assert is_private_or_internal("172.16.5.20") is True
    assert is_private_or_internal("127.0.0.1") is True
    assert is_private_or_internal("8.8.8.8") is False
    assert is_private_or_internal("104.16.24.1") is False


def test_direction_determination():
    # Internal to External -> Outbound
    assert determine_direction("192.168.1.10", "8.8.8.8") == NetworkDirection.OUTBOUND
    # External to Internal -> Inbound
    assert determine_direction("198.51.100.2", "10.0.0.5") == NetworkDirection.INBOUND
    # Internal to Internal -> Lateral
    assert determine_direction("10.0.0.1", "192.168.1.5") == NetworkDirection.LATERAL
    # External to External -> External
    assert determine_direction("8.8.8.8", "1.1.1.1") == NetworkDirection.EXTERNAL


def test_offline_geo_asn_lookup():
    country, city, asn = get_offline_geo_asn("8.8.8.8")
    assert country == "US"
    assert "Google" in asn

    country, city, asn = get_offline_geo_asn("192.168.1.1")
    assert country == "INTERNAL"
    assert "Private" in asn


def test_offline_threat_ioc_lookup():
    # Test known Tor exit node in offline database
    threat = lookup_threat("185.220.101.5", "10.0.0.1")
    assert threat is not None
    assert threat.signature_id == "IOC-TOR-EXIT"

    # Clean IP
    assert lookup_threat("8.8.8.8", "1.1.1.1") is None
