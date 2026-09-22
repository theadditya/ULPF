"""
Tests for FastAPI Web UI and REST API Endpoints.
"""

import pytest
from starlette.testclient import TestClient
from ulpf.ui.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_api_parsers_list(client):
    res = client.get("/api/v1/parsers")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] >= 8
    parser_ids = [p["id"] for p in data["parsers"]]
    assert "palo_alto_traffic" in parser_ids
    assert "cisco_asa" in parser_ids
    assert "fortinet_fortios" in parser_ids


def test_api_process_single_log(client):
    payload = {
        "raw_log": '<166>Sep 22 18:01:05 firewall-edge-01 %ASA-6-302013: Built outbound TCP connection 987654 for outside:198.51.100.20/443 (198.51.100.20/443) to inside:192.168.1.100/54321 (192.168.1.100/54321)'
    }
    res = client.post("/api/v1/process", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["integrity_verified"] is True
    assert data["event"]["product"]["vendor_name"] == "Cisco Systems"
    assert data["event"]["disposition"] == "Allowed"
    assert "ml_vector" in data
    assert len(data["ml_vector"]) == 26


def test_api_telemetry(client):
    res = client.get("/api/v1/telemetry")
    assert res.status_code == 200
    data = res.json()
    assert "total_processed" in data
    assert "average_latency_ms" in data


def test_api_events_query(client):
    res = client.get("/api/v1/events?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "records" in data
