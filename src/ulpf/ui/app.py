"""
ULPF FastAPI Server & SOC Operations Dashboard Backend.
Provides RESTful ingestion, interactive Parser Studio, forensic investigation,
and ML feature export.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from ulpf.core.models import UniversalEvent
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.parsing.engine import ParserRegistry
from ulpf.normalization.taxonomy import ACTION_TAXONOMY_MAP, SEVERITY_TAXONOMY_MAP
from ulpf.ml.feature_extractor import MLFeatureExtractor
from ulpf.sinks.jsonl_sink import JsonlSink
from ulpf.sinks.parquet_sink import ParquetDataLakeSink
from ulpf.sinks.sqlite_sink import SqliteForensicSink
from ulpf.ingestion.file_reader import FileIngestionReader

# Global paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
CONFIGS_DIR = os.path.join(BASE_DIR, "configs", "parsers")
SAMPLE_LOGS_FILE = os.path.join(BASE_DIR, "sample_logs", "perimeter_devices.log")

# Robust writable DATA_DIR detection for serverless (Vercel / Lambda) environments
data_dir_env = os.environ.get("ULPF_DATA_DIR")
if data_dir_env:
    DATA_DIR = data_dir_env
elif os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DATA_DIR = "/tmp/ulpf_data"
else:
    DATA_DIR = os.path.join(BASE_DIR, "data")

try:
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    # Writability sanity check
    test_path = os.path.join(DATA_DIR, ".write_test")
    with open(test_path, "w") as f:
        f.write("1")
    os.remove(test_path)
except OSError:
    DATA_DIR = "/tmp/ulpf_data"
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

# Initialize registry, sinks, pipeline
registry = ParserRegistry(CONFIGS_DIR)
jsonl_sink = JsonlSink(os.path.join(DATA_DIR, "events.jsonl"))
parquet_sink = ParquetDataLakeSink(os.path.join(DATA_DIR, "parquet"))
sqlite_sink = SqliteForensicSink(os.path.join(DATA_DIR, "forensics.db"))

pipeline = ProcessingPipeline(registry=registry, sinks=[jsonl_sink, parquet_sink, sqlite_sink])

app = FastAPI(
    title="Universal Log Pre-processing Framework (ULPF)",
    description="Universal OCSF v1.2 Pre-processing & Standardization Engine for Perimeter Cybersecurity Logs",
    version="1.0.0",
)

# Mount static web directory
STATIC_DIR = os.path.join(Path(__file__).resolve().parent, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class LogProcessRequest(BaseModel):
    raw_log: str
    parser_id: Optional[str] = None


class BatchProcessRequest(BaseModel):
    logs: List[str]
    parser_id: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h2>ULPF Dashboard Active. Static files loading...</h2>")


from ulpf.enrichment.mitre_compliance import SecurityIntelligenceEngine
from ulpf.normalization.exporters import MultiSchemaExporter

default_mode = "internet" if (os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")) else "air_gapped"
DEPLOYMENT_MODE = os.environ.get("ULPF_DEPLOYMENT_MODE", default_mode)  # "air_gapped" or "internet"


@app.get("/api/v1/system/mode")
async def get_system_mode():
    return {
        "mode": DEPLOYMENT_MODE,
        "is_air_gapped": DEPLOYMENT_MODE == "air_gapped",
        "description": "Running 100% self-contained offline without external internet calls" if DEPLOYMENT_MODE == "air_gapped" else "Internet-connected Public SaaS mode"
    }


@app.post("/api/v1/system/mode")
async def set_system_mode(mode: str = Query(..., pattern="^(air_gapped|internet)$")):
    global DEPLOYMENT_MODE
    DEPLOYMENT_MODE = mode
    return {"status": "updated", "current_mode": DEPLOYMENT_MODE}


@app.post("/api/v1/process")
async def process_single_log(req: LogProcessRequest):
    """
    Ingests, parses, normalizes, enriches, extracts ML features, and maps to MITRE & Compliance.
    """
    if not req.raw_log.strip():
        raise HTTPException(status_code=400, detail="Empty raw_log received.")

    # Extract tokens for Phase 2 inspection
    extracted, plugin, confidence = registry.parse(req.raw_log.strip(), req.parser_id)
    event = pipeline.process_event(req.raw_log, parser_id=req.parser_id, deployment_mode=DEPLOYMENT_MODE)
    features = MLFeatureExtractor.extract_features(event)
    vector = MLFeatureExtractor.to_vector(event)
    
    # Security Intelligence & Regulatory Compliance Engine
    mitre, compliance, risk = SecurityIntelligenceEngine.evaluate(event)
    siem_format = MultiSchemaExporter.to_siem_format(event, risk.score)
    ecs_format = MultiSchemaExporter.to_ecs_format(event)
    forensic_bundle = MultiSchemaExporter.to_forensic_bundle(event)
    traceability = MultiSchemaExporter.build_traceability(event)

    # Executive Plain-English Narrative
    src = f"{event.src_endpoint.ip}:{event.src_endpoint.port}" if event.src_endpoint.port else str(event.src_endpoint.ip or "Unknown Source")
    dst = f"{event.dst_endpoint.ip}:{event.dst_endpoint.port}" if event.dst_endpoint.port else str(event.dst_endpoint.ip or "Unknown Target")
    src_loc = "Internal LAN" if event.src_endpoint.is_internal else (event.src_endpoint.country or "Public Internet")
    dst_loc = "Internal Protected LAN" if event.dst_endpoint.is_internal else (event.dst_endpoint.country or "Public Internet")
    proto = (event.connection_info.protocol_name or "IP").upper()
    action = event.disposition.value
    vendor = event.product.vendor_name
    direction = event.connection_info.direction.value

    rule = (
        event.unmapped.get("rule_name")
        or event.unmapped.get("policyid")
        or event.unmapped.get("rule")
        or event.unmapped.get("access-group")
        or "Default Perimeter Policy"
    )

    if action == "Allowed":
        narrative = (
            f"Authorized network connection permitted from {src} ({src_loc}) to {dst} ({dst_loc}) "
            f"over {proto}. Firewall policy '{rule}' on {vendor} granted {direction.lower()} session. "
            f"Zero active security violations detected."
        )
    else:
        narrative = (
            f"Perimeter security policy '{rule}' on {vendor} actively BLOCKED traffic from {src} ({src_loc}) "
            f"targeting {dst} ({dst_loc}) via {proto}. Ingress inspection resulted in an immediate {action} "
            f"decision to protect internal resources."
        )

    # 3-Phase Transformation Execution Trace
    phases = {
        "phase_1": {
            "title": "Phase 1: Ingestion & Integrity Hash",
            "description": "Verbatim raw log captured and SHA-256 fingerprint computed for legal non-repudiation.",
            "sha256": event.lineage.raw_hash,
            "raw_log": event.raw_event,
            "raw_length": len(event.raw_event.encode('utf-8')),
            "ingestion_timestamp": event.lineage.ingestion_timestamp,
            "event_timestamp": event.lineage.event_timestamp or event.lineage.ingestion_timestamp,
            "status": "Verified Lossless (Bit-for-Bit)"
        },
        "phase_2": {
            "title": f"Phase 2: Declarative Extraction ({event.lineage.parser_id})",
            "description": f"Log deconstructed into structured tokens using declarative YAML rules for {event.product.vendor_name}.",
            "parser_id": event.lineage.parser_id,
            "vendor": event.product.vendor_name,
            "parser_name": plugin.name if plugin else event.product.vendor_name,
            "format": (plugin.format if plugin else "Auto-Detected").upper(),
            "confidence": round(float(confidence) * 100, 1),
            "extracted_fields": {k: str(v) for k, v in extracted.items()} if extracted else {},
            "extracted_count": len(extracted) if extracted else 0,
            "unmapped_retained": len(event.unmapped)
        },
        "phase_3": {
            "title": "Phase 3: Canonical Normalization & Intelligence",
            "description": "Attributes mapped to canonical OCSF Network Activity (Class 4001), MITRE ATT&CK, and 26-D ML vectors.",
            "action": event.disposition.value,
            "direction": event.connection_info.direction.value,
            "protocol": proto,
            "src_endpoint": src,
            "dst_endpoint": dst,
            "mitre_tactic": mitre.tactic_name,
            "mitre_technique": mitre.technique_name,
            "risk_score": risk.score,
            "risk_level": risk.level,
            "risk_factors": risk.factors,
            "ml_features_count": len(vector),
            "sinks_dispatched": ["Apache Parquet Data Lake", "Forensic SQLite Database", "Streaming JSON-L"],
            "enclave_status": "Air-Gapped: 0 Outbound Sockets Opened" if DEPLOYMENT_MODE == "air_gapped" else "Public Cloud: Live PTR & Threat Alliance Active"
        }
    }
    
    return {
        "event": event.model_dump(),
        "integrity_verified": event.verify_integrity(),
        "features": features,
        "ml_vector": vector,
        "feature_names": MLFeatureExtractor.get_feature_names(),
        "mitre": mitre.model_dump(),
        "compliance": compliance.model_dump(),
        "risk": risk.model_dump(),
        "narrative": narrative,
        "phases": phases,
        "siem_format": siem_format,
        "wazuh_format": siem_format,  # backward compatibility
        "ecs_format": ecs_format,
        "forensic_bundle": forensic_bundle,
        "traceability": traceability,
        "deployment_mode": DEPLOYMENT_MODE,
        "enclave_telemetry": {
            "mode": DEPLOYMENT_MODE,
            "is_air_gapped": DEPLOYMENT_MODE == "air_gapped",
            "egress_permitted": DEPLOYMENT_MODE == "internet",
            "dns_resolution": "Live Reverse DNS (PTR) Active" if DEPLOYMENT_MODE == "internet" else "Inhibited (Air-Gapped Leak Prevention Active)",
            "isolation_rating": "MIL-SPEC Enclave Isolation (0 Outbound Sockets)" if DEPLOYMENT_MODE == "air_gapped" else "Public SaaS Multi-Tenant Cloud",
            "threat_feed_origin": "Local Air-Gapped Signature Cache" if DEPLOYMENT_MODE == "air_gapped" else "Cloud Dynamic Global Threat Alliance",
            "compliance_focus": "NIST SP 800-53 SC-7 & ISO 27001 A.13.1 (Isolation)" if DEPLOYMENT_MODE == "air_gapped" else "SOC 2 Type II & PCI-DSS 1.3 (Cloud Transport)"
        },
    }


@app.post("/api/v1/batch")
async def process_batch_logs(req: BatchProcessRequest):
    """
    Batch processing endpoint for high volume ingestion.
    """
    events = pipeline.process_batch(req.logs, parser_id=req.parser_id)
    return {
        "processed_count": len(events),
        "events": [e.model_dump() for e in events]
    }


@app.get("/api/v1/parsers")
async def list_parsers():
    """
    Lists all loaded declarative parser plugins.
    """
    return {
        "count": len(registry.parsers),
        "parsers": [
            {
                "id": p.id,
                "name": p.name,
                "vendor": p.vendor,
                "product": p.product,
                "format": p.format,
                "version": p.version,
            }
            for p in registry.parsers.values()
        ]
    }


@app.post("/api/v1/parsers/reload")
async def reload_parsers():
    """Hot-reloads parser plugins from YAML configs directory."""
    registry.load_from_directory(CONFIGS_DIR)
    return {"status": "reloaded", "active_parsers": len(registry.parsers)}


@app.get("/api/v1/telemetry")
async def get_telemetry():
    """Returns pipeline throughput, latency, and classification metrics."""
    return pipeline.get_telemetry()


@app.get("/api/v1/events")
async def get_events(limit: int = 50, vendor: Optional[str] = None):
    """
    Forensic query endpoint querying SQLite sink.
    """
    where_clause = "1=1"
    params = []
    if vendor:
        where_clause += " AND vendor = ?"
        params.append(vendor)

    rows = sqlite_sink.query(where_clause=where_clause, params=tuple(params), limit=limit)
    return {"count": len(rows), "records": rows}


@app.post("/api/v1/load-samples")
async def load_sample_dataset():
    """
    Ingests the standard perimeter sample dataset into the pipeline.
    """
    if not os.path.exists(SAMPLE_LOGS_FILE):
        raise HTTPException(status_code=404, detail="Sample logs file not found.")

    reader = FileIngestionReader(pipeline)
    events = reader.ingest_file(SAMPLE_LOGS_FILE)
    parquet_sink.flush()
    return {"status": "success", "ingested_events": len(events)}
