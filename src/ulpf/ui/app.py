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
DATA_DIR = os.path.join(BASE_DIR, "data")
SAMPLE_LOGS_FILE = os.path.join(BASE_DIR, "sample_logs", "perimeter_devices.log")

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

DEPLOYMENT_MODE = os.environ.get("ULPF_DEPLOYMENT_MODE", "air_gapped")  # "air_gapped" or "internet"


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

    event = pipeline.process_event(req.raw_log, parser_id=req.parser_id)
    features = MLFeatureExtractor.extract_features(event)
    vector = MLFeatureExtractor.to_vector(event)
    
    # Wazuh-inspired Intelligence & Compliance Engine
    mitre, compliance, risk = SecurityIntelligenceEngine.evaluate(event)
    wazuh_format = MultiSchemaExporter.to_wazuh_format(event, risk.score)
    ecs_format = MultiSchemaExporter.to_ecs_format(event)

    # 3-Phase Wazuh Logtest-inspired Transformation Trace
    phases = {
        "phase_1": {
            "title": "Phase 1: Ingestion & Integrity Hash",
            "description": "Verbatim raw log captured and SHA-256 fingerprint computed for legal non-repudiation.",
            "sha256": event.lineage.raw_hash,
            "raw_length": len(event.raw_event),
            "ingestion_timestamp": event.lineage.ingestion_timestamp
        },
        "phase_2": {
            "title": f"Phase 2: YAML Extraction ({event.lineage.parser_id})",
            "description": f"Log deconstructed into key-value pairs using declarative parser rules for {event.product.vendor_name}.",
            "parser_id": event.lineage.parser_id,
            "vendor": event.product.vendor_name,
            "unmapped_retained": len(event.unmapped)
        },
        "phase_3": {
            "title": "Phase 3: OCSF v1.2 Normalization & Intelligence",
            "description": "Attributes mapped to canonical OCSF Network Activity (Class 4001), MITRE ATT&CK, and 26-D ML vectors.",
            "action": event.disposition.value,
            "direction": event.connection_info.direction.value,
            "mitre_tactic": mitre.tactic_name,
            "risk_score": risk.score,
            "ml_features_count": len(vector)
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
        "phases": phases,
        "wazuh_format": wazuh_format,
        "ecs_format": ecs_format,
        "deployment_mode": DEPLOYMENT_MODE,
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
