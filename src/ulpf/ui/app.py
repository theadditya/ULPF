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


@app.post("/api/v1/process")
async def process_single_log(req: LogProcessRequest):
    """
    Ingests, parses, normalizes, enriches, and extracts ML features for a single raw log.
    """
    if not req.raw_log.strip():
        raise HTTPException(status_code=400, detail="Empty raw_log received.")

    event = pipeline.process_event(req.raw_log, parser_id=req.parser_id)
    features = MLFeatureExtractor.extract_features(event)
    vector = MLFeatureExtractor.to_vector(event)
    
    return {
        "event": event.model_dump(),
        "integrity_verified": event.verify_integrity(),
        "features": features,
        "ml_vector": vector,
        "feature_names": MLFeatureExtractor.get_feature_names(),
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
