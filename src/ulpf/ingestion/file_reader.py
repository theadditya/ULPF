"""
ULPF File Ingestion Engine.
Processes static log files and streams in batches.
"""

from __future__ import annotations
import os
from typing import Generator, List, Optional
from ulpf.core.pipeline import ProcessingPipeline
from ulpf.core.models import UniversalEvent


class FileIngestionReader:
    """
    Ingests logs from files or directories, skipping comments and blank lines.
    """
    def __init__(self, pipeline: ProcessingPipeline):
        self.pipeline = pipeline

    def ingest_file(self, file_path: str, parser_id: Optional[str] = None) -> List[UniversalEvent]:
        """
        Reads all non-comment lines from a file and pushes them through the pipeline.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        events: List[UniversalEvent] = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                event = self.pipeline.process_event(stripped, parser_id=parser_id)
                events.append(event)
        return events

    def stream_file(self, file_path: str, parser_id: Optional[str] = None) -> Generator[UniversalEvent, None, None]:
        """
        Generator yielding events one by one for low memory footprint.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                yield self.pipeline.process_event(stripped, parser_id=parser_id)
