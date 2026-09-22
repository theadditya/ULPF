"""
ULPF Streaming JSON-Lines Sink.
Fast, lossless, append-only JSON-L output.
"""

from __future__ import annotations
import os
import json
from pathlib import Path
from typing import List, Optional
from ulpf.core.models import UniversalEvent
from ulpf.sinks.base import BaseSink


class JsonlSink(BaseSink):
    """
    Appends normalized events as newline-delimited JSON.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        self._file = open(file_path, "a", encoding="utf-8")

    def write(self, event: UniversalEvent) -> None:
        line = event.model_dump_json() + "\n"
        self._file.write(line)
        self._file.flush()

    def write_batch(self, events: List[UniversalEvent]) -> None:
        for ev in events:
            self._file.write(ev.model_dump_json() + "\n")
        self._file.flush()

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()
