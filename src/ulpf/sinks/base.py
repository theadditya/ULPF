"""
ULPF Sinks Base Interface.
Defines standard contracts for Big Data Lakes, SIEMs, and storage systems.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List
from ulpf.core.models import UniversalEvent


class BaseSink(ABC):
    """Abstract base class for all output sinks."""

    @abstractmethod
    def write(self, event: UniversalEvent) -> None:
        """Writes a single normalized UniversalEvent."""
        pass

    def write_batch(self, events: List[UniversalEvent]) -> None:
        """Batch write implementation for high-throughput streaming."""
        for event in events:
            self.write(event)

    def close(self) -> None:
        """Closes open connections or file handles."""
        pass
