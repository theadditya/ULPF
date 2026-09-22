"""
ULPF Network Syslog Ingestion Listener (RFC 3164 / RFC 5424).
Listens for live perimeter device telemetry over UDP/TCP in air-gapped networks.
"""

from __future__ import annotations
import asyncio
from typing import Optional
from ulpf.core.pipeline import ProcessingPipeline


class SyslogUdpProtocol(asyncio.DatagramProtocol):
    """Async UDP Protocol for high-throughput Syslog streams."""
    def __init__(self, pipeline: ProcessingPipeline):
        self.pipeline = pipeline

    def datagram_received(self, data: bytes, addr):
        try:
            line = data.decode("utf-8", errors="replace")
            for subline in line.splitlines():
                if subline.strip():
                    self.pipeline.process_event(subline)
        except Exception as e:
            print(f"Error processing syslog datagram from {addr}: {e}")


class SyslogServer:
    """
    Manages UDP and TCP listeners for ingesting raw syslog from perimeter devices.
    """
    def __init__(self, pipeline: ProcessingPipeline, host: str = "0.0.0.0", port: int = 1514):
        self.pipeline = pipeline
        self.host = host
        self.port = port
        self.transport: Optional[asyncio.DatagramTransport] = None

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogUdpProtocol(self.pipeline),
            local_addr=(self.host, self.port)
        )
        print(f"[*] ULPF Syslog UDP listener active on {self.host}:{self.port}")

    def stop(self):
        if self.transport:
            self.transport.close()
