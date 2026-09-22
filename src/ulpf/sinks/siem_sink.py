"""
ULPF SIEM Forwarder Sink.
Simulates real-time event forwarding to enterprise SIEM platforms
(Splunk, Microsoft Sentinel, IBM QRadar, Elastic Security).
"""

from __future__ import annotations
import socket
import json
from typing import Optional, List
from ulpf.core.models import UniversalEvent
from ulpf.sinks.base import BaseSink


class SiemForwarderSink(BaseSink):
    """
    Forwards standardized OCSF / JSON-Lines events to a SIEM collector
    via Syslog UDP/TCP or simulates forwarding in memory.
    """
    def __init__(self, host: Optional[str] = None, port: int = 514, protocol: str = "udp", dry_run: bool = True):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.dry_run = dry_run
        self.forwarded_count = 0
        self._sock: Optional[socket.socket] = None
        
        if not self.dry_run and self.host:
            sock_type = socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM
            self._sock = socket.socket(socket.AF_INET, sock_type)
            if self.protocol == "tcp":
                self._sock.connect((self.host, self.port))

    def write(self, event: UniversalEvent) -> None:
        payload = event.model_dump_json()
        if not self.dry_run and self._sock and self.host:
            try:
                data = (payload + "\n").encode("utf-8")
                if self.protocol == "udp":
                    self._sock.sendto(data, (self.host, self.port))
                else:
                    self._sock.sendall(data)
            except Exception:
                pass
        self.forwarded_count += 1

    def close(self) -> None:
        if self._sock:
            self._sock.close()
