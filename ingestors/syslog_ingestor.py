"""
Syslog UDP/TCP ingestor.
Listens on a UDP port and accepts RFC 3164/5424 syslog messages.
Makes the agent a drop-in SIEM receiver — any device that can send syslog
(firewalls, switches, load balancers, routers) integrates immediately.

Usage:
    ingestor = SyslogIngestor(host="0.0.0.0", port=5140)
    await ingestor.start()          # Start UDP listener in background
    events = ingestor.poll()        # Drain collected events
    await ingestor.stop()
"""

import asyncio
import logging
import re
import uuid
from collections import deque
from datetime import datetime
from typing import List, Optional, Deque

from .base_ingestor import BaseIngestor, NormalizedEvent

logger = logging.getLogger("SyslogIngestor")

# RFC 3164 syslog pattern:
# <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
RFC3164_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.+)$"
)

# IP extraction from messages
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "clock",
    10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
}

SEVERITY_NAMES = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# Map syslog severity to our severity levels
SYSLOG_TO_SEVERITY = {
    0: "CRITICAL",  # EMERGENCY
    1: "CRITICAL",  # ALERT
    2: "CRITICAL",  # CRITICAL
    3: "HIGH",      # ERROR
    4: "MEDIUM",    # WARNING
    5: "LOW",       # NOTICE
    6: "LOW",       # INFO
    7: "LOW",       # DEBUG
}


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol handler that queues received syslog messages."""

    def __init__(self, queue: deque, max_queue: int = 10000):
        self._queue = queue
        self._max = max_queue

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            message = data.decode("utf-8", errors="replace").strip()
            if message and len(self._queue) < self._max:
                self._queue.append((message, addr[0]))
        except Exception:
            pass

    def error_received(self, exc) -> None:
        logger.warning(f"Syslog UDP error: {exc}")


class SyslogIngestor(BaseIngestor):
    """
    Listens for syslog messages over UDP and normalizes them to NormalizedEvent.

    Devices configure their syslog target to <host>:<port> (UDP).
    Default port 5140 avoids needing root (port 514 requires root on Linux).
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5140):
        self.host = host
        self.port = port
        self._queue: Deque = deque()
        self._transport = None
        self._started = False

    @property
    def name(self) -> str:
        return "SyslogIngestor"

    async def start(self) -> None:
        """Start the UDP listener. Call this once before the agent loop begins."""
        if self._started:
            return
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self._queue),
            local_addr=(self.host, self.port),
        )
        self._started = True
        logger.info(f"Syslog UDP listener started on {self.host}:{self.port}")

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._started = False
            logger.info("Syslog UDP listener stopped")

    def poll(self) -> List[NormalizedEvent]:
        """Drain the queue and return normalized events."""
        events = []
        while self._queue:
            try:
                raw_msg, sender_ip = self._queue.popleft()
                event = self._parse_syslog(raw_msg, sender_ip)
                if event:
                    events.append(event)
            except IndexError:
                break
            except Exception as e:
                logger.debug(f"Syslog parse error: {e}")
        return events

    def _parse_syslog(self, raw: str, sender_ip: str) -> Optional[NormalizedEvent]:
        m = RFC3164_RE.match(raw)
        if not m:
            # Unstructured message — still useful
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                source="syslog",
                source_ip=sender_ip,
                message=raw[:512],
            )

        pri = int(m.group("pri"))
        facility = pri >> 3
        syslog_severity = pri & 0x07

        # Try to extract IP from message body (e.g., "from 1.2.3.4")
        message = m.group("message")
        ip_match = IP_RE.search(message)
        source_ip = ip_match.group(1) if ip_match else sender_ip

        # Extract username from common auth messages
        username = None
        user_match = re.search(r'for\s+(?:invalid user\s+)?(\S+)', message)
        if user_match:
            username = user_match.group(1)

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source=f"syslog/{FACILITY_NAMES.get(facility, str(facility))}",
            source_ip=source_ip,
            username=username,
            message=message[:512],
            extra={
                "syslog_facility": FACILITY_NAMES.get(facility, str(facility)),
                "syslog_severity": SEVERITY_NAMES.get(syslog_severity, str(syslog_severity)),
                "syslog_host": m.group("host"),
                "syslog_tag": m.group("tag").strip(),
                "sender_ip": sender_ip,
            },
        )

    def feed_line(self, line: str, sender_ip: str = "127.0.0.1") -> None:
        """Inject a raw syslog line directly (for testing without UDP)."""
        self._queue.append((line, sender_ip))
