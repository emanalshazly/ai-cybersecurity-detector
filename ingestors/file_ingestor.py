"""
File-based log ingestor.
Tails log files and parses common formats (Apache/Nginx combined log, auth.log).
"""

import re
import uuid
import logging
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from .base_ingestor import BaseIngestor, NormalizedEvent

logger = logging.getLogger("FileIngestor")

# Apache/Nginx combined log format:
# 1.2.3.4 - frank [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref.com" "Mozilla/5.0"
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+'           # Client IP
    r'\S+\s+'                   # Ident (usually -)
    r'\S+\s+'                   # Auth user (usually -)
    r'\[(?P<time>[^\]]+)\]\s+'  # Timestamp
    r'"(?P<method>\S+)\s+'      # HTTP method
    r'(?P<path>\S+)\s+'         # Request path
    r'\S+"\s+'                  # Protocol
    r'(?P<code>\d+)\s+'         # Status code
    r'(?P<size>\S+)'            # Response size
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'  # Referer + User-Agent (optional)
)

# auth.log entry:  Apr  1 13:00:01 hostname sshd[1234]: Failed password for root from 1.2.3.4
AUTH_LOG_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+(?P<service>\S+):\s+(?P<message>.+)'
)


class FileIngestor(BaseIngestor):
    """
    Tails one or more log files, remembering read position between polls.
    Thread-safe for single-consumer use.
    """

    def __init__(self, file_paths: List[str]):
        self._paths = [Path(p) for p in file_paths if Path(p).exists()]
        self._positions: dict = {}  # filepath -> byte offset
        if not self._paths:
            logger.warning("FileIngestor: no valid log files found to monitor")
        else:
            logger.info(f"FileIngestor monitoring: {[str(p) for p in self._paths]}")
            # Start from end of file (don't replay historical logs)
            for p in self._paths:
                self._positions[str(p)] = p.stat().st_size

    @property
    def name(self) -> str:
        return "FileIngestor"

    def poll(self) -> List[NormalizedEvent]:
        events = []
        for path in self._paths:
            try:
                events.extend(self._read_new_lines(path))
            except Exception as e:
                logger.error(f"Error reading {path}: {e}")
        return events

    def _read_new_lines(self, path: Path) -> List[NormalizedEvent]:
        events = []
        key = str(path)
        current_size = path.stat().st_size
        last_pos = self._positions.get(key, 0)

        if current_size < last_pos:
            # Log was rotated
            last_pos = 0

        if current_size == last_pos:
            return []  # No new data

        with open(path, "r", errors="replace") as f:
            f.seek(last_pos)
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                event = self._parse_line(line, str(path))
                if event:
                    events.append(event)

        self._positions[key] = current_size
        return events

    def _parse_line(self, line: str, source: str) -> Optional[NormalizedEvent]:
        """Try each parser until one succeeds."""
        if "auth.log" in source or "syslog" in source:
            return self._parse_auth_log(line, source)
        return self._parse_combined_log(line, source)

    def _parse_combined_log(self, line: str, source: str) -> Optional[NormalizedEvent]:
        m = COMBINED_LOG_RE.match(line)
        if not m:
            return None
        try:
            size_str = m.group("size")
            size = int(size_str) if size_str != "-" else None
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                source=Path(source).name,
                source_ip=m.group("ip"),
                request_type=m.group("method"),
                endpoint=m.group("path"),
                response_code=int(m.group("code")),
                response_size=size,
                user_agent=m.group("ua"),
                message=line,
            )
        except Exception:
            return None

    def _parse_auth_log(self, line: str, source: str) -> Optional[NormalizedEvent]:
        m = AUTH_LOG_RE.match(line)
        if not m:
            return None
        try:
            message = m.group("message")
            # Extract IP from auth.log messages like "from 1.2.3.4"
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            source_ip = ip_match.group(1) if ip_match else None
            # Extract username
            user_match = re.search(r'for\s+(?:invalid user\s+)?(\S+)', message)
            username = user_match.group(1) if user_match else None
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                source=Path(source).name,
                source_ip=source_ip,
                username=username,
                message=message,
            )
        except Exception:
            return None
