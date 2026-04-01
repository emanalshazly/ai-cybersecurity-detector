"""
Base ingestor and NormalizedEvent schema.

IMPORTANT: Every ingestor MUST normalize its output to NormalizedEvent.
This is the contract that all detectors depend on.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class NormalizedEvent:
    """
    Common schema for all ingested security events.
    Every data source maps its fields into this structure.
    """
    # Core fields (always populated)
    event_id: str
    timestamp: datetime
    source: str                         # Origin: "nginx_access", "auth.log", "mock", etc.

    # Network / HTTP fields
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None

    # HTTP-specific
    request_type: Optional[str] = None  # GET, POST, PUT, DELETE, etc.
    endpoint: Optional[str] = None
    response_code: Optional[int] = None
    response_time: Optional[float] = None   # seconds
    request_size: Optional[int] = None      # bytes
    response_size: Optional[int] = None     # bytes
    user_agent: Optional[str] = None

    # Auth / system
    username: Optional[str] = None
    message: Optional[str] = None          # Raw log message or description

    # Extra context
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "request_type": self.request_type,
            "endpoint": self.endpoint,
            "response_code": self.response_code,
            "response_time": self.response_time,
            "request_size": self.request_size,
            "response_size": self.response_size,
            "user_agent": self.user_agent,
            "username": self.username,
            "message": self.message,
            **self.extra,
        }


class BaseIngestor(ABC):
    """Abstract base class for all ingestors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this ingestor."""

    @abstractmethod
    def poll(self) -> List[NormalizedEvent]:
        """
        Fetch new events since the last call.
        Must be safe to call repeatedly — should track its own read position.

        Returns:
            List of new NormalizedEvent objects (may be empty)
        """

    def normalize(self, raw: Any) -> Optional[NormalizedEvent]:
        """
        Convert a raw data item to a NormalizedEvent.
        Subclasses implement their source-specific parsing here.
        Returns None if the item cannot be parsed.
        """
        return None
