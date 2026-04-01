"""
Abstract base class for all threat detectors.
Every detector receives a list of NormalizedEvents and returns ThreatCandidates.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Any


@dataclass
class ThreatCandidate:
    """A potential threat identified by a detector, before AI analysis."""
    event: Any                          # The raw NormalizedEvent that triggered this
    detector: str                       # Name of the detector that flagged it
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW
    anomaly_score: Optional[float]      # Float score (lower = more anomalous) or None for rule-based
    rule_name: Optional[str]            # Populated for signature-based detections
    description: str                    # Human-readable description of why this was flagged
    source_ip: Optional[str] = None
    tags: List[str] = field(default_factory=list)  # e.g., ["brute_force", "ssh"]


class BaseDetector(ABC):
    """Abstract base class that all detectors must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this detector."""

    @abstractmethod
    def detect(self, events: List[Any]) -> List[ThreatCandidate]:
        """
        Analyze a batch of NormalizedEvents and return any threat candidates.

        Args:
            events: List of NormalizedEvent objects to analyze

        Returns:
            List of ThreatCandidate objects for any suspicious events
        """
