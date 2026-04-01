"""
User/Entity Behavior Analytics (UEBA) detector.
Builds a per-IP behavioral baseline using Welford's online algorithm
(numerically stable running mean/variance without storing all history).

An IP is flagged when its current behavior deviates >3σ from its own
historical baseline — not from the global average. This eliminates FPs
on legitimate power users who make many requests.
"""

import logging
import math
from collections import defaultdict
from datetime import datetime
from typing import List, Any, Dict, Optional

from .base_detector import BaseDetector, ThreatCandidate

logger = logging.getLogger("UEBADetector")

# Minimum observations before a baseline is considered reliable
MIN_OBSERVATIONS = 30

# Deviation threshold (z-score)
ZSCORE_THRESHOLD = 3.0


class _WelfordStats:
    """
    Online mean and variance using Welford's algorithm.
    Numerically stable, O(1) memory, no need to store raw values.
    """
    __slots__ = ("n", "mean", "M2")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.M2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        return self.M2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float:
        if self.std == 0 or self.n < MIN_OBSERVATIONS:
            return 0.0
        return abs(value - self.mean) / self.std


class _EntityProfile:
    """Per-entity (IP address) behavioral baseline."""

    def __init__(self, ip: str):
        self.ip = ip
        self.request_size = _WelfordStats()
        self.response_time = _WelfordStats()
        self.hourly_request_rate = _WelfordStats()  # requests per hour slot
        self._current_hour: Optional[int] = None
        self._hour_count = 0
        self.total_requests = 0
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None

    def update(self, event: dict, ts: datetime) -> None:
        self.total_requests += 1
        if not self.first_seen:
            self.first_seen = ts
        self.last_seen = ts

        if event.get("request_size") is not None:
            try:
                self.request_size.update(float(event["request_size"]))
            except (TypeError, ValueError):
                pass

        if event.get("response_time") is not None:
            try:
                self.response_time.update(float(event["response_time"]))
            except (TypeError, ValueError):
                pass

        hour = ts.hour
        if self._current_hour is None:
            self._current_hour = hour
            self._hour_count = 1
        elif hour == self._current_hour:
            self._hour_count += 1
        else:
            self.hourly_request_rate.update(float(self._hour_count))
            self._current_hour = hour
            self._hour_count = 1

    def anomaly_scores(self, event: dict) -> Dict[str, float]:
        """Return z-scores for each behavioral dimension."""
        scores = {}
        if event.get("request_size") is not None and self.request_size.n >= MIN_OBSERVATIONS:
            try:
                scores["request_size"] = self.request_size.zscore(float(event["request_size"]))
            except (TypeError, ValueError):
                pass
        if event.get("response_time") is not None and self.response_time.n >= MIN_OBSERVATIONS:
            try:
                scores["response_time"] = self.response_time.zscore(float(event["response_time"]))
            except (TypeError, ValueError):
                pass
        return scores

    def is_reliable(self) -> bool:
        return self.total_requests >= MIN_OBSERVATIONS


class UEBADetector(BaseDetector):
    """
    Detects anomalies by comparing each entity's current behavior
    to its own historical baseline (not to all other entities).
    """

    def __init__(self, zscore_threshold: float = ZSCORE_THRESHOLD):
        self.threshold = zscore_threshold
        self._profiles: Dict[str, _EntityProfile] = defaultdict(lambda: _EntityProfile(""))

    @property
    def name(self) -> str:
        return "UEBADetector"

    def detect(self, events: List[Any]) -> List[ThreatCandidate]:
        candidates = []

        for event in events:
            raw = event.__dict__ if hasattr(event, "__dict__") else event
            ip = raw.get("source_ip")
            if not ip:
                continue

            ts = raw.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    ts = datetime.utcnow()
            elif not isinstance(ts, datetime):
                ts = datetime.utcnow()

            profile = self._profiles[ip]
            if not profile.ip:
                profile.ip = ip

            # Score BEFORE updating (we want to measure against past baseline)
            if profile.is_reliable():
                scores = profile.anomaly_scores(raw)
                max_score = max(scores.values(), default=0.0)

                if max_score >= self.threshold:
                    dimension = max(scores, key=scores.get)
                    severity = self._zscore_to_severity(max_score)
                    candidates.append(ThreatCandidate(
                        event=event,
                        detector=self.name,
                        severity=severity,
                        anomaly_score=-max_score / 10.0,  # Normalize to Isolation Forest range
                        rule_name=f"ueba_{dimension}_anomaly",
                        description=(
                            f"UEBA: {ip} {dimension} is {max_score:.1f}σ above its own baseline "
                            f"(mean={getattr(profile, dimension).mean:.1f}, "
                            f"std={getattr(profile, dimension).std:.1f})"
                        ),
                        source_ip=ip,
                        tags=["ueba", "behavioral", dimension],
                    ))

            # Now update the baseline with this event
            profile.update(raw, ts)

        return candidates

    def _zscore_to_severity(self, zscore: float) -> str:
        if zscore >= 6.0:
            return "CRITICAL"
        elif zscore >= 4.5:
            return "HIGH"
        elif zscore >= 3.0:
            return "MEDIUM"
        return "LOW"

    def get_profile(self, ip: str) -> Optional[dict]:
        """Return baseline stats for an IP (for dashboard display)."""
        if ip not in self._profiles:
            return None
        p = self._profiles[ip]
        return {
            "ip": ip,
            "total_requests": p.total_requests,
            "first_seen": p.first_seen.isoformat() if p.first_seen else None,
            "last_seen": p.last_seen.isoformat() if p.last_seen else None,
            "baseline_reliable": p.is_reliable(),
            "request_size_mean": round(p.request_size.mean, 1),
            "request_size_std": round(p.request_size.std, 1),
            "response_time_mean": round(p.response_time.mean, 3),
            "response_time_std": round(p.response_time.std, 3),
        }

    def get_all_profiles(self) -> List[dict]:
        return [self.get_profile(ip) for ip in self._profiles]
