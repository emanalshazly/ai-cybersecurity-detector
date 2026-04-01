"""
Stateful (threshold-based) detector.
Fixes the core weakness of the per-event signature detector:
brute force, scanning, and DoS are only meaningful over a TIME WINDOW,
not as individual events.

Uses per-IP rolling counters with a configurable time window.
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Deque, Tuple, Any

from .base_detector import BaseDetector, ThreatCandidate

logger = logging.getLogger("StatefulDetector")


class _RollingCounter:
    """Track event counts within a sliding time window."""

    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self._events: Deque[datetime] = deque()

    def add(self, ts: datetime = None) -> None:
        ts = ts or datetime.utcnow()
        self._events.append(ts)
        self._evict(ts)

    def count(self) -> int:
        self._evict(datetime.utcnow())
        return len(self._events)

    def _evict(self, now: datetime) -> None:
        cutoff = now - self.window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


class StatefulDetector(BaseDetector):
    """
    Threshold-based detector that tracks per-IP state over a rolling window.

    Detects:
    - HTTP brute force: ≥10 401/403 from same IP in 5 minutes
    - SSH brute force:  ≥5  failed auths from same IP in 5 minutes
    - Directory scan:   ≥15 404s from same IP in 2 minutes
    - DoS indicator:    ≥20 5xx from same IP in 1 minute
    - High request rate: ≥100 requests from same IP in 1 minute
    """

    # (counter_key, window_seconds, threshold, severity, rule_name, description)
    RULES: List[Tuple] = [
        ("auth_fail",    300, 10,  "HIGH",     "http_brute_force_stateful",
         "Brute force: ≥10 failed auth attempts in 5 minutes"),
        ("ssh_fail",     300,  5,  "HIGH",     "ssh_brute_force_stateful",
         "Brute force: ≥5 SSH authentication failures in 5 minutes"),
        ("not_found",    120, 15,  "MEDIUM",   "directory_scan_stateful",
         "Directory scan: ≥15 HTTP 404s in 2 minutes"),
        ("server_error",  60, 20,  "HIGH",     "dos_indicator_stateful",
         "DoS indicator: ≥20 HTTP 5xx errors in 1 minute"),
        ("request_total", 60, 100, "MEDIUM",   "high_request_rate",
         "High request rate: ≥100 requests in 1 minute"),
    ]

    def __init__(self):
        # counters[ip][counter_key] → _RollingCounter
        self._counters: dict = defaultdict(lambda: defaultdict(_RollingCounter))
        # Track which windows each counter uses
        self._windows = {
            "auth_fail":    300,
            "ssh_fail":     300,
            "not_found":    120,
            "server_error":  60,
            "request_total": 60,
        }

    @property
    def name(self) -> str:
        return "StatefulDetector"

    def detect(self, events: List[Any]) -> List[ThreatCandidate]:
        candidates = []
        triggered: set = set()  # (ip, rule_name) — one alert per window

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

            code = raw.get("response_code") or 0
            msg = raw.get("message") or ""

            # Classify event into counter buckets
            if code in (401, 403):
                self._tick(ip, "auth_fail", 300, ts)
            if "Failed password" in msg or "authentication failure" in msg.lower():
                self._tick(ip, "ssh_fail", 300, ts)
            if code == 404:
                self._tick(ip, "not_found", 120, ts)
            if code >= 500:
                self._tick(ip, "server_error", 60, ts)
            self._tick(ip, "request_total", 60, ts)

            # Check all rules for this IP
            for counter_key, window, threshold, severity, rule_name, description in self.RULES:
                alert_key = (ip, rule_name)
                if alert_key in triggered:
                    continue
                counter = self._counters[ip][counter_key]
                if counter.count() >= threshold:
                    triggered.add(alert_key)
                    candidates.append(ThreatCandidate(
                        event=event,
                        detector=self.name,
                        severity=severity,
                        anomaly_score=None,
                        rule_name=rule_name,
                        description=f"{description} (count={counter.count()})",
                        source_ip=ip,
                        tags=["stateful", "threshold", rule_name.split("_")[0]],
                    ))

        return candidates

    def _tick(self, ip: str, key: str, window: int, ts: datetime) -> None:
        """Increment a rolling counter, creating it with correct window if needed."""
        if key not in self._counters[ip]:
            self._counters[ip][key] = _RollingCounter(window)
        self._counters[ip][key].add(ts)

    def get_ip_stats(self, ip: str) -> dict:
        """Return current counter values for an IP (useful for dashboard)."""
        if ip not in self._counters:
            return {}
        return {k: v.count() for k, v in self._counters[ip].items()}
