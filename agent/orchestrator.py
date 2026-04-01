"""
Security Orchestrator — the main agent loop.
Wires together: ingestors → detectors → Claude analyst → response engine.

Runs continuously on a configurable polling interval.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import List, Optional

from config import get_config
from ingestors.base_ingestor import BaseIngestor, NormalizedEvent
from detectors.base_detector import BaseDetector, ThreatCandidate
from detectors.isolation_forest import IsolationForestDetector
from detectors.signature_detector import SignatureDetector
from storage.alert_store import AlertStore, Alert, AlertStatus
from agent.claude_analyst import ClaudeAnalyst
from response.approval_gate import ApprovalGate, ActionTier

logger = logging.getLogger("SecurityOrchestrator")


class SecurityOrchestrator:
    """
    Central agent loop: poll → detect → analyze → respond.

    Usage:
        orchestrator = SecurityOrchestrator(ingestors=[MockIngestor()])
        await orchestrator.run()          # Run indefinitely
        await orchestrator.run_once()     # Single poll cycle (for testing)
    """

    def __init__(
        self,
        ingestors: List[BaseIngestor],
        detectors: Optional[List[BaseDetector]] = None,
        alert_store: Optional[AlertStore] = None,
        on_alert=None,  # Callback: async fn(alert: Alert, analysis: AnalysisResult)
    ):
        self.cfg = get_config()
        self.ingestors = ingestors
        self.alert_store = alert_store or AlertStore()
        self._running = False
        self._recent_events: List[NormalizedEvent] = []
        self._max_event_cache = 1000

        # Detectors
        self.detectors = detectors or [
            IsolationForestDetector(),
            SignatureDetector(),
        ]

        # Claude analyst (shares the event cache for tool lookups)
        self.analyst = ClaudeAnalyst(
            alert_store=self.alert_store,
            recent_events_cache=self._recent_events,
        )

        # Approval gate (handles response action tiers)
        self.approval_gate = ApprovalGate(alert_store=self.alert_store)

        # Optional callback for external notification
        self.on_alert = on_alert

        logger.info(
            f"Orchestrator initialized: {len(self.ingestors)} ingestor(s), "
            f"{len(self.detectors)} detector(s)"
        )

    async def run(self) -> None:
        """Run the agent loop indefinitely."""
        self._running = True
        logger.info(f"Agent loop started — polling every {self.cfg.poll_interval_seconds}s")
        while self._running:
            try:
                await self.run_once()
            except Exception as e:
                logger.error(f"Error in agent loop: {e}", exc_info=True)
            await asyncio.sleep(self.cfg.poll_interval_seconds)

    def stop(self) -> None:
        self._running = False
        logger.info("Agent loop stopping")

    async def run_once(self) -> List[Alert]:
        """
        Execute one full poll cycle.
        Returns list of Alert objects created in this cycle.
        """
        # 1. Ingest new events
        events = self._collect_events()
        if not events:
            return []

        logger.info(f"Collected {len(events)} new events")

        # 2. Update event cache (for tool lookups)
        self._recent_events.extend(events)
        if len(self._recent_events) > self._max_event_cache:
            self._recent_events = self._recent_events[-self._max_event_cache:]

        # 3. Run detectors
        candidates = self._run_detectors(events)
        if not candidates:
            return []

        logger.info(f"Detectors flagged {len(candidates)} threat candidates")

        # 4. Deduplicate and filter by severity
        candidates = self._filter_candidates(candidates)

        # 5. Persist as alerts + run Claude analysis
        created_alerts = []
        for candidate in candidates:
            alert = await self._process_candidate(candidate)
            if alert:
                created_alerts.append(alert)

        if created_alerts:
            logger.info(f"Created {len(created_alerts)} alerts this cycle")

        return created_alerts

    def _collect_events(self) -> List[NormalizedEvent]:
        events = []
        for ingestor in self.ingestors:
            try:
                new_events = ingestor.poll()
                events.extend(new_events)
            except Exception as e:
                logger.error(f"Ingestor {ingestor.name} failed: {e}")
        return events

    def _run_detectors(self, events: List[NormalizedEvent]) -> List[ThreatCandidate]:
        candidates = []
        event_dicts = [e.to_dict() for e in events]
        for detector in self.detectors:
            try:
                if isinstance(detector, IsolationForestDetector):
                    found = detector.detect(event_dicts)
                else:
                    found = detector.detect(events)
                candidates.extend(found)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed: {e}")
        return candidates

    def _filter_candidates(self, candidates: List[ThreatCandidate]) -> List[ThreatCandidate]:
        """Remove duplicates and apply severity filter."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = severity_order.get(self.cfg.alert_min_severity, 1)

        # Filter by minimum severity
        filtered = [c for c in candidates if severity_order.get(c.severity, 0) >= min_level]

        # Deduplicate by (source_ip, rule_name) — keep highest severity
        seen: dict = {}
        for c in sorted(filtered, key=lambda x: severity_order.get(x.severity, 0), reverse=True):
            key = (c.source_ip or "unknown", c.rule_name or c.detector)
            if key not in seen:
                seen[key] = c

        return list(seen.values())

    async def _process_candidate(self, candidate: ThreatCandidate) -> Optional[Alert]:
        """Persist a threat candidate as an alert and run Claude analysis."""
        alert_id = f"ALERT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8].upper()}"

        event = candidate.event
        raw = event if isinstance(event, dict) else (event.to_dict() if hasattr(event, "to_dict") else vars(event))

        alert = Alert(
            id=alert_id,
            timestamp=datetime.utcnow(),
            severity=candidate.severity,
            anomaly_score=candidate.anomaly_score,
            source_ip=candidate.source_ip,
            source=getattr(event, "source", "unknown"),
            detector=candidate.detector,
            rule_name=candidate.rule_name,
            event_details=json.dumps(raw, default=str),
            status=AlertStatus.NEW,
        )
        self.alert_store.save_alert(alert)
        logger.warning(
            f"[{alert.severity}] {alert_id} | "
            f"IP={alert.source_ip} | "
            f"Rule={alert.rule_name or 'anomaly'} | "
            f"{candidate.description}"
        )

        # Run Claude analysis for HIGH and CRITICAL alerts
        if candidate.severity in self.cfg.auto_investigate_severities:
            try:
                analysis = self.analyst.investigate(alert_id, candidate)
                self.alert_store.update_analysis(
                    alert_id,
                    analysis.threat_assessment,
                    analysis.recommended_actions,
                )
                alert.analysis = analysis.threat_assessment

                if analysis.is_likely_false_positive:
                    logger.info(f"Claude assessed {alert_id} as likely false positive")
                else:
                    # Dispatch response actions through the approval gate
                    await self.approval_gate.evaluate(alert, analysis, candidate)

            except Exception as e:
                logger.error(f"Analysis failed for {alert_id}: {e}")

        # Fire external callback if provided
        if self.on_alert:
            try:
                await self.on_alert(alert)
            except Exception as e:
                logger.error(f"on_alert callback failed: {e}")

        return alert
