"""
Security Orchestrator — the main agent loop.
Wires together: ingestors → detectors → analyst → campaign tracker → response.

Enhancement integrations:
  - StatefulDetector: threshold-based brute force / DoS detection
  - UEBADetector: per-entity behavioral baselines
  - CampaignTracker: groups related alerts into campaigns
  - FeedbackLoop: retrains the ML model from analyst-labeled data
  - Dashboard push: broadcasts new alerts to WebSocket clients
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
from detectors.stateful_detector import StatefulDetector
from detectors.ueba_detector import UEBADetector
from storage.alert_store import AlertStore, Alert, AlertStatus
from storage.feedback_loop import FeedbackLoop
from agent.claude_analyst import ClaudeAnalyst
from agent.tool_registry import ToolExecutor
from correlation.campaign_tracker import CampaignTracker
from response.approval_gate import ApprovalGate

logger = logging.getLogger("SecurityOrchestrator")

# Import MITRE mapping directly (avoid circular imports)
_RULE_TO_MITRE = {
    "sql_injection":              ("Initial Access", "T1190"),
    "path_traversal":             ("Initial Access", "T1190"),
    "xss_attempt":                ("Initial Access", "T1059"),
    "http_brute_force":           ("Credential Access", "T1110.003"),
    "http_brute_force_stateful":  ("Credential Access", "T1110.003"),
    "ssh_brute_force":            ("Credential Access", "T1110"),
    "ssh_brute_force_stateful":   ("Credential Access", "T1110"),
    "directory_scan":             ("Discovery", "T1083"),
    "directory_scan_stateful":    ("Discovery", "T1083"),
    "suspicious_user_agent":      ("Reconnaissance", "T1592"),
    "large_outbound_transfer":    ("Exfiltration", "T1048"),
    "large_upload":               ("Exfiltration", "T1048"),
    "server_error_spike":         ("Impact", "T1499"),
    "dos_indicator_stateful":     ("Impact", "T1499"),
    "high_request_rate":          ("Impact", "T1499"),
    "slow_response":              ("Impact", "T1499"),
}


class SecurityOrchestrator:
    """
    Central agent loop: poll → detect → analyze → respond.

    Usage:
        orchestrator = SecurityOrchestrator(ingestors=[MockIngestor()])
        await orchestrator.run()
        await orchestrator.run_once()
    """

    def __init__(
        self,
        ingestors: List[BaseIngestor],
        detectors: Optional[List[BaseDetector]] = None,
        alert_store: Optional[AlertStore] = None,
        dashboard_manager=None,   # WebSocket manager for live push
    ):
        self.cfg = get_config()
        self.ingestors = ingestors
        self.alert_store = alert_store or AlertStore()
        self._running = False
        self._recent_events: List[NormalizedEvent] = []
        self._max_event_cache = 2000
        self._cycle_count = 0

        # Build default detector stack if none provided
        self._iso_detector = IsolationForestDetector()
        self._ueba_detector = UEBADetector()
        self.detectors = detectors or [
            self._iso_detector,
            SignatureDetector(),
            StatefulDetector(),
            self._ueba_detector,
        ]

        # Campaign tracker
        self.campaign_tracker = CampaignTracker()

        # Feedback loop (retrains ML from FP labels)
        self.feedback_loop = FeedbackLoop(
            alert_store=self.alert_store,
            isolation_forest_detector=self._iso_detector,
            model_path=self.cfg.model_path,
        )

        # Claude analyst — passes campaign tracker + UEBA for tool context
        self.analyst = ClaudeAnalyst(
            alert_store=self.alert_store,
            recent_events_cache=self._recent_events,
            campaign_tracker=self.campaign_tracker,
            ueba_detector=self._ueba_detector,
        )

        # Approval gate
        self.approval_gate = ApprovalGate(alert_store=self.alert_store)

        # Dashboard WebSocket manager (optional)
        self._dashboard_manager = dashboard_manager

        logger.info(
            f"Orchestrator initialized: {len(self.ingestors)} ingestor(s), "
            f"{len(self.detectors)} detector(s)"
        )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

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
        """Execute one full poll cycle. Returns alerts created this cycle."""
        self._cycle_count += 1

        # 1. Ingest
        events = self._collect_events()
        if not events:
            return []
        logger.info(f"[Cycle {self._cycle_count}] Collected {len(events)} events")

        # 2. Update event cache
        self._recent_events.extend(events)
        if len(self._recent_events) > self._max_event_cache:
            self._recent_events = self._recent_events[-self._max_event_cache:]

        # 3. Detect
        candidates = self._run_detectors(events)
        if not candidates:
            # Still check feedback loop periodically
            if self._cycle_count % 10 == 0:
                self.feedback_loop.retrain_if_ready()
            return []

        logger.info(f"Detectors flagged {len(candidates)} threat candidates")

        # 4. Deduplicate + filter
        candidates = self._filter_candidates(candidates)

        # 5. Process each candidate
        created_alerts = []
        for candidate in candidates:
            alert = await self._process_candidate(candidate)
            if alert:
                created_alerts.append(alert)

        # 6. Prune stale campaigns every 10 cycles
        if self._cycle_count % 10 == 0:
            pruned = self.campaign_tracker.prune_old_campaigns()
            if pruned:
                logger.info(f"Archived {pruned} stale campaigns")
            self.feedback_loop.retrain_if_ready()

        if created_alerts:
            logger.info(f"Created {len(created_alerts)} alerts this cycle")

        return created_alerts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_events(self) -> List[NormalizedEvent]:
        events = []
        for ingestor in self.ingestors:
            try:
                events.extend(ingestor.poll())
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
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = severity_order.get(self.cfg.alert_min_severity, 1)
        filtered = [c for c in candidates if severity_order.get(c.severity, 0) >= min_level]
        # Dedup by (ip, rule) — keep highest severity
        seen: dict = {}
        for c in sorted(filtered, key=lambda x: severity_order.get(x.severity, 0), reverse=True):
            key = (c.source_ip or "unknown", c.rule_name or c.detector)
            if key not in seen:
                seen[key] = c
        return list(seen.values())

    async def _process_candidate(self, candidate: ThreatCandidate) -> Optional[Alert]:
        alert_id = f"ALERT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8].upper()}"

        event = candidate.event
        raw = event if isinstance(event, dict) else (
            event.to_dict() if hasattr(event, "to_dict") else vars(event)
        )

        # MITRE tagging
        mitre_tactic, mitre_technique = _RULE_TO_MITRE.get(
            candidate.rule_name or "", ("", "")
        )

        alert = Alert(
            id=alert_id,
            timestamp=datetime.utcnow(),
            severity=candidate.severity,
            anomaly_score=candidate.anomaly_score,
            source_ip=candidate.source_ip,
            source=getattr(event, "source", "unknown") if not isinstance(event, dict) else event.get("source", "unknown"),
            detector=candidate.detector,
            rule_name=candidate.rule_name,
            event_details=json.dumps(raw, default=str),
            status=AlertStatus.NEW,
            mitre_tactic=mitre_tactic or None,
            mitre_technique=mitre_technique or None,
        )
        self.alert_store.save_alert(alert)

        # Assign to campaign
        campaign = self.campaign_tracker.link_alert(alert)
        if campaign:
            self.alert_store.update_campaign(alert_id, campaign.id)
            logger.info(f"Alert {alert_id} → Campaign {campaign.id} ({campaign.alert_count} alerts)")

        logger.warning(
            f"[{alert.severity}] {alert_id} | IP={alert.source_ip} | "
            f"Rule={alert.rule_name or 'anomaly'} | MITRE={mitre_tactic or '?'}"
        )

        # Claude analysis for HIGH/CRITICAL
        if candidate.severity in self.cfg.auto_investigate_severities:
            try:
                analysis = self.analyst.investigate(alert_id, candidate)
                self.alert_store.update_analysis(
                    alert_id, analysis.threat_assessment, analysis.recommended_actions
                )
                alert.analysis = analysis.threat_assessment

                if not analysis.is_likely_false_positive:
                    await self.approval_gate.evaluate(alert, analysis, candidate)
                else:
                    logger.info(f"Claude assessed {alert_id} as likely false positive")
            except Exception as e:
                logger.error(f"Analysis failed for {alert_id}: {e}")

        # Push to dashboard WebSocket
        if self._dashboard_manager:
            try:
                await self._dashboard_manager.broadcast({
                    "type": "new_alert",
                    "alert": alert.to_dict(),
                })
            except Exception:
                pass

        return alert
