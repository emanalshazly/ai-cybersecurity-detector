"""
Claude AI analyst — the intelligence core of the cybersecurity agent.
Uses Claude claude-opus-4-6 with adaptive thinking and tool-use to investigate threats.

Each call to investigate() runs a multi-turn tool-use loop:
  Claude receives the alert → calls tools to gather context → produces analysis + recommendations.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Any

import anthropic

from .tool_registry import get_tool_definitions, ToolExecutor
from config import get_config

logger = logging.getLogger("ClaudeAnalyst")

SYSTEM_PROMPT = """You are an expert cybersecurity analyst AI with deep knowledge of:
- Network intrusion detection and MITRE ATT&CK framework
- Web application attacks (OWASP Top 10, injection, authentication bypass)
- Brute force and credential stuffing detection
- Data exfiltration and insider threat patterns
- Incident response and triage procedures

You have access to tools to query the alert database and gather context.
Your job is to investigate security alerts and produce:
1. A concise, actionable threat assessment (2-4 sentences)
2. Confidence level (HIGH/MEDIUM/LOW) — is this a real threat or likely false positive?
3. A list of specific recommended actions, prioritized by urgency

Be direct and concise. Security teams are busy — give them what they need to act, not essays.
When assessing confidence, consider: Is the pattern consistent with a real attack? Could this be legitimate use?
Always use tools to gather context before concluding — never judge on a single data point."""


@dataclass
class AnalysisResult:
    alert_id: str
    threat_assessment: str           # 2-4 sentence narrative
    confidence: str                  # HIGH / MEDIUM / LOW
    is_likely_false_positive: bool
    recommended_actions: List[str]
    mitre_tactics: List[str] = field(default_factory=list)
    raw_response: Optional[str] = None


class ClaudeAnalyst:
    """
    Wraps the Anthropic API with a tool-use investigation loop.
    Uses claude-opus-4-6 with adaptive thinking for deep threat reasoning.
    """

    def __init__(
        self,
        alert_store=None,
        recent_events_cache: list = None,
        campaign_tracker=None,
        ueba_detector=None,
    ):
        cfg = get_config()
        if not cfg.anthropic_api_key:
            logger.warning("ANTHROPIC_API_KEY not set — Claude analysis disabled")
        self.client = anthropic.Anthropic(api_key=cfg.anthropic_api_key) if cfg.anthropic_api_key else None
        self.model = cfg.claude_model
        self.tools = get_tool_definitions()
        self.executor = ToolExecutor(
            alert_store=alert_store,
            recent_events_cache=recent_events_cache or [],
            campaign_tracker=campaign_tracker,
            ueba_detector=ueba_detector,
        )

    def investigate(self, alert_id: str, threat_candidate: Any) -> AnalysisResult:
        """
        Investigate a ThreatCandidate using Claude with tool-use.
        Runs a multi-turn loop until Claude produces a final assessment.

        Returns AnalysisResult with threat narrative and recommended actions.
        """
        if not self.client:
            return self._offline_analysis(alert_id, threat_candidate)

        # Build initial message describing the alert
        event = threat_candidate.event
        raw = event.to_dict() if hasattr(event, "to_dict") else (event if isinstance(event, dict) else vars(event))

        user_message = self._format_alert_message(alert_id, threat_candidate, raw)
        messages = [{"role": "user", "content": user_message}]

        logger.info(f"Investigating alert {alert_id} ({threat_candidate.severity}) via Claude")

        # Agentic tool-use loop
        max_iterations = 6  # Prevent runaway loops
        for iteration in range(max_iterations):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    thinking={"type": "adaptive"},
                    system=SYSTEM_PROMPT,
                    tools=self.tools,
                    messages=messages,
                )
            except anthropic.APIError as e:
                logger.error(f"Claude API error during investigation: {e}")
                return self._offline_analysis(alert_id, threat_candidate)

            # Append assistant response to conversation
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                # Claude is done — extract the final text response
                final_text = self._extract_text(response.content)
                return self._parse_analysis(alert_id, final_text, threat_candidate)

            if response.stop_reason == "tool_use":
                # Execute tool calls and feed results back
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        logger.debug(f"Claude calling tool: {block.name}({block.input})")
                        result = self.executor.execute(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })
                if tool_results:
                    messages.append({"role": "user", "content": tool_results})
                continue

            # Unexpected stop reason
            break

        # Fallback if loop exhausted
        final_text = self._extract_text(messages[-1]["content"]) if messages else ""
        return self._parse_analysis(alert_id, final_text or "Investigation incomplete.", threat_candidate)

    def _format_alert_message(self, alert_id: str, candidate: Any, raw: dict) -> str:
        return f"""Investigate this security alert and determine if it represents a real threat.

**Alert ID**: {alert_id}
**Severity**: {candidate.severity}
**Detector**: {candidate.detector}
**Rule/Pattern**: {candidate.rule_name or 'ML Anomaly Detection'}
**Description**: {candidate.description}
**Source IP**: {candidate.source_ip or 'Unknown'}
**Anomaly Score**: {candidate.anomaly_score:.4f if candidate.anomaly_score is not None else 'N/A'}
**Tags**: {', '.join(candidate.tags)}

**Raw Event Data**:
```json
{json.dumps(raw, indent=2, default=str)}
```

Use the available tools to:
1. Check if this IP has prior alerts
2. Look for related events in the same time window
3. Check the attack pattern context if a rule name is available
4. Assess the overall threat level

Then provide your assessment."""

    def _extract_text(self, content) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if hasattr(block, "type") and block.type == "text":
                    parts.append(block.text)
                elif isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            return "\n".join(parts)
        return str(content)

    def _parse_analysis(self, alert_id: str, text: str, candidate: Any) -> AnalysisResult:
        """Parse Claude's response into a structured AnalysisResult."""
        text_lower = text.lower()

        # Confidence detection
        if "high confidence" in text_lower or "definitely" in text_lower or "confirmed" in text_lower:
            confidence = "HIGH"
        elif "low confidence" in text_lower or "likely false positive" in text_lower or "probably not" in text_lower:
            confidence = "LOW"
        else:
            confidence = "MEDIUM"

        # False positive detection
        is_fp = any(phrase in text_lower for phrase in [
            "false positive", "likely legitimate", "normal behavior",
            "not a threat", "no threat", "benign"
        ])

        # Extract recommended actions (look for numbered lists or bullet points)
        actions = []
        import re
        action_patterns = [
            r'(?:^|\n)\s*(?:\d+\.|[-*•])\s*(.+)',  # numbered or bulleted lists
            r'(?:recommend|action|should|must|immediately).*?:\s*(.+)',
        ]
        for pattern in action_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            for m in matches:
                action = m.strip()
                if len(action) > 10 and action not in actions:
                    actions.append(action)

        # Default action if none found
        if not actions:
            if candidate.severity in ("CRITICAL", "HIGH"):
                actions = [f"Investigate source IP {candidate.source_ip}", "Review related logs"]
            else:
                actions = ["Monitor for continued activity"]

        return AnalysisResult(
            alert_id=alert_id,
            threat_assessment=text[:2000] if text else "Analysis unavailable",
            confidence=confidence,
            is_likely_false_positive=is_fp,
            recommended_actions=actions[:6],
            raw_response=text,
        )

    def _offline_analysis(self, alert_id: str, candidate: Any) -> AnalysisResult:
        """Fallback analysis when Claude API is unavailable."""
        severity_actions = {
            "CRITICAL": [
                f"URGENT: Block source IP {candidate.source_ip} immediately",
                "Escalate to security team",
                "Preserve logs for forensic investigation",
            ],
            "HIGH": [
                f"Block or rate-limit source IP {candidate.source_ip}",
                "Review related logs from same IP",
                "Notify security team",
            ],
            "MEDIUM": [
                f"Monitor source IP {candidate.source_ip} for continued activity",
                "Add to watchlist",
            ],
            "LOW": ["Log for trend analysis", "Monitor"],
        }
        return AnalysisResult(
            alert_id=alert_id,
            threat_assessment=(
                f"[Offline Analysis] {candidate.severity} severity alert from {candidate.source_ip}. "
                f"Pattern: {candidate.rule_name or 'ML anomaly'}. "
                f"Description: {candidate.description}. "
                f"Claude AI analysis unavailable — check ANTHROPIC_API_KEY."
            ),
            confidence="MEDIUM",
            is_likely_false_positive=False,
            recommended_actions=severity_actions.get(candidate.severity, ["Monitor"]),
        )
