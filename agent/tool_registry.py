"""
Tool definitions exposed to the Claude analyst via function-calling.
Claude uses these tools to actively investigate threats rather than
passively receiving data dumps.
"""

import json
import logging
from typing import Any

logger = logging.getLogger("ToolRegistry")


def get_tool_definitions() -> list:
    """Return all tool schemas for the Claude API tool_use parameter."""
    return [
        {
            "name": "get_recent_alerts_for_ip",
            "description": (
                "Look up recent security alerts for a specific IP address from the alert database. "
                "Use this to determine if an IP is a repeat offender or part of a sustained campaign."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to look up (e.g., '192.168.1.10')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of recent alerts to return (default: 10)",
                    }
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "get_alert_statistics",
            "description": (
                "Retrieve overall statistics about recent alerts: counts by severity, "
                "top attacking IPs, false positive rate, and detection trends."
            ),
            "input_schema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "get_related_events",
            "description": (
                "Find other events from the same IP address, same endpoint, or within the same "
                "time window as the current alert. Use this to identify coordinated attacks "
                "or correlate events that belong to the same campaign."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "description": "IP address to find related events for"
                    },
                    "time_window_minutes": {
                        "type": "integer",
                        "description": "How many minutes back to look for related events (default: 60)"
                    }
                },
                "required": ["source_ip"],
            },
        },
        {
            "name": "check_ip_reputation",
            "description": (
                "Check basic reputation indicators for an IP address based on local threat intelligence: "
                "known bad actor lists, prior alert history, geographic location context."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to check"
                    }
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "get_attack_pattern_context",
            "description": (
                "Look up contextual information about a specific attack pattern or rule name, "
                "including MITRE ATT&CK mapping, typical attacker goals, and recommended responses."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "rule_name": {
                        "type": "string",
                        "description": "The detection rule name (e.g., 'sql_injection', 'ssh_brute_force')"
                    }
                },
                "required": ["rule_name"],
            },
        },
    ]


class ToolExecutor:
    """Executes tool calls made by the Claude analyst."""

    def __init__(self, alert_store=None, recent_events_cache: list = None):
        self.alert_store = alert_store
        self.recent_events_cache = recent_events_cache or []

    def execute(self, tool_name: str, tool_input: dict) -> str:
        """Dispatch a tool call and return a JSON string result."""
        try:
            if tool_name == "get_recent_alerts_for_ip":
                return self._get_recent_alerts_for_ip(**tool_input)
            elif tool_name == "get_alert_statistics":
                return self._get_alert_statistics()
            elif tool_name == "get_related_events":
                return self._get_related_events(**tool_input)
            elif tool_name == "check_ip_reputation":
                return self._check_ip_reputation(**tool_input)
            elif tool_name == "get_attack_pattern_context":
                return self._get_attack_pattern_context(**tool_input)
            else:
                return json.dumps({"error": f"Unknown tool: {tool_name}"})
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return json.dumps({"error": str(e)})

    def _get_recent_alerts_for_ip(self, ip_address: str, limit: int = 10) -> str:
        if self.alert_store:
            alerts = self.alert_store.get_recent_alerts_for_ip(ip_address, limit=limit)
            return json.dumps({
                "ip_address": ip_address,
                "alert_count": len(alerts),
                "alerts": alerts[:limit],
            })
        return json.dumps({"ip_address": ip_address, "alert_count": 0, "alerts": []})

    def _get_alert_statistics(self) -> str:
        if self.alert_store:
            stats = self.alert_store.get_stats()
            return json.dumps(stats)
        return json.dumps({"error": "No alert store available"})

    def _get_related_events(self, source_ip: str, time_window_minutes: int = 60) -> str:
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        related = [
            e if isinstance(e, dict) else e.to_dict() if hasattr(e, "to_dict") else vars(e)
            for e in self.recent_events_cache
            if (getattr(e, "source_ip", None) or (e.get("source_ip") if isinstance(e, dict) else None)) == source_ip
        ]
        return json.dumps({
            "source_ip": source_ip,
            "time_window_minutes": time_window_minutes,
            "related_event_count": len(related),
            "events": related[:20],  # Cap at 20 to avoid context bloat
        }, default=str)

    def _check_ip_reputation(self, ip_address: str) -> str:
        # Local heuristic checks (no external API call)
        indicators = []
        risk_score = 0

        # Private IP ranges are lower risk
        is_private = (
            ip_address.startswith("192.168.")
            or ip_address.startswith("10.")
            or ip_address.startswith("172.16.")
        )

        if is_private:
            indicators.append("Private/internal IP range")
            risk_score += 10
        else:
            risk_score += 30

        # Check alert history
        if self.alert_store:
            history = self.alert_store.get_recent_alerts_for_ip(ip_address, limit=50)
            if history:
                risk_score += min(50, len(history) * 5)
                severity_counts = {}
                for a in history:
                    s = a.get("severity", "LOW")
                    severity_counts[s] = severity_counts.get(s, 0) + 1
                indicators.append(f"Prior alerts: {severity_counts}")
                if severity_counts.get("CRITICAL", 0) > 0:
                    indicators.append("Previously triggered CRITICAL alerts")
                    risk_score += 20

        risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH"
        return json.dumps({
            "ip_address": ip_address,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_private": is_private,
            "indicators": indicators,
        })

    def _get_attack_pattern_context(self, rule_name: str) -> str:
        ATTACK_CONTEXT = {
            "sql_injection": {
                "mitre_tactic": "Initial Access / Credential Access",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
                "attacker_goal": "Extract database contents, bypass authentication, execute OS commands via database",
                "typical_next_steps": ["Data exfiltration", "Privilege escalation", "Persistence via web shell"],
                "recommended_response": ["Block source IP", "Review and patch vulnerable endpoint", "Audit database query logs"],
                "severity_context": "High - SQLi can lead to full database compromise",
            },
            "ssh_brute_force": {
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110 - Brute Force",
                "attacker_goal": "Gain SSH access to server for persistent access or lateral movement",
                "typical_next_steps": ["Credential theft", "Lateral movement", "Ransomware deployment"],
                "recommended_response": ["Block source IP", "Enable fail2ban", "Enforce key-based auth only", "Review successful logins"],
                "severity_context": "High - SSH access gives full server control",
            },
            "http_brute_force": {
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110.003 - Password Spraying",
                "attacker_goal": "Compromise user accounts via automated credential testing",
                "typical_next_steps": ["Account takeover", "Data theft", "Privilege escalation"],
                "recommended_response": ["Rate-limit source IP", "Enable CAPTCHA", "Notify affected users", "Review successful auths"],
                "severity_context": "Medium-High - depends on account privileges",
            },
            "large_outbound_transfer": {
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
                "attacker_goal": "Steal sensitive data from the environment",
                "typical_next_steps": ["Data sale", "Ransomware leverage", "Regulatory exposure"],
                "recommended_response": ["Block outbound connection", "Identify data accessed", "Notify data owners", "Forensic investigation"],
                "severity_context": "Critical - may indicate active data breach",
            },
            "path_traversal": {
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
                "attacker_goal": "Read sensitive files outside web root (credentials, configs, /etc/passwd)",
                "typical_next_steps": ["Credential theft", "Configuration disclosure", "Remote code execution"],
                "recommended_response": ["Block source IP", "Patch file access controls", "Review accessed paths"],
                "severity_context": "High - can expose credentials and configuration files",
            },
        }
        context = ATTACK_CONTEXT.get(rule_name, {
            "mitre_tactic": "Unknown",
            "attacker_goal": "Unknown attack pattern",
            "recommended_response": ["Investigate manually", "Block if suspicious"],
            "severity_context": f"Rule '{rule_name}' — no context available",
        })
        return json.dumps({"rule_name": rule_name, **context})
