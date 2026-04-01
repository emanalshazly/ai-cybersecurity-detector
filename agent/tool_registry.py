"""
Tool definitions exposed to the Claude analyst via function-calling.
Claude uses these tools to actively investigate threats rather than
passively receiving data dumps.

Enhancement #3: AbuseIPDB integration for real IP reputation data.
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger("ToolRegistry")

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")


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
                    "ip_address": {"type": "string", "description": "The IP address to look up"},
                    "limit": {"type": "integer", "description": "Max alerts to return (default: 10)"},
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "get_alert_statistics",
            "description": (
                "Retrieve overall statistics: counts by severity, top attacking IPs, "
                "false positive rate, and detection trends."
            ),
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_related_events",
            "description": (
                "Find other events from the same IP within a time window. "
                "Use this to identify coordinated attacks or campaign activity."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string", "description": "IP address to search"},
                    "time_window_minutes": {"type": "integer", "description": "Minutes to look back (default: 60)"},
                },
                "required": ["source_ip"],
            },
        },
        {
            "name": "check_ip_reputation",
            "description": (
                "Check IP reputation via AbuseIPDB (live threat intel database) plus local alert history. "
                "Returns abuse confidence score, total reports, and country. "
                "Always call this for any external IP before concluding your analysis."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "The IP address to check"},
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "get_attack_pattern_context",
            "description": (
                "Look up MITRE ATT&CK mapping, attacker goals, and recommended responses "
                "for a specific detection rule name."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "rule_name": {"type": "string", "description": "Detection rule name (e.g., 'sql_injection')"},
                },
                "required": ["rule_name"],
            },
        },
        {
            "name": "get_campaign_context",
            "description": (
                "Check if this alert belongs to an active attack campaign. "
                "Returns campaign ID, total alerts in campaign, involved IPs, and TTPs observed."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string", "description": "IP address to look up campaign for"},
                },
                "required": ["source_ip"],
            },
        },
        {
            "name": "get_entity_baseline",
            "description": (
                "Retrieve the UEBA behavioral baseline for an IP address: "
                "normal request size, response time patterns, and how long the baseline has been built."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP to get baseline for"},
                },
                "required": ["ip_address"],
            },
        },
    ]


class ToolExecutor:
    """Executes tool calls made by the Claude analyst."""

    def __init__(
        self,
        alert_store=None,
        recent_events_cache: list = None,
        campaign_tracker=None,
        ueba_detector=None,
    ):
        self.alert_store = alert_store
        self.recent_events_cache = recent_events_cache or []
        self.campaign_tracker = campaign_tracker
        self.ueba_detector = ueba_detector

    def execute(self, tool_name: str, tool_input: dict) -> str:
        """Dispatch a tool call and return a JSON string result."""
        try:
            dispatch = {
                "get_recent_alerts_for_ip": self._get_recent_alerts_for_ip,
                "get_alert_statistics": lambda **_: self._get_alert_statistics(),
                "get_related_events": self._get_related_events,
                "check_ip_reputation": self._check_ip_reputation,
                "get_attack_pattern_context": self._get_attack_pattern_context,
                "get_campaign_context": self._get_campaign_context,
                "get_entity_baseline": self._get_entity_baseline,
            }
            fn = dispatch.get(tool_name)
            if fn:
                return fn(**tool_input)
            return json.dumps({"error": f"Unknown tool: {tool_name}"})
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def _get_recent_alerts_for_ip(self, ip_address: str, limit: int = 10) -> str:
        if self.alert_store:
            alerts = self.alert_store.get_recent_alerts_for_ip(ip_address, limit=limit)
            return json.dumps({"ip_address": ip_address, "alert_count": len(alerts), "alerts": alerts[:limit]})
        return json.dumps({"ip_address": ip_address, "alert_count": 0, "alerts": []})

    def _get_alert_statistics(self) -> str:
        if self.alert_store:
            return json.dumps(self.alert_store.get_stats())
        return json.dumps({"error": "No alert store available"})

    def _get_related_events(self, source_ip: str, time_window_minutes: int = 60) -> str:
        related = [
            e if isinstance(e, dict) else (e.to_dict() if hasattr(e, "to_dict") else vars(e))
            for e in self.recent_events_cache
            if (getattr(e, "source_ip", None) or (e.get("source_ip") if isinstance(e, dict) else None)) == source_ip
        ]
        return json.dumps({
            "source_ip": source_ip,
            "time_window_minutes": time_window_minutes,
            "related_event_count": len(related),
            "events": related[:20],
        }, default=str)

    def _check_ip_reputation(self, ip_address: str) -> str:
        """Check AbuseIPDB first, fall back to local heuristics."""
        # Try AbuseIPDB if API key is set
        if ABUSEIPDB_KEY:
            try:
                import urllib.request
                import urllib.parse
                url = (
                    "https://api.abuseipdb.com/api/v2/check?"
                    + urllib.parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": "30"})
                )
                req = urllib.request.Request(url, headers={
                    "Key": ABUSEIPDB_KEY,
                    "Accept": "application/json",
                })
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())["data"]
                    result = {
                        "source": "AbuseIPDB",
                        "ip_address": ip_address,
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode", "?"),
                        "is_tor": data.get("isTor", False),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "risk_level": (
                            "CRITICAL" if data.get("abuseConfidenceScore", 0) > 80 else
                            "HIGH" if data.get("abuseConfidenceScore", 0) > 50 else
                            "MEDIUM" if data.get("abuseConfidenceScore", 0) > 20 else
                            "LOW"
                        ),
                    }
                    # Augment with local alert history
                    if self.alert_store:
                        history = self.alert_store.get_recent_alerts_for_ip(ip_address, limit=10)
                        result["local_alert_count"] = len(history)
                    return json.dumps(result)
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup failed for {ip_address}: {e} — using local heuristics")

        # Fallback: local heuristic checks
        indicators = []
        risk_score = 0
        is_private = (
            ip_address.startswith("192.168.")
            or ip_address.startswith("10.")
            or ip_address.startswith("172.16.")
            or ip_address == "127.0.0.1"
        )

        if is_private:
            indicators.append("Private/internal IP range")
            risk_score += 10
        else:
            risk_score += 30

        if self.alert_store:
            history = self.alert_store.get_recent_alerts_for_ip(ip_address, limit=50)
            if history:
                risk_score += min(50, len(history) * 5)
                severity_counts: dict = {}
                for a in history:
                    s = a.get("severity", "LOW")
                    severity_counts[s] = severity_counts.get(s, 0) + 1
                indicators.append(f"Prior alert counts: {severity_counts}")
                if severity_counts.get("CRITICAL", 0) > 0:
                    indicators.append("Previously triggered CRITICAL alerts")
                    risk_score += 20

        return json.dumps({
            "source": "local_heuristic",
            "ip_address": ip_address,
            "risk_score": risk_score,
            "risk_level": "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH",
            "is_private": is_private,
            "indicators": indicators,
            "note": "Set ABUSEIPDB_KEY env var for real threat intelligence",
        })

    def _get_attack_pattern_context(self, rule_name: str) -> str:
        ATTACK_CONTEXT = {
            "sql_injection": {
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application",
                "attacker_goal": "Extract database contents, bypass authentication, RCE via DB",
                "typical_next_steps": ["Data exfiltration", "Privilege escalation", "Web shell persistence"],
                "recommended_response": ["Block source IP", "Patch vulnerable endpoint", "Audit DB query logs"],
            },
            "ssh_brute_force": {
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110",
                "mitre_technique_name": "Brute Force",
                "attacker_goal": "Gain SSH access for persistent entry or lateral movement",
                "typical_next_steps": ["Credential theft", "Lateral movement", "Ransomware"],
                "recommended_response": ["Block source IP", "Enable fail2ban", "Enforce key-based auth"],
            },
            "http_brute_force": {
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110.003",
                "mitre_technique_name": "Password Spraying",
                "attacker_goal": "Compromise user accounts via automated credential testing",
                "typical_next_steps": ["Account takeover", "Data theft"],
                "recommended_response": ["Rate-limit source IP", "Enable CAPTCHA", "Review successful auths"],
            },
            "http_brute_force_stateful": {
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110.003",
                "mitre_technique_name": "Password Spraying",
                "attacker_goal": "Sustained credential stuffing attack confirmed by volume",
                "typical_next_steps": ["Account takeover", "Data theft"],
                "recommended_response": ["Block source IP immediately", "Check for successful logins", "Enable CAPTCHA"],
            },
            "large_outbound_transfer": {
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "T1048",
                "mitre_technique_name": "Exfiltration Over Alternative Protocol",
                "attacker_goal": "Steal sensitive data",
                "typical_next_steps": ["Data sale", "Ransomware leverage"],
                "recommended_response": ["Block outbound connection", "Identify data accessed", "Forensic investigation"],
            },
            "path_traversal": {
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application",
                "attacker_goal": "Read sensitive files outside web root",
                "typical_next_steps": ["Credential theft", "Config disclosure", "RCE"],
                "recommended_response": ["Block source IP", "Patch file access controls"],
            },
            "directory_scan_stateful": {
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1083",
                "mitre_technique_name": "File and Directory Discovery",
                "attacker_goal": "Enumerate web application files and hidden endpoints",
                "typical_next_steps": ["Exploit discovered endpoints", "Find backup files"],
                "recommended_response": ["Block scanner IP", "Review discovered paths for exposure"],
            },
            "dos_indicator_stateful": {
                "mitre_tactic": "Impact",
                "mitre_technique": "T1499",
                "mitre_technique_name": "Endpoint Denial of Service",
                "attacker_goal": "Overwhelm server resources to cause service disruption",
                "typical_next_steps": ["Service degradation", "Extortion"],
                "recommended_response": ["Rate-limit source IP", "Enable CDN/WAF", "Scale infrastructure"],
            },
        }
        context = ATTACK_CONTEXT.get(rule_name, {
            "mitre_tactic": "Unknown",
            "mitre_technique": "N/A",
            "attacker_goal": "Unknown attack pattern",
            "recommended_response": ["Investigate manually", "Block if suspicious"],
        })
        return json.dumps({"rule_name": rule_name, **context})

    def _get_campaign_context(self, source_ip: str) -> str:
        if not self.campaign_tracker:
            return json.dumps({"message": "Campaign tracking not enabled"})
        campaign = self.campaign_tracker.get_campaign_for_ip(source_ip)
        if not campaign:
            return json.dumps({"source_ip": source_ip, "in_campaign": False})
        return json.dumps({"source_ip": source_ip, "in_campaign": True, **campaign.to_dict()})

    def _get_entity_baseline(self, ip_address: str) -> str:
        if not self.ueba_detector:
            return json.dumps({"message": "UEBA detector not enabled"})
        profile = self.ueba_detector.get_profile(ip_address)
        if not profile:
            return json.dumps({"ip_address": ip_address, "profile": None, "message": "No baseline yet"})
        return json.dumps(profile)
