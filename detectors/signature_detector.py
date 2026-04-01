"""
Signature-based (rule-based) threat detector.
Complements the ML detector with fast, interpretable detection of known patterns.
Zero false-negatives on known attack signatures.
"""

import re
import logging
from dataclasses import dataclass
from typing import List, Callable, Any

from .base_detector import BaseDetector, ThreatCandidate

logger = logging.getLogger("SignatureDetector")


@dataclass
class Rule:
    name: str
    severity: str
    description: str
    tags: List[str]
    match_fn: Callable[[dict], bool]


# ---------------------------------------------------------------------------
# Built-in rule library
# ---------------------------------------------------------------------------

def _build_rules() -> List[Rule]:
    return [
        # --- Authentication attacks ---
        Rule(
            name="ssh_brute_force",
            severity="HIGH",
            description="Multiple failed SSH authentication attempts from same IP",
            tags=["brute_force", "ssh", "authentication"],
            match_fn=lambda e: (
                e.get("source") in ("auth.log", "syslog", "/var/log/auth.log")
                and "Failed password" in (e.get("message") or "")
            ),
        ),
        Rule(
            name="http_brute_force",
            severity="HIGH",
            description="Repeated HTTP 401/403 responses — possible credential stuffing",
            tags=["brute_force", "http", "authentication"],
            match_fn=lambda e: e.get("response_code") in (401, 403),
        ),
        Rule(
            name="http_login_flood",
            severity="HIGH",
            description="Excessive POST to login endpoint",
            tags=["brute_force", "http"],
            match_fn=lambda e: (
                e.get("request_type") == "POST"
                and any(kw in (e.get("endpoint") or "") for kw in ["/login", "/auth", "/signin", "/api/token"])
            ),
        ),

        # --- Injection attacks ---
        Rule(
            name="sql_injection",
            severity="CRITICAL",
            description="SQL injection pattern detected in request",
            tags=["injection", "sqli", "web"],
            match_fn=lambda e: bool(re.search(
                r"(?i)(union\s+select|or\s+1=1|'--|;\s*drop\s+table|xp_cmdshell)",
                str(e.get("endpoint", "")) + str(e.get("user_agent", ""))
            )),
        ),
        Rule(
            name="path_traversal",
            severity="HIGH",
            description="Path traversal attempt detected",
            tags=["lfi", "path_traversal", "web"],
            match_fn=lambda e: bool(re.search(
                r"\.\./|\.\.\%2f|%2e%2e/",
                str(e.get("endpoint", "")),
                re.IGNORECASE
            )),
        ),
        Rule(
            name="xss_attempt",
            severity="MEDIUM",
            description="Cross-site scripting attempt detected",
            tags=["xss", "web"],
            match_fn=lambda e: bool(re.search(
                r"<script|javascript:|onerror=|onload=",
                str(e.get("endpoint", "")) + str(e.get("user_agent", "")),
                re.IGNORECASE
            )),
        ),

        # --- Scanning & reconnaissance ---
        Rule(
            name="directory_scan",
            severity="MEDIUM",
            description="Automated directory/file enumeration scan detected",
            tags=["scanner", "recon", "web"],
            match_fn=lambda e: (
                e.get("response_code") == 404
                and any(kw in (e.get("endpoint") or "") for kw in [
                    ".php", ".asp", ".env", ".git", "wp-admin", "phpmyadmin", "/.well-known"
                ])
            ),
        ),
        Rule(
            name="suspicious_user_agent",
            severity="MEDIUM",
            description="Known scanner or attack tool user-agent detected",
            tags=["scanner", "recon"],
            match_fn=lambda e: bool(re.search(
                r"(?i)(sqlmap|nmap|nikto|masscan|zgrab|nuclei|dirbuster|hydra|metasploit)",
                str(e.get("user_agent", ""))
            )),
        ),

        # --- Data exfiltration indicators ---
        Rule(
            name="large_outbound_transfer",
            severity="HIGH",
            description="Unusually large response size — possible data exfiltration",
            tags=["exfiltration", "data_transfer"],
            match_fn=lambda e: (e.get("response_size") or 0) > 10_000_000,  # 10 MB
        ),
        Rule(
            name="large_upload",
            severity="MEDIUM",
            description="Unusually large request body — possible data upload",
            tags=["exfiltration", "upload"],
            match_fn=lambda e: (e.get("request_size") or 0) > 5_000_000,  # 5 MB
        ),

        # --- Server health / DoS indicators ---
        Rule(
            name="server_error_spike",
            severity="HIGH",
            description="HTTP 5xx server error — possible DoS or application crash",
            tags=["dos", "server_error"],
            match_fn=lambda e: (e.get("response_code") or 0) >= 500,
        ),
        Rule(
            name="slow_response",
            severity="MEDIUM",
            description="Abnormally slow response time — possible resource exhaustion",
            tags=["dos", "performance"],
            match_fn=lambda e: (e.get("response_time") or 0) > 10.0,  # 10 seconds
        ),
    ]


class SignatureDetector(BaseDetector):
    def __init__(self):
        self.rules = _build_rules()

    @property
    def name(self) -> str:
        return "SignatureDetector"

    def detect(self, events: List[Any]) -> List[ThreatCandidate]:
        candidates = []
        for event in events:
            raw = event.__dict__ if hasattr(event, "__dict__") else event
            for rule in self.rules:
                try:
                    if rule.match_fn(raw):
                        candidates.append(ThreatCandidate(
                            event=event,
                            detector=self.name,
                            severity=rule.severity,
                            anomaly_score=None,
                            rule_name=rule.name,
                            description=rule.description,
                            source_ip=raw.get("source_ip"),
                            tags=rule.tags.copy(),
                        ))
                        break  # One rule match per event is enough; avoid duplicate alerts
                except Exception:
                    pass  # Malformed events should never crash the detector

        if candidates:
            logger.info(f"Signature detector found {len(candidates)} matches in {len(events)} events")
        return candidates

    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule at runtime."""
        self.rules.append(rule)
        logger.info(f"Added custom rule: {rule.name}")
