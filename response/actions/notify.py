"""
Notification actions: Slack webhook, email, and rich console output.
"""

import json
import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from config import get_config

logger = logging.getLogger("Notifier")

SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF6600",
    "MEDIUM": "#FFC300",
    "LOW": "#36A64F",
}

SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":warning:",
    "MEDIUM": ":yellow_circle:",
    "LOW": ":information_source:",
}


class Notifier:
    """Sends security alert notifications via Slack and/or email."""

    def __init__(self):
        self.cfg = get_config()

    async def send_alert(self, alert, analysis=None) -> None:
        """Send alert via all configured channels."""
        tasks = []
        if self.cfg.slack_webhook_url:
            await self._send_slack(alert, analysis)
        if self.cfg.smtp_host and self.cfg.alert_email_to:
            await self._send_email(alert, analysis)
        self._log_to_console(alert, analysis)

    async def _send_slack(self, alert, analysis) -> None:
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — Slack notifications disabled. Run: pip install httpx")
            return

        severity = getattr(alert, "severity", "UNKNOWN")
        color = SEVERITY_COLORS.get(severity, "#808080")
        emoji = SEVERITY_EMOJI.get(severity, ":shield:")

        analysis_text = ""
        if analysis:
            analysis_text = f"\n*Analysis:*\n{getattr(analysis, 'threat_assessment', '')[:500]}"
            actions = getattr(analysis, "recommended_actions", [])
            if actions:
                action_list = "\n".join(f"• {a}" for a in actions[:4])
                analysis_text += f"\n\n*Recommended Actions:*\n{action_list}"

        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} {severity} Security Alert — {getattr(alert, 'id', 'N/A')}",
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                            {"type": "mrkdwn", "text": f"*Source IP:*\n{getattr(alert, 'source_ip', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*Detector:*\n{getattr(alert, 'detector', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*Rule:*\n{getattr(alert, 'rule_name', 'anomaly') or 'ML anomaly'}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"},
                            {"type": "mrkdwn", "text": f"*Alert ID:*\n`{getattr(alert, 'id', 'N/A')}`"},
                        ]
                    },
                ],
                "fallback": f"{severity} alert from {getattr(alert, 'source_ip', 'unknown')}",
            }]
        }

        if analysis_text:
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": analysis_text}
            })

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.cfg.slack_webhook_url, json=payload)
                resp.raise_for_status()
                logger.info(f"Slack notification sent for {getattr(alert, 'id', 'N/A')}")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")

    async def _send_email(self, alert, analysis) -> None:
        severity = getattr(alert, "severity", "UNKNOWN")
        alert_id = getattr(alert, "id", "N/A")
        source_ip = getattr(alert, "source_ip", "N/A")

        subject = f"[{severity}] Security Alert {alert_id} — {source_ip}"

        body_lines = [
            f"Security Alert: {alert_id}",
            f"Severity: {severity}",
            f"Source IP: {source_ip}",
            f"Detector: {getattr(alert, 'detector', 'N/A')}",
            f"Rule: {getattr(alert, 'rule_name', 'ML anomaly') or 'ML anomaly'}",
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
        ]

        if analysis:
            body_lines.append("ANALYSIS:")
            body_lines.append(getattr(analysis, "threat_assessment", "")[:1000])
            body_lines.append("")
            actions = getattr(analysis, "recommended_actions", [])
            if actions:
                body_lines.append("RECOMMENDED ACTIONS:")
                body_lines.extend(f"  {i+1}. {a}" for i, a in enumerate(actions[:6]))

        body = "\n".join(body_lines)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.cfg.smtp_user
        msg["To"] = self.cfg.alert_email_to
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port) as server:
                server.starttls()
                if self.cfg.smtp_user and self.cfg.smtp_password:
                    server.login(self.cfg.smtp_user, self.cfg.smtp_password)
                server.sendmail(self.cfg.smtp_user, self.cfg.alert_email_to, msg.as_string())
            logger.info(f"Email notification sent for {alert_id}")
        except Exception as e:
            logger.error(f"Email notification failed: {e}")

    def _log_to_console(self, alert, analysis) -> None:
        """Always log to console regardless of other notification channels."""
        severity = getattr(alert, "severity", "UNKNOWN")
        alert_id = getattr(alert, "id", "N/A")
        source_ip = getattr(alert, "source_ip", "N/A")
        rule = getattr(alert, "rule_name", None) or "ML anomaly"

        bar = "=" * 60
        lines = [
            bar,
            f"  ALERT [{severity}] {alert_id}",
            f"  IP: {source_ip}  |  Rule: {rule}",
            f"  Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        if analysis:
            assessment = getattr(analysis, "threat_assessment", "")
            if assessment:
                lines.append("")
                lines.append("  ANALYSIS:")
                for line in assessment[:400].split("\n"):
                    lines.append(f"    {line}")
            actions = getattr(analysis, "recommended_actions", [])
            if actions:
                lines.append("")
                lines.append("  ACTIONS:")
                for a in actions[:4]:
                    lines.append(f"    - {a}")
        lines.append(bar)

        for line in lines:
            logger.warning(line)
