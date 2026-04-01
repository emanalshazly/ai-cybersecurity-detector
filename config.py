"""
Centralized configuration for the AI Cybersecurity Agent.
All settings are loaded from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentConfig:
    # Anthropic API
    anthropic_api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    claude_model: str = "claude-opus-4-6"

    # Detection thresholds
    anomaly_threshold: float = -0.5
    contamination_rate: float = 0.02
    alert_min_severity: str = "LOW"  # Minimum severity to process: LOW, MEDIUM, HIGH, CRITICAL

    # Agent loop
    poll_interval_seconds: int = 30
    max_concurrent_investigations: int = 5
    auto_investigate_severities: list = field(default_factory=lambda: ["HIGH", "CRITICAL"])

    # Storage
    db_path: str = os.environ.get("DB_PATH", "cybersecurity_agent.db")
    model_path: str = os.environ.get("MODEL_PATH", "threat_detector_model.joblib")
    log_file: str = os.environ.get("LOG_FILE", "security_agent.log")

    # Notifications (Slack)
    slack_webhook_url: Optional[str] = field(default_factory=lambda: os.environ.get("SLACK_WEBHOOK_URL"))
    slack_channel: str = os.environ.get("SLACK_CHANNEL", "#security-alerts")

    # Notifications (Email)
    smtp_host: Optional[str] = field(default_factory=lambda: os.environ.get("SMTP_HOST"))
    smtp_port: int = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user: Optional[str] = field(default_factory=lambda: os.environ.get("SMTP_USER"))
    smtp_password: Optional[str] = field(default_factory=lambda: os.environ.get("SMTP_PASSWORD"))
    alert_email_to: Optional[str] = field(default_factory=lambda: os.environ.get("ALERT_EMAIL_TO"))

    # Log file monitoring
    monitored_log_files: list = field(default_factory=lambda: [
        path for path in [
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/auth.log",
        ] if os.path.exists(path)
    ])

    # Response actions (approval tiers)
    # TIER_1: auto-execute (log, notify)
    # TIER_2: auto-execute with audit trail (rate-limit, watchlist)
    # TIER_3: hold for human approval (block IP, quarantine)
    auto_block_critical: bool = os.environ.get("AUTO_BLOCK_CRITICAL", "false").lower() == "true"


# Global singleton config
config = AgentConfig()


def get_config() -> AgentConfig:
    return config
