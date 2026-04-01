"""
Approval gate — enforces human-in-the-loop safety for response actions.

Three tiers:
  TIER_1: Auto-execute (log, console notification)
  TIER_2: Auto-execute with audit trail (Slack/email notification)
  TIER_3: Hold for human approval (block IP, quarantine host)

This ensures destructive actions are never taken automatically without
explicit configuration or human sign-off.
"""

import logging
from enum import Enum
from typing import Any

from config import get_config
from response.actions.notify import Notifier

logger = logging.getLogger("ApprovalGate")


class ActionTier(str, Enum):
    TIER_1 = "tier_1"  # Auto-execute: log, internal notification
    TIER_2 = "tier_2"  # Auto-execute + audit: Slack, email
    TIER_3 = "tier_3"  # Hold for human: block IP, quarantine


class ApprovalGate:
    """
    Evaluates threat analysis and executes appropriate response actions
    based on severity and configuration.
    """

    def __init__(self, alert_store=None):
        self.cfg = get_config()
        self.alert_store = alert_store
        self.notifier = Notifier()

    async def evaluate(self, alert: Any, analysis: Any, candidate: Any) -> None:
        """
        Determine the appropriate tier and execute actions.
        """
        severity = getattr(alert, "severity", "LOW")
        is_fp = getattr(analysis, "is_likely_false_positive", False)

        if is_fp:
            logger.info(f"Skipping response for {alert.id} — assessed as false positive")
            return

        tier = self._determine_tier(severity, analysis)
        logger.info(f"Alert {alert.id} ({severity}) → {tier.value}")

        if tier == ActionTier.TIER_1:
            await self._tier1_actions(alert, analysis)
        elif tier == ActionTier.TIER_2:
            await self._tier2_actions(alert, analysis)
        elif tier == ActionTier.TIER_3:
            await self._tier3_actions(alert, analysis, candidate)

    def _determine_tier(self, severity: str, analysis: Any) -> ActionTier:
        confidence = getattr(analysis, "confidence", "MEDIUM")

        if severity == "CRITICAL":
            if self.cfg.auto_block_critical and confidence == "HIGH":
                return ActionTier.TIER_3
            return ActionTier.TIER_2  # Notify but don't auto-block by default

        elif severity == "HIGH":
            return ActionTier.TIER_2  # Notify team

        elif severity == "MEDIUM":
            return ActionTier.TIER_2

        else:  # LOW
            return ActionTier.TIER_1

    async def _tier1_actions(self, alert: Any, analysis: Any) -> None:
        """Log internally — no external notifications for LOW severity."""
        self.notifier._log_to_console(alert, analysis)

    async def _tier2_actions(self, alert: Any, analysis: Any) -> None:
        """Send notifications via all configured channels."""
        await self.notifier.send_alert(alert, analysis)

    async def _tier3_actions(self, alert: Any, analysis: Any, candidate: Any) -> None:
        """
        High-impact actions that require either explicit config flag or human approval.
        Currently: notify team and log pending action (block IP).
        Auto-execution of block requires AUTO_BLOCK_CRITICAL=true.
        """
        await self.notifier.send_alert(alert, analysis)

        source_ip = getattr(alert, "source_ip", None)
        if source_ip and self.cfg.auto_block_critical:
            self._block_ip_local(source_ip, alert.id)
        else:
            logger.warning(
                f"[PENDING ACTION] Manual approval required: "
                f"Block IP {source_ip} for alert {alert.id}. "
                f"Set AUTO_BLOCK_CRITICAL=true to enable auto-blocking."
            )

    def _block_ip_local(self, ip: str, alert_id: str) -> None:
        """
        Add iptables rule to block an IP.
        Only called when AUTO_BLOCK_CRITICAL=true is explicitly set.
        """
        import subprocess
        try:
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.warning(f"[BLOCKED] IP {ip} blocked via iptables (alert: {alert_id})")
            else:
                logger.error(f"iptables block failed for {ip}: {result.stderr}")
        except FileNotFoundError:
            logger.warning(f"iptables not available — cannot block {ip}")
        except subprocess.TimeoutExpired:
            logger.error(f"iptables command timed out for {ip}")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
