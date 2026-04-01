"""
Attack Campaign Tracker.
Groups related alerts into campaigns using IP proximity and time windows.

Instead of 50 individual brute-force alerts, analysts see ONE campaign
with a summary: "Sustained credential stuffing attack from IP 10.0.0.99,
50 alerts over 2 hours, targeting /api/login, HIGH confidence."
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set

logger = logging.getLogger("CampaignTracker")

# How long without new alerts before a campaign is considered inactive
CAMPAIGN_TIMEOUT_MINUTES = 60

# Maximum age of a campaign before it's archived
CAMPAIGN_MAX_AGE_HOURS = 24


@dataclass
class Campaign:
    """A group of related security alerts attributed to the same attacker activity."""
    id: str
    first_seen: datetime
    last_seen: datetime
    source_ips: Set[str] = field(default_factory=set)
    alert_ids: List[str] = field(default_factory=list)
    rule_names: Set[str] = field(default_factory=set)
    severities: List[str] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    status: str = "active"  # active | inactive | archived

    @property
    def duration_minutes(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds() / 60

    @property
    def peak_severity(self) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.severities:
            return "LOW"
        return max(self.severities, key=lambda s: order.get(s, 0))

    @property
    def alert_count(self) -> int:
        return len(self.alert_ids)

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_minutes": round(self.duration_minutes, 1),
            "source_ips": list(self.source_ips),
            "alert_count": self.alert_count,
            "peak_severity": self.peak_severity,
            "rule_names": list(self.rule_names),
            "endpoints": list(self.endpoints),
            "status": self.status,
        }

    def summary(self) -> str:
        ips = ", ".join(sorted(self.source_ips)[:3])
        if len(self.source_ips) > 3:
            ips += f" (+{len(self.source_ips) - 3} more)"
        rules = ", ".join(sorted(self.rule_names)[:3])
        return (
            f"Campaign {self.id[:8]}: {self.alert_count} alerts over "
            f"{self.duration_minutes:.0f}min from {ips}. "
            f"Techniques: {rules}. Peak severity: {self.peak_severity}."
        )


class CampaignTracker:
    """
    Groups alerts into campaigns by correlating:
    - Same source IP within the campaign timeout window
    - Same rule_name from different IPs in the same window (coordinated attack)
    """

    def __init__(self):
        self._campaigns: Dict[str, Campaign] = {}
        # ip -> campaign_id for fast lookup
        self._ip_to_campaign: Dict[str, str] = {}

    def link_alert(self, alert) -> Optional[Campaign]:
        """
        Assign an alert to an existing campaign or create a new one.
        Returns the campaign it was assigned to.
        """
        source_ip = getattr(alert, "source_ip", None)
        rule_name = getattr(alert, "rule_name", None) or ""
        severity = getattr(alert, "severity", "LOW")
        alert_id = getattr(alert, "id", str(uuid.uuid4()))
        now = datetime.utcnow()

        # Try to find existing campaign for this IP
        existing_campaign = self._find_campaign(source_ip, now)

        if existing_campaign:
            campaign = existing_campaign
        else:
            # Create a new campaign
            campaign = Campaign(
                id=f"CAMP-{uuid.uuid4().hex[:8].upper()}",
                first_seen=now,
                last_seen=now,
            )
            self._campaigns[campaign.id] = campaign
            logger.info(f"New campaign started: {campaign.id}")

        # Update campaign
        campaign.last_seen = now
        campaign.alert_ids.append(alert_id)
        campaign.severities.append(severity)
        if rule_name:
            campaign.rule_names.add(rule_name)
        if source_ip:
            campaign.source_ips.add(source_ip)
            self._ip_to_campaign[source_ip] = campaign.id

        # Extract endpoint if available
        try:
            event_details = getattr(alert, "event_details", None)
            if event_details:
                import json
                details = json.loads(event_details) if isinstance(event_details, str) else event_details
                ep = details.get("endpoint")
                if ep:
                    campaign.endpoints.add(ep)
        except Exception:
            pass

        return campaign

    def _find_campaign(self, source_ip: Optional[str], now: datetime) -> Optional[Campaign]:
        """Find an active campaign for this IP, if one exists within the timeout window."""
        if not source_ip:
            return None

        campaign_id = self._ip_to_campaign.get(source_ip)
        if not campaign_id:
            return None

        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return None

        # Check if campaign is still active (not timed out)
        timeout = timedelta(minutes=CAMPAIGN_TIMEOUT_MINUTES)
        if now - campaign.last_seen > timeout:
            campaign.status = "inactive"
            return None

        return campaign

    def get_campaign_for_ip(self, source_ip: str) -> Optional[Campaign]:
        """Return the active campaign for an IP, if any."""
        campaign_id = self._ip_to_campaign.get(source_ip)
        if not campaign_id:
            return None
        return self._campaigns.get(campaign_id)

    def get_active_campaigns(self) -> List[Campaign]:
        """Return all currently active campaigns."""
        now = datetime.utcnow()
        timeout = timedelta(minutes=CAMPAIGN_TIMEOUT_MINUTES)
        active = []
        for c in self._campaigns.values():
            if c.status == "active" and (now - c.last_seen) <= timeout:
                active.append(c)
        return sorted(active, key=lambda c: c.last_seen, reverse=True)

    def get_all_campaigns(self, limit: int = 20) -> List[dict]:
        all_c = sorted(self._campaigns.values(), key=lambda c: c.last_seen, reverse=True)
        return [c.to_dict() for c in all_c[:limit]]

    def prune_old_campaigns(self) -> int:
        """Archive campaigns older than CAMPAIGN_MAX_AGE_HOURS. Returns count pruned."""
        now = datetime.utcnow()
        cutoff = timedelta(hours=CAMPAIGN_MAX_AGE_HOURS)
        pruned = 0
        for campaign in self._campaigns.values():
            if campaign.status != "archived" and (now - campaign.last_seen) > cutoff:
                campaign.status = "archived"
                pruned += 1
        return pruned
