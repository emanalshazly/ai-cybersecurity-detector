"""
Report generator — weekly HTML security summary with MITRE ATT&CK heat map.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional

logger = logging.getLogger("ReportGenerator")

# MITRE ATT&CK tactics in kill-chain order
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

# Map rule_name → MITRE tactic (for heat map)
RULE_TO_TACTIC = {
    "sql_injection":              "Initial Access",
    "path_traversal":             "Initial Access",
    "xss_attempt":                "Initial Access",
    "http_brute_force":           "Credential Access",
    "http_brute_force_stateful":  "Credential Access",
    "ssh_brute_force":            "Credential Access",
    "ssh_brute_force_stateful":   "Credential Access",
    "directory_scan":             "Discovery",
    "directory_scan_stateful":    "Discovery",
    "suspicious_user_agent":      "Reconnaissance",
    "large_outbound_transfer":    "Exfiltration",
    "large_upload":               "Exfiltration",
    "server_error_spike":         "Impact",
    "dos_indicator_stateful":     "Impact",
    "slow_response":              "Impact",
    "high_request_rate":          "Impact",
    "ueba_request_size_anomaly":  "Exfiltration",
    "ueba_response_time_anomaly": "Impact",
}


class ReportGenerator:
    def __init__(self, alert_store):
        self.store = alert_store

    def generate_weekly_html(self, output_path: str = "weekly_report.html") -> str:
        """Generate an HTML weekly security report and save to file."""
        now = datetime.utcnow()
        week_start = now - timedelta(days=7)

        alerts = self.store.get_alerts_in_range(week_start, now)
        stats = self.store.get_stats()
        tactic_counts = self._count_tactics(alerts)
        top_ips = self._top_ips(alerts, limit=10)
        top_rules = self._top_rules(alerts, limit=10)
        timeline = self._daily_counts(alerts)

        html = self._render_html(
            now=now,
            week_start=week_start,
            alerts=alerts,
            stats=stats,
            tactic_counts=tactic_counts,
            top_ips=top_ips,
            top_rules=top_rules,
            timeline=timeline,
        )

        with open(output_path, "w") as f:
            f.write(html)
        logger.info(f"Weekly report saved to {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # Data aggregation helpers
    # ------------------------------------------------------------------

    def _count_tactics(self, alerts: List[dict]) -> dict:
        counts: dict = {t: 0 for t in TACTICS}
        for a in alerts:
            rule = a.get("rule_name") or ""
            mitre = a.get("mitre_tactic") or RULE_TO_TACTIC.get(rule, "")
            if mitre in counts:
                counts[mitre] += 1
        return counts

    def _top_ips(self, alerts: List[dict], limit: int = 10) -> List[dict]:
        counts: dict = {}
        for a in alerts:
            ip = a.get("source_ip") or "unknown"
            counts[ip] = counts.get(ip, 0) + 1
        return [{"ip": ip, "count": c} for ip, c in sorted(counts.items(), key=lambda x: -x[1])[:limit]]

    def _top_rules(self, alerts: List[dict], limit: int = 10) -> List[dict]:
        counts: dict = {}
        for a in alerts:
            rule = a.get("rule_name") or "anomaly"
            counts[rule] = counts.get(rule, 0) + 1
        return [{"rule": r, "count": c} for r, c in sorted(counts.items(), key=lambda x: -x[1])[:limit]]

    def _daily_counts(self, alerts: List[dict]) -> List[dict]:
        days: dict = {}
        for a in alerts:
            ts = (a.get("timestamp") or "")[:10]  # YYYY-MM-DD
            if ts:
                days[ts] = days.get(ts, 0) + 1
        return [{"date": d, "count": c} for d, c in sorted(days.items())]

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def _render_html(self, now, week_start, alerts, stats, tactic_counts,
                     top_ips, top_rules, timeline) -> str:
        sev = stats.get("by_severity", {})
        total = stats.get("total", 0)
        fp_rate = stats.get("fp_rate", 0)
        week_total = len(alerts)

        # MITRE heat map cells
        max_tactic = max(tactic_counts.values(), default=1) or 1
        tactic_cells = ""
        for tactic in TACTICS:
            count = tactic_counts.get(tactic, 0)
            intensity = min(int((count / max_tactic) * 5), 5)
            color = ["#f0f4f8", "#d4e6f1", "#a9cce3", "#5dade2", "#2e86c1", "#1a5276"][intensity]
            tactic_cells += (
                f'<div class="tactic-cell" style="background:{color}" title="{count} alerts">'
                f'<span class="tactic-name">{tactic}</span>'
                f'<span class="tactic-count">{count}</span>'
                f'</div>'
            )

        # Timeline bars
        max_day = max((d["count"] for d in timeline), default=1) or 1
        timeline_html = ""
        for d in timeline:
            pct = int((d["count"] / max_day) * 100)
            timeline_html += (
                f'<div class="bar-wrap" title="{d["date"]}: {d["count"]} alerts">'
                f'<div class="bar" style="height:{pct}%"></div>'
                f'<div class="bar-label">{d["date"][5:]}</div>'
                f'</div>'
            )

        # Top IPs table
        ip_rows = "".join(
            f'<tr><td>{r["ip"]}</td><td>{r["count"]}</td></tr>'
            for r in top_ips
        )

        # Top rules table
        rule_rows = "".join(
            f'<tr><td><code>{r["rule"]}</code></td><td>{r["count"]}</td></tr>'
            for r in top_rules
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — {now.strftime('%Y-%m-%d')}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0d1117; color: #e6edf3; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
  h2 {{ color: #79c0ff; margin-top: 32px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 16px; text-align: center; }}
  .stat-value {{ font-size: 2em; font-weight: bold; }}
  .critical {{ color: #f85149; }} .high {{ color: #d29922; }}
  .medium {{ color: #e3b341; }} .low {{ color: #3fb950; }}
  .tactic-grid {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }}
  .tactic-cell {{ border-radius: 6px; padding: 8px 12px; min-width: 120px;
                 display: flex; flex-direction: column; align-items: center;
                 border: 1px solid #30363d; }}
  .tactic-name {{ font-size: 0.75em; color: #010409; font-weight: 600; }}
  .tactic-count {{ font-size: 1.2em; font-weight: bold; color: #010409; }}
  .timeline {{ display: flex; align-items: flex-end; gap: 4px; height: 100px;
              background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: 12px; margin: 12px 0; }}
  .bar-wrap {{ display: flex; flex-direction: column; align-items: center; flex: 1; height: 100%; }}
  .bar {{ background: #58a6ff; border-radius: 3px 3px 0 0; width: 100%; min-height: 2px; }}
  .bar-label {{ font-size: 0.6em; color: #8b949e; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22;
          border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; padding: 10px 14px; text-align: left; color: #8b949e; font-size: 0.85em; }}
  td {{ padding: 10px 14px; border-top: 1px solid #21262d; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  .tables-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 16px; }}
  .meta {{ color: #8b949e; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>AI Cybersecurity Agent — Weekly Report</h1>
<p class="meta">Period: {week_start.strftime('%Y-%m-%d')} → {now.strftime('%Y-%m-%d %H:%M')} UTC &nbsp;|&nbsp;
Generated: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC</p>

<h2>Summary</h2>
<div class="stats-grid">
  <div class="stat-card"><div class="stat-value">{week_total}</div><div>Alerts this week</div></div>
  <div class="stat-card"><div class="stat-value critical">{sev.get('CRITICAL', 0)}</div><div>Critical</div></div>
  <div class="stat-card"><div class="stat-value high">{sev.get('HIGH', 0)}</div><div>High</div></div>
  <div class="stat-card"><div class="stat-value low">{round(fp_rate * 100, 1)}%</div><div>False Positive Rate</div></div>
</div>

<h2>Alert Timeline (last 7 days)</h2>
<div class="timeline">{timeline_html or '<span style="color:#8b949e;margin:auto">No data</span>'}</div>

<h2>MITRE ATT&CK Coverage</h2>
<div class="tactic-grid">{tactic_cells}</div>

<div class="tables-grid">
  <div>
    <h2>Top Attacking IPs</h2>
    <table><thead><tr><th>IP Address</th><th>Alert Count</th></tr></thead>
    <tbody>{ip_rows or '<tr><td colspan="2" style="color:#8b949e">No data</td></tr>'}</tbody></table>
  </div>
  <div>
    <h2>Top Detection Rules</h2>
    <table><thead><tr><th>Rule</th><th>Count</th></tr></thead>
    <tbody>{rule_rows or '<tr><td colspan="2" style="color:#8b949e">No data</td></tr>'}</tbody></table>
  </div>
</div>

<p class="meta" style="margin-top:32px">Generated by AI Cybersecurity Agent — Powered by Claude claude-opus-4-6</p>
</body>
</html>"""
