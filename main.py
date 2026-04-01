"""
AI Cybersecurity Agent v2.0 — Main Entry Point

Commands:
    python main.py demo              Single demo cycle with synthetic attack data
    python main.py monitor           Continuous monitoring of real log files
    python main.py monitor --mock    Continuous monitoring with synthetic data stream
    python main.py monitor --syslog  Also start syslog UDP receiver on port 5140
    python main.py dashboard         Start the web dashboard only (no monitoring)
    python main.py full              monitor + dashboard together
    python main.py full --mock       full stack with mock data
    python main.py status            Print alert stats from the database
    python main.py report            Generate weekly HTML security report
    python main.py campaigns         Show active attack campaigns

Environment variables:
    ANTHROPIC_API_KEY    Claude AI API key (enables intelligent threat analysis)
    ABUSEIPDB_KEY        AbuseIPDB API key (real IP reputation lookups)
    SLACK_WEBHOOK_URL    Slack webhook for alert notifications
    ALERT_EMAIL_TO       Email address for critical alerts
    AUTO_BLOCK_CRITICAL  Set to 'true' to auto-block CRITICAL IPs
    ENABLE_SYSLOG        Set to 'true' to start syslog UDP receiver
    DASHBOARD_PORT       Dashboard HTTP port (default: 8000)
    SYSLOG_PORT          Syslog UDP port (default: 5140)
"""

import asyncio
import logging
import os
import sys
from datetime import datetime

from config import get_config

cfg = get_config()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(cfg.log_file),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("main")


def _print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║            AI CYBERSECURITY AGENT  v2.0                      ║
║  Claude claude-opus-4-6 · ML · UEBA · Campaigns · Dashboard     ║
╚══════════════════════════════════════════════════════════════╝
""")


def _build_ingestors(use_mock: bool, enable_syslog: bool):
    ingestors = []

    if use_mock:
        from ingestors.mock_ingestor import MockIngestor
        ingestors.append(MockIngestor(events_per_poll=40, attack_rate=0.10, attack_scenario="mixed"))
        print("  [✓] Mock ingestor (synthetic attacks)")
    elif cfg.monitored_log_files:
        from ingestors.file_ingestor import FileIngestor
        ingestors.append(FileIngestor(cfg.monitored_log_files))
        print(f"  [✓] File ingestor: {cfg.monitored_log_files}")

    if enable_syslog or cfg.enable_syslog:
        from ingestors.syslog_ingestor import SyslogIngestor
        syslog = SyslogIngestor(host=cfg.syslog_host, port=cfg.syslog_port)
        ingestors.append(syslog)
        print(f"  [✓] Syslog UDP receiver on port {cfg.syslog_port}")

    return ingestors


def _build_detectors():
    from detectors.isolation_forest import IsolationForestDetector
    from detectors.signature_detector import SignatureDetector
    from detectors.stateful_detector import StatefulDetector
    from detectors.ueba_detector import UEBADetector

    detectors = [SignatureDetector(), StatefulDetector(), UEBADetector()]

    if os.path.exists(cfg.model_path):
        try:
            iso = IsolationForestDetector.load(cfg.model_path)
            detectors.insert(0, iso)
            print(f"  [✓] ML model loaded from {cfg.model_path}")
        except Exception as e:
            iso = IsolationForestDetector()
            detectors.insert(0, iso)
            logger.warning(f"Could not load model ({e}) — will train on first batch")
    else:
        iso = IsolationForestDetector()
        detectors.insert(0, iso)

    print("  [✓] Signature detector (13 rules)")
    print("  [✓] Stateful detector  (threshold-based brute force / DoS)")
    print("  [✓] UEBA detector      (per-entity behavioral baselines)")
    return detectors


async def _run_demo():
    from ingestors.mock_ingestor import MockIngestor
    from detectors.isolation_forest import IsolationForestDetector
    from agent.orchestrator import SecurityOrchestrator

    print("\n  Running DEMO with synthetic attack data…")
    print(f"  Claude AI: {'ENABLED (' + cfg.claude_model + ')' if cfg.anthropic_api_key else 'DISABLED — set ANTHROPIC_API_KEY'}")
    print(f"  AbuseIPDB: {'ENABLED' if cfg.abuseipdb_key else 'DISABLED — set ABUSEIPDB_KEY'}\n")

    # Warm up ML model
    warmup = MockIngestor(events_per_poll=400, attack_rate=0.0)
    warmup_events = warmup.poll()
    iso = IsolationForestDetector()
    iso.train([e.to_dict() for e in warmup_events])
    iso.save(cfg.model_path)
    print(f"  ML model trained on {len(warmup_events)} normal events → {cfg.model_path}")

    orchestrator = SecurityOrchestrator(
        ingestors=[MockIngestor(events_per_poll=80, attack_rate=0.15, attack_scenario="mixed")],
        detectors=_build_detectors(),
    )

    print("  Running detection cycle…\n")
    alerts = await orchestrator.run_once()

    print(f"\n  {'─'*56}")
    print(f"  Alerts generated : {len(alerts)}")
    for alert in alerts[:15]:
        print(
            f"    [{alert.severity:<8}] {alert.id}  "
            f"IP={str(alert.source_ip or '?'):<18} "
            f"{alert.rule_name or 'anomaly'}"
        )
        if alert.analysis:
            line = alert.analysis.split("\n")[0][:72]
            print(f"               → {line}")

    # Campaign summary
    active = orchestrator.campaign_tracker.get_active_campaigns()
    if active:
        print(f"\n  Active campaigns : {len(active)}")
        for c in active[:5]:
            print(f"    {c.summary()}")

    print(f"\n  DB: {cfg.db_path}  |  Log: {cfg.log_file}\n")


async def _run_monitor(use_mock=False, enable_syslog=False, with_dashboard=False):
    from agent.orchestrator import SecurityOrchestrator
    from storage.alert_store import AlertStore

    store = AlertStore()
    ingestors = _build_ingestors(use_mock, enable_syslog)
    if not ingestors:
        print("  No data sources configured. Use --mock flag or configure log files.")
        return

    # Start syslog listeners that need async startup
    from ingestors.syslog_ingestor import SyslogIngestor
    for ing in ingestors:
        if isinstance(ing, SyslogIngestor):
            await ing.start()

    dashboard_manager = None
    dashboard_task = None

    if with_dashboard:
        try:
            from dashboard.app import create_app
            import uvicorn
            app, dashboard_manager = create_app(
                alert_store=store,
                campaign_tracker=None,   # will be set after orchestrator init
                ueba_detector=None,
            )
            config = uvicorn.Config(app, host=cfg.dashboard_host, port=cfg.dashboard_port, log_level="warning")
            server = uvicorn.Server(config)
            dashboard_task = asyncio.create_task(server.serve())
            print(f"  [✓] Dashboard at http://{cfg.dashboard_host}:{cfg.dashboard_port}")
        except ImportError:
            print("  [!] FastAPI/uvicorn not installed — dashboard disabled")

    orchestrator = SecurityOrchestrator(
        ingestors=ingestors,
        detectors=_build_detectors(),
        alert_store=store,
        dashboard_manager=dashboard_manager,
    )

    print(f"\n  Poll interval : {cfg.poll_interval_seconds}s")
    print(f"  Min severity  : {cfg.alert_min_severity}")
    print(f"  Claude AI     : {'ENABLED' if cfg.anthropic_api_key else 'DISABLED'}")
    print(f"  AbuseIPDB     : {'ENABLED' if cfg.abuseipdb_key else 'DISABLED'}")
    print(f"  Auto-block    : {'ENABLED (CAUTION)' if cfg.auto_block_critical else 'DISABLED'}")
    print("\n  Agent running. Ctrl+C to stop.\n")

    try:
        monitor_task = asyncio.create_task(orchestrator.run())
        tasks = [monitor_task]
        if dashboard_task:
            tasks.append(dashboard_task)
        await asyncio.gather(*tasks)
    except (KeyboardInterrupt, asyncio.CancelledError):
        orchestrator.stop()
        for ing in ingestors:
            if isinstance(ing, SyslogIngestor):
                await ing.stop()
        print("\n  Agent stopped.")


def _print_status():
    from storage.alert_store import AlertStore
    store = AlertStore()
    stats = store.get_stats()
    recent = store.get_recent_alerts(limit=15)
    sev = stats.get("by_severity", {})

    print(f"\n  {'─'*60}")
    print(f"  ALERT DATABASE  ({cfg.db_path})")
    print(f"  {'─'*60}")
    print(f"  Total alerts  : {stats['total']}")
    print(f"  CRITICAL      : {sev.get('CRITICAL', 0)}")
    print(f"  HIGH          : {sev.get('HIGH', 0)}")
    print(f"  MEDIUM        : {sev.get('MEDIUM', 0)}")
    print(f"  LOW           : {sev.get('LOW', 0)}")
    print(f"  False pos.    : {stats['false_positives']} ({stats['fp_rate']:.1%})")

    if recent:
        print(f"\n  RECENT ALERTS:")
        for a in recent:
            ts = (a.get("timestamp") or "")[:19]
            camp = f" [C:{a['campaign_id'][:8]}]" if a.get("campaign_id") else ""
            mitre = f" [{a.get('mitre_tactic', '')}]" if a.get("mitre_tactic") else ""
            print(
                f"  [{a['severity']:<8}] {a['id']}  "
                f"IP={str(a.get('source_ip','?')):<18}{mitre}{camp}"
            )
    print()


def _print_campaigns():
    from storage.alert_store import AlertStore
    from correlation.campaign_tracker import CampaignTracker
    # Reconstruct campaigns from DB (simplified view — live tracker is more accurate)
    store = AlertStore()
    recent = store.get_recent_alerts(limit=500)
    tracker = CampaignTracker()

    class _FakeAlert:
        pass

    from storage.alert_store import Alert as AlertModel
    for a in recent:
        fa = _FakeAlert()
        fa.id = a["id"]
        fa.source_ip = a.get("source_ip")
        fa.rule_name = a.get("rule_name")
        fa.severity = a.get("severity", "LOW")
        fa.event_details = None
        tracker.link_alert(fa)

    camps = tracker.get_all_campaigns(limit=20)
    print(f"\n  CAMPAIGNS ({len(camps)} total)\n")
    for c in camps:
        print(
            f"  [{c['peak_severity']:<8}] {c['campaign_id']}  "
            f"Alerts={c['alert_count']:<4} "
            f"Duration={c['duration_minutes']:.0f}min  "
            f"IPs={','.join(c['source_ips'])[:40]}"
        )
        print(f"             TTPs: {', '.join(c['rule_names'])[:60]}")
    print()


def _generate_report():
    from storage.alert_store import AlertStore
    from response.reports import ReportGenerator
    store = AlertStore()
    gen = ReportGenerator(store)
    path = gen.generate_weekly_html()
    print(f"\n  Weekly report generated: {path}\n")


def main():
    _print_banner()
    args = sys.argv[1:]
    command = args[0] if args else "help"

    if command == "demo":
        asyncio.run(_run_demo())

    elif command == "monitor":
        use_mock = "--mock" in args
        enable_syslog = "--syslog" in args
        asyncio.run(_run_monitor(use_mock=use_mock, enable_syslog=enable_syslog))

    elif command == "dashboard":
        asyncio.run(_run_monitor(use_mock=True, with_dashboard=True))

    elif command == "full":
        use_mock = "--mock" in args
        enable_syslog = "--syslog" in args
        asyncio.run(_run_monitor(use_mock=use_mock, enable_syslog=enable_syslog, with_dashboard=True))

    elif command == "status":
        _print_status()

    elif command == "campaigns":
        _print_campaigns()

    elif command == "report":
        _generate_report()

    else:
        print("Commands:")
        print("  demo              Single demo cycle with synthetic attack data")
        print("  monitor           Monitor real log files")
        print("  monitor --mock    Monitor with synthetic data stream")
        print("  monitor --syslog  Also start syslog UDP receiver (port 5140)")
        print("  dashboard         Dashboard only (http://localhost:8000)")
        print("  full              Monitor + dashboard together")
        print("  full --mock       Full stack with mock data")
        print("  status            Show alert statistics")
        print("  campaigns         Show attack campaigns")
        print("  report            Generate weekly HTML report")
        print()
        print("Key env vars:")
        print("  ANTHROPIC_API_KEY   Claude AI (enables threat analysis narratives)")
        print("  ABUSEIPDB_KEY       Real IP reputation lookups")
        print("  SLACK_WEBHOOK_URL   Slack alert notifications")
        print()


if __name__ == "__main__":
    main()
