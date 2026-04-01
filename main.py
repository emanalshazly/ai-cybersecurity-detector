"""
AI Cybersecurity Agent — Main Entry Point

Usage:
    python main.py demo           Run a single demo cycle with mock attack data
    python main.py monitor        Start continuous monitoring (requires log files or mock mode)
    python main.py monitor --mock Use mock data source (no real log files needed)
    python main.py status         Show alert statistics from the database
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime

from config import get_config

# ── Logging setup ─────────────────────────────────────────────────────────────
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


def _print_banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════╗
║          AI CYBERSECURITY AGENT  v2.0                    ║
║  Powered by Claude claude-opus-4-6 + Isolation Forest        ║
╚══════════════════════════════════════════════════════════╝
""")


def _print_status() -> None:
    """Print alert statistics from the database."""
    from storage.alert_store import AlertStore
    store = AlertStore()
    stats = store.get_stats()
    recent = store.get_recent_alerts(limit=10)

    print("\n  ALERT STATISTICS")
    print(f"  Total alerts : {stats['total']}")
    print(f"  CRITICAL     : {stats['by_severity']['CRITICAL']}")
    print(f"  HIGH         : {stats['by_severity']['HIGH']}")
    print(f"  MEDIUM       : {stats['by_severity']['MEDIUM']}")
    print(f"  LOW          : {stats['by_severity']['LOW']}")
    print(f"  False pos.   : {stats['false_positives']} ({stats['fp_rate']:.1%})")

    if recent:
        print("\n  RECENT ALERTS (last 10):")
        for a in recent:
            ts = a.get("timestamp", "")[:19]
            print(
                f"  [{a['severity']:<8}] {a['id']}  "
                f"IP={a.get('source_ip','?'):<18} "
                f"Rule={a.get('rule_name','anomaly') or 'anomaly':<25} "
                f"@ {ts}"
            )
    print()


async def _run_demo() -> None:
    """
    Run one full agent cycle with synthetic attack data.
    Great for testing the system without real log files.
    """
    from ingestors.mock_ingestor import MockIngestor
    from agent.orchestrator import SecurityOrchestrator

    print("\n  Running DEMO mode with synthetic attack data...")
    print(f"  API key configured: {'YES' if cfg.anthropic_api_key else 'NO (offline analysis only)'}\n")

    ingestor = MockIngestor(
        events_per_poll=80,
        attack_rate=0.15,
        attack_scenario="mixed",
    )

    orchestrator = SecurityOrchestrator(
        ingestors=[ingestor],
        alert_store=None,  # Uses default DB path from config
    )

    # Warm up the ML model with normal traffic first
    print("  Warming up ML model with normal traffic...")
    from ingestors.mock_ingestor import MockIngestor as MI
    warmup_ingestor = MI(events_per_poll=300, attack_rate=0.0)
    warmup_events = warmup_ingestor.poll()
    from detectors.isolation_forest import IsolationForestDetector
    for detector in orchestrator.detectors:
        if isinstance(detector, IsolationForestDetector):
            event_dicts = [e.to_dict() for e in warmup_events]
            detector.train(event_dicts)
            print(f"  ML model trained on {len(warmup_events)} events")

    # Run one detection cycle
    print("  Running detection cycle...")
    alerts = await orchestrator.run_once()

    print(f"\n  Results: {len(alerts)} alert(s) generated")
    for alert in alerts[:10]:
        print(
            f"    [{alert.severity:<8}] {alert.id}  "
            f"IP={alert.source_ip or '?':<18} "
            f"Rule={alert.rule_name or 'anomaly':<25}"
        )
        if alert.analysis:
            # Print first line of analysis
            first_line = alert.analysis.split("\n")[0][:80]
            print(f"             Analysis: {first_line}")

    # Save model
    try:
        from detectors.isolation_forest import IsolationForestDetector
        for d in orchestrator.detectors:
            if isinstance(d, IsolationForestDetector) and d.is_trained:
                d.save(cfg.model_path)
                print(f"\n  ML model saved to {cfg.model_path}")
    except Exception as e:
        logger.warning(f"Could not save model: {e}")

    print(f"\n  Alerts persisted to: {cfg.db_path}")
    print(f"  Full logs in: {cfg.log_file}")
    print()


async def _run_monitor(use_mock: bool = False) -> None:
    """Start continuous monitoring."""
    from agent.orchestrator import SecurityOrchestrator

    ingestors = []

    if use_mock:
        from ingestors.mock_ingestor import MockIngestor
        ingestors.append(MockIngestor(events_per_poll=30, attack_rate=0.08))
        print("  Using MOCK data source")
    elif cfg.monitored_log_files:
        from ingestors.file_ingestor import FileIngestor
        ingestors.append(FileIngestor(cfg.monitored_log_files))
        print(f"  Monitoring log files: {cfg.monitored_log_files}")
    else:
        print("  No log files found. Run with --mock flag or set log paths in config.")
        print("  Example: python main.py monitor --mock")
        return

    # Load existing model if available
    detectors = None
    if os.path.exists(cfg.model_path):
        try:
            from detectors.isolation_forest import IsolationForestDetector
            from detectors.signature_detector import SignatureDetector
            iso = IsolationForestDetector.load(cfg.model_path)
            detectors = [iso, SignatureDetector()]
            print(f"  Loaded ML model from {cfg.model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e} — will train on first batch")

    orchestrator = SecurityOrchestrator(ingestors=ingestors, detectors=detectors)

    print(f"  Poll interval: {cfg.poll_interval_seconds}s")
    print(f"  Min severity: {cfg.alert_min_severity}")
    print(f"  Claude AI: {'ENABLED' if cfg.anthropic_api_key else 'DISABLED (set ANTHROPIC_API_KEY)'}")
    print(f"  Slack: {'ENABLED' if cfg.slack_webhook_url else 'DISABLED'}")
    print("\n  Agent running. Press Ctrl+C to stop.\n")

    try:
        await orchestrator.run()
    except KeyboardInterrupt:
        orchestrator.stop()
        print("\n  Agent stopped.")


def main() -> None:
    _print_banner()

    args = sys.argv[1:]
    command = args[0] if args else "help"

    if command == "demo":
        asyncio.run(_run_demo())
    elif command == "monitor":
        use_mock = "--mock" in args
        asyncio.run(_run_monitor(use_mock=use_mock))
    elif command == "status":
        _print_status()
    else:
        print("Usage:")
        print("  python main.py demo              Run demo with synthetic attack data")
        print("  python main.py monitor           Monitor real log files")
        print("  python main.py monitor --mock    Monitor with synthetic data stream")
        print("  python main.py status            Show alert statistics")
        print()
        print("Environment variables:")
        print("  ANTHROPIC_API_KEY   Claude AI API key (enables intelligent threat analysis)")
        print("  SLACK_WEBHOOK_URL   Slack webhook for notifications")
        print("  ALERT_EMAIL_TO      Email address for critical alerts")
        print("  AUTO_BLOCK_CRITICAL Set to 'true' to auto-block CRITICAL IPs (use with caution)")
        print()


if __name__ == "__main__":
    main()
