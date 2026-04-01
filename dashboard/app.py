"""
Real-time security dashboard — FastAPI + WebSocket.

Endpoints:
  GET  /                    → serve index.html
  GET  /api/alerts          → paginated alert list
  GET  /api/alerts/{id}     → full alert detail + analysis
  POST /api/alerts/{id}/fp  → mark as false positive
  GET  /api/stats           → counts, FP rate, top IPs
  GET  /api/campaigns       → active attack campaigns
  GET  /api/profiles        → UEBA entity baselines
  POST /api/report          → generate weekly HTML report
  WS   /ws/live             → push new alerts in real time

Run with:
    uvicorn dashboard.app:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Set, Optional

logger = logging.getLogger("Dashboard")

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not installed. Run: pip install fastapi uvicorn")

STATIC_DIR = Path(__file__).parent / "static"


class FalsePositiveRequest(BaseModel):
    notes: str = ""


class _ConnectionManager:
    """Manages active WebSocket connections for live alert push."""

    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, data: dict) -> None:
        if not self._connections:
            return
        message = json.dumps(data, default=str)
        dead = set()
        for ws in list(self._connections):
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        self._connections -= dead


manager = _ConnectionManager()


def create_app(
    alert_store=None,
    campaign_tracker=None,
    ueba_detector=None,
):
    """
    Factory function — creates the FastAPI app wired to live data sources.
    Call this from main.py and pass the shared instances.
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI required: pip install fastapi uvicorn")

    from storage.alert_store import AlertStore
    from response.reports import ReportGenerator

    store = alert_store or AlertStore()
    report_gen = ReportGenerator(store)

    app = FastAPI(title="AI Cybersecurity Agent", version="2.0")

    # ------------------------------------------------------------------
    # Static files
    # ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html_path = STATIC_DIR / "index.html"
        if html_path.exists():
            return HTMLResponse(html_path.read_text())
        return HTMLResponse("<h1>Dashboard</h1><p>Static files not found.</p>")

    # ------------------------------------------------------------------
    # REST API
    # ------------------------------------------------------------------

    @app.get("/api/alerts")
    async def get_alerts(
        limit: int = 50,
        severity: Optional[str] = None,
        offset: int = 0,
    ):
        alerts = store.get_recent_alerts(limit=limit + offset, severity=severity)
        return {"alerts": alerts[offset:offset + limit], "total": len(alerts)}

    @app.get("/api/alerts/{alert_id}")
    async def get_alert(alert_id: str):
        alert = store.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert.to_dict()

    @app.post("/api/alerts/{alert_id}/fp")
    async def mark_false_positive(alert_id: str, body: FalsePositiveRequest):
        alert = store.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        store.mark_false_positive(alert_id, notes=body.notes)
        return {"status": "marked_as_false_positive", "alert_id": alert_id}

    @app.get("/api/stats")
    async def get_stats():
        stats = store.get_stats()
        # Top attacking IPs (last 100 alerts)
        recent = store.get_recent_alerts(limit=200)
        ip_counts: dict = {}
        for a in recent:
            ip = a.get("source_ip") or "unknown"
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
        stats["top_attacking_ips"] = [{"ip": ip, "count": c} for ip, c in top_ips]
        return stats

    @app.get("/api/campaigns")
    async def get_campaigns():
        if not campaign_tracker:
            return {"campaigns": [], "message": "Campaign tracking not enabled"}
        active = campaign_tracker.get_active_campaigns()
        all_camps = campaign_tracker.get_all_campaigns(limit=20)
        return {
            "active_count": len(active),
            "campaigns": all_camps,
        }

    @app.get("/api/profiles")
    async def get_profiles():
        if not ueba_detector:
            return {"profiles": [], "message": "UEBA not enabled"}
        profiles = ueba_detector.get_all_profiles()
        return {"profiles": profiles, "count": len(profiles)}

    @app.post("/api/report")
    async def generate_report():
        path = report_gen.generate_weekly_html()
        return {"status": "generated", "path": path}

    # ------------------------------------------------------------------
    # WebSocket live feed
    # ------------------------------------------------------------------

    @app.websocket("/ws/live")
    async def websocket_live(ws: WebSocket):
        await manager.connect(ws)
        logger.info(f"WebSocket client connected: {ws.client}")
        try:
            while True:
                await asyncio.sleep(30)  # Keep-alive ping
                await ws.send_text(json.dumps({"type": "ping"}))
        except WebSocketDisconnect:
            manager.disconnect(ws)
            logger.info(f"WebSocket client disconnected")

    return app, manager


async def push_alert(manager_instance, alert) -> None:
    """Push a new alert to all connected WebSocket clients."""
    if manager_instance:
        data = {
            "type": "new_alert",
            "alert": alert.to_dict() if hasattr(alert, "to_dict") else vars(alert),
        }
        await manager_instance.broadcast(data)
