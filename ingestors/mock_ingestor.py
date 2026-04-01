"""
Mock ingestor for demos, testing, and development.
Generates realistic synthetic log events including injected attack patterns.
"""

import uuid
import random
import logging
from datetime import datetime, timedelta
from typing import List

import numpy as np

from .base_ingestor import BaseIngestor, NormalizedEvent

logger = logging.getLogger("MockIngestor")

NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 30)]
ATTACK_IPS = ["10.0.0.99", "185.220.101.15", "194.165.16.5"]
ENDPOINTS = ["/", "/api/data", "/user/profile", "/settings", "/dashboard", "/api/reports"]
LOGIN_ENDPOINTS = ["/api/login", "/auth/token", "/signin"]
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]
ATTACK_UAS = [
    "sqlmap/1.7.8#stable",
    "Nikto/2.1.6",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
]


class MockIngestor(BaseIngestor):
    """
    Generates synthetic events for demos and testing.
    Produces a mix of normal traffic + configurable attack scenarios.
    """

    def __init__(
        self,
        events_per_poll: int = 50,
        attack_rate: float = 0.05,
        attack_scenario: str = "mixed",  # "brute_force", "sqli", "scan", "mixed"
    ):
        self.events_per_poll = events_per_poll
        self.attack_rate = attack_rate
        self.attack_scenario = attack_scenario
        self._poll_count = 0
        logger.info(f"MockIngestor: {events_per_poll} events/poll, {attack_rate:.0%} attack rate, scenario={attack_scenario}")

    @property
    def name(self) -> str:
        return "MockIngestor"

    def poll(self) -> List[NormalizedEvent]:
        self._poll_count += 1
        events = []
        now = datetime.utcnow()

        # Normal traffic
        normal_count = int(self.events_per_poll * (1 - self.attack_rate))
        for _ in range(normal_count):
            events.append(self._normal_event(now))

        # Attack traffic
        attack_count = self.events_per_poll - normal_count
        for _ in range(attack_count):
            events.append(self._attack_event(now))

        random.shuffle(events)
        return events

    def _normal_event(self, now: datetime) -> NormalizedEvent:
        delta = timedelta(seconds=random.randint(0, 300))
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=now - delta,
            source="mock_access_log",
            source_ip=random.choice(NORMAL_IPS),
            request_type=random.choices(["GET", "POST", "PUT"], weights=[0.7, 0.2, 0.1])[0],
            endpoint=random.choice(ENDPOINTS),
            response_code=random.choices([200, 301, 302, 404], weights=[0.85, 0.05, 0.05, 0.05])[0],
            response_time=max(0.01, random.gauss(0.2, 0.05)),
            request_size=max(100, int(random.gauss(500, 100))),
            response_size=max(500, int(random.gauss(5000, 1000))),
            user_agent=random.choice(NORMAL_UAS),
        )

    def _attack_event(self, now: datetime) -> NormalizedEvent:
        scenario = self.attack_scenario
        if scenario == "mixed":
            scenario = random.choice(["brute_force", "sqli", "scan", "exfil", "dos"])

        if scenario == "brute_force":
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(seconds=random.randint(0, 30)),
                source="mock_access_log",
                source_ip=random.choice(ATTACK_IPS),
                request_type="POST",
                endpoint=random.choice(LOGIN_ENDPOINTS),
                response_code=random.choice([401, 403]),
                response_time=max(0.05, random.gauss(0.1, 0.02)),
                request_size=random.randint(200, 400),
                user_agent=NORMAL_UAS[0],
                message="Failed login attempt",
            )

        elif scenario == "sqli":
            payloads = [
                "/api/users?id=1' OR '1'='1",
                "/search?q=1; DROP TABLE users--",
                "/api/data?filter=1 UNION SELECT * FROM passwords",
            ]
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(seconds=random.randint(0, 60)),
                source="mock_access_log",
                source_ip=random.choice(ATTACK_IPS),
                request_type="GET",
                endpoint=random.choice(payloads),
                response_code=random.choice([200, 400, 500]),
                response_time=random.gauss(0.3, 0.1),
                request_size=random.randint(300, 600),
                user_agent=ATTACK_UAS[0],
            )

        elif scenario == "scan":
            scan_paths = [
                "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/",
                "/admin/", "/backup.sql", "/config.php", "/.htaccess",
            ]
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(seconds=random.randint(0, 10)),
                source="mock_access_log",
                source_ip=random.choice(ATTACK_IPS),
                request_type="GET",
                endpoint=random.choice(scan_paths),
                response_code=404,
                response_time=random.gauss(0.05, 0.01),
                request_size=random.randint(100, 200),
                user_agent=random.choice(ATTACK_UAS),
            )

        elif scenario == "exfil":
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(seconds=random.randint(0, 120)),
                source="mock_access_log",
                source_ip=random.choice(NORMAL_IPS),
                request_type="GET",
                endpoint="/api/export/users",
                response_code=200,
                response_time=random.gauss(5.0, 1.0),
                request_size=random.randint(200, 400),
                response_size=random.randint(15_000_000, 50_000_000),  # 15-50 MB
                user_agent=NORMAL_UAS[0],
            )

        else:  # dos
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(seconds=random.randint(0, 5)),
                source="mock_access_log",
                source_ip=random.choice(ATTACK_IPS),
                request_type="GET",
                endpoint=random.choice(ENDPOINTS),
                response_code=500,
                response_time=random.gauss(15.0, 3.0),
                request_size=random.randint(400, 800),
                user_agent=NORMAL_UAS[0],
                message="Internal server error",
            )
