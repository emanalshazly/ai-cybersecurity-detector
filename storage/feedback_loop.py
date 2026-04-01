"""
Feedback loop — closes the learning cycle.
When analysts mark false positives via the dashboard or CLI, this module
collects those labels, builds a training dataset, and retrains the
IsolationForest. Also computes model drift (FP rate over time).
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

logger = logging.getLogger("FeedbackLoop")

MIN_LABELS_TO_RETRAIN = 30   # Minimum labeled samples before retraining
RETRAIN_INTERVAL_HOURS = 6   # Don't retrain more often than this


class FeedbackLoop:
    """
    Collects analyst TP/FP feedback from the alert store and
    triggers IsolationForest retraining when enough labels accumulate.
    """

    def __init__(self, alert_store, isolation_forest_detector, model_path: str):
        self.store = alert_store
        self.detector = isolation_forest_detector
        self.model_path = model_path
        self._last_retrain: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_retrain(self) -> Tuple[bool, str]:
        """Return (should_retrain, reason)."""
        if self._last_retrain:
            since = datetime.utcnow() - self._last_retrain
            if since < timedelta(hours=RETRAIN_INTERVAL_HOURS):
                return False, f"Last retrain {since.seconds // 60}m ago — cooldown active"

        labeled = self.store.get_labeled_training_data()
        if len(labeled) < MIN_LABELS_TO_RETRAIN:
            return False, f"Only {len(labeled)} labeled samples (need {MIN_LABELS_TO_RETRAIN})"

        return True, f"{len(labeled)} labeled samples available"

    def retrain_if_ready(self) -> bool:
        """
        Check if retraining conditions are met and retrain if so.
        Returns True if retraining happened.
        """
        should, reason = self.should_retrain()
        if not should:
            logger.debug(f"Retrain skipped: {reason}")
            return False

        logger.info(f"Retraining model: {reason}")
        labeled = self.store.get_labeled_training_data()

        # Separate true positives (confirmed threats) from false positives
        tp_events = [row["event"] for row in labeled if not row["is_false_positive"]]
        fp_events = [row["event"] for row in labeled if row["is_false_positive"]]

        logger.info(f"Training data: {len(tp_events)} confirmed threats, {len(fp_events)} false positives")

        # Retrain using only the true positives as the "normal + anomaly" mix
        # False positives are treated as normal behavior to reduce future FP rate
        all_events = fp_events + tp_events
        if len(all_events) < 10:
            logger.warning("Not enough valid events for retraining")
            return False

        try:
            self.detector.train(all_events)
            self.detector.save(self.model_path)
            self._last_retrain = datetime.utcnow()
            logger.info(f"Model retrained on {len(all_events)} samples and saved to {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            return False

    def compute_drift_metrics(self) -> dict:
        """
        Compare FP rate over the last 7 days vs the 7 days before that.
        A rising FP rate indicates model drift.
        """
        now = datetime.utcnow()
        week1_start = now - timedelta(days=14)
        week1_end = now - timedelta(days=7)
        week2_start = now - timedelta(days=7)

        w1_alerts = self.store.get_alerts_in_range(week1_start, week1_end)
        w2_alerts = self.store.get_alerts_in_range(week2_start, now)

        def fp_rate(alerts):
            if not alerts:
                return 0.0
            fps = sum(1 for a in alerts if a.get("is_false_positive"))
            return round(fps / len(alerts), 3)

        w1_rate = fp_rate(w1_alerts)
        w2_rate = fp_rate(w2_alerts)
        drift = round(w2_rate - w1_rate, 3)

        return {
            "period_1_fp_rate": w1_rate,
            "period_2_fp_rate": w2_rate,
            "drift": drift,
            "drift_status": "stable" if abs(drift) < 0.05 else ("rising" if drift > 0 else "improving"),
            "recommendation": (
                "Retrain recommended — FP rate rising significantly"
                if drift > 0.1 else
                "Model performance stable"
            ),
        }
