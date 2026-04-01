"""
Isolation Forest anomaly detector.
Refactored from the original AIThreatDetector — now implements BaseDetector
and operates on NormalizedEvent objects.
"""

import logging
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .base_detector import BaseDetector, ThreatCandidate
from config import get_config

logger = logging.getLogger("IsolationForestDetector")


class IsolationForestDetector(BaseDetector):
    def __init__(self, contamination: Optional[float] = None):
        cfg = get_config()
        self.contamination = contamination or cfg.contamination_rate
        self.threshold = cfg.anomaly_threshold
        self.model = IsolationForest(contamination=self.contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self._feature_columns: List[str] = []

    @property
    def name(self) -> str:
        return "IsolationForest"

    def _extract_features(self, events: List[dict]) -> pd.DataFrame:
        """Extract numeric features from normalized event dicts."""
        df = pd.DataFrame(events)
        features = pd.DataFrame()

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            features["hour_of_day"] = df["timestamp"].dt.hour.fillna(0)
            features["day_of_week"] = df["timestamp"].dt.dayofweek.fillna(0)

        if "source_ip" in df.columns:
            ip_counts = df.groupby("source_ip").size().to_dict()
            features["ip_request_count"] = df["source_ip"].map(ip_counts).fillna(1)

        if "request_type" in df.columns:
            request_dummies = pd.get_dummies(df["request_type"], prefix="req")
            features = pd.concat([features, request_dummies], axis=1)

        if "response_code" in df.columns:
            features["is_error"] = (df["response_code"] >= 400).astype(int)
            features["is_server_error"] = (df["response_code"] >= 500).astype(int)

        if "request_size" in df.columns:
            features["request_size"] = pd.to_numeric(df["request_size"], errors="coerce").fillna(0)

        if "response_time" in df.columns:
            features["response_time"] = pd.to_numeric(df["response_time"], errors="coerce").fillna(0)

        return features

    def train(self, events: List[dict]) -> "IsolationForestDetector":
        features = self._extract_features(events)
        numeric = features.select_dtypes(include=[np.number])

        if numeric.empty:
            raise ValueError("No numeric features available for training")

        self._feature_columns = list(numeric.columns)
        scaled = self.scaler.fit_transform(numeric)
        self.model.fit(scaled)
        self.is_trained = True
        logger.info(f"Trained on {len(events)} events with {len(self._feature_columns)} features")
        return self

    def detect(self, events: List) -> List[ThreatCandidate]:
        if not events:
            return []

        # Accept both NormalizedEvent objects and raw dicts
        raw_dicts = [e.__dict__ if hasattr(e, "__dict__") else e for e in events]

        if not self.is_trained:
            logger.warning("Model not trained — running auto-train on current batch")
            self.train(raw_dicts)
            return []  # First batch is training data; no alerts on first pass

        features = self._extract_features(raw_dicts)
        numeric = features.select_dtypes(include=[np.number])

        # Align columns to training feature set
        for col in self._feature_columns:
            if col not in numeric.columns:
                numeric[col] = 0
        numeric = numeric.reindex(columns=self._feature_columns, fill_value=0)

        scaled = self.scaler.transform(numeric)
        scores = self.model.decision_function(scaled)
        predictions = self.model.predict(scaled)

        candidates = []
        for i, (score, pred) in enumerate(zip(scores, predictions)):
            if score < self.threshold or pred == -1:
                event = events[i]
                raw = raw_dicts[i]
                severity = self._score_to_severity(float(score))
                candidates.append(ThreatCandidate(
                    event=event,
                    detector=self.name,
                    severity=severity,
                    anomaly_score=float(score),
                    rule_name=None,
                    description=f"Anomaly score {score:.3f} — unusual pattern detected",
                    source_ip=raw.get("source_ip"),
                    tags=["anomaly", "ml-detected"],
                ))

        return candidates

    def _score_to_severity(self, score: float) -> str:
        if score < -0.8:
            return "CRITICAL"
        elif score < -0.6:
            return "HIGH"
        elif score < -0.4:
            return "MEDIUM"
        return "LOW"

    def save(self, filepath: str) -> None:
        import joblib
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "feature_columns": self._feature_columns,
            "is_trained": self.is_trained,
        }, filepath)
        logger.info(f"Model saved to {filepath}")

    @classmethod
    def load(cls, filepath: str) -> "IsolationForestDetector":
        import joblib
        data = joblib.load(filepath)
        detector = cls()
        detector.model = data["model"]
        detector.scaler = data["scaler"]
        detector._feature_columns = data.get("feature_columns", [])
        detector.is_trained = data["is_trained"]
        logger.info(f"Model loaded from {filepath}")
        return detector
