"""DBSCAN-based anomaly detection with an honest chronological holdout."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.metrics import pairwise_distances
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from feature_engineering import build_activity_features
from data_processing import MAX_EVENTS_PER_ANALYSIS


@dataclass
class AnalysisResult:
    events: pd.DataFrame
    train_count: int
    test_count: int
    model_trained: bool
    note: str


def _attach_rule_reasons(frame: pd.DataFrame) -> pd.DataFrame:
    reasons: list[list[str]] = [[] for _ in range(len(frame))]
    failed_windows: dict[str, deque[tuple[pd.Timestamp, int]]] = defaultdict(deque)
    known_ips: dict[str, set[str]] = defaultdict(set)
    known_devices: dict[str, set[str]] = defaultdict(set)
    activity_windows: dict[str, tuple[pd.Timestamp, int]] = {}
    prior_window_counts: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=20))

    ordered = frame.sort_values("timestamp", na_position="last").reset_index()
    for row in ordered.itertuples(index=False):
        output_index = int(row.index)
        timestamp = row.timestamp
        user = str(row.user)
        ip = str(row.src_ip)
        device = str(row.device)
        event_type = str(row.event_type).lower()
        result = str(row.result).lower()

        if pd.notna(timestamp):
            subject = user if user != "unknown" else ip
            bucket = timestamp.floor("15min")
            previous = activity_windows.get(subject)
            if previous is not None and previous[0] != bucket:
                prior_window_counts[subject].append(previous[1])
                previous = None
            count = previous[1] + 1 if previous is not None else 1
            activity_windows[subject] = (bucket, count)
            history = prior_window_counts[subject]
            baseline = float(np.median(history)) if len(history) >= 3 else 0.0
            if count >= max(8, baseline * 4):
                reasons[output_index].append(f"Sudden activity increase: {count} events from this account in 15 minutes")

        if result == "failed" and pd.notna(timestamp):
            window = failed_windows[user if user != "unknown" else ip]
            cutoff = timestamp - pd.Timedelta(minutes=10)
            while window and window[0][0] < cutoff:
                window.popleft()
            window.append((timestamp, output_index))
            if len(window) >= 5:
                for _, affected_index in window:
                    reasons[affected_index].append(f"{len(window)} failed sign-in attempts within 10 minutes")

        if user in known_ips and ip != "unknown" and ip not in known_ips[user]:
            reasons[output_index].append("Sign-in from a new IP address for this account")
        if user in known_devices and device != "unknown" and device not in known_devices[user]:
            reasons[output_index].append("Activity from a new device for this account")
        if user != "unknown":
            if ip != "unknown":
                known_ips[user].add(ip)
            if device != "unknown":
                known_devices[user].add(device)

        if (
            pd.notna(timestamp)
            and 0 <= timestamp.hour <= 4
            and result == "success"
            and ("auth" in event_type or "login" in event_type)
        ):
            reasons[output_index].append("Successful sign-in during a low-activity overnight hour (UTC)")

        is_admin = any(word in event_type for word in ("admin", "privilege", "permission", "sudo", "root"))
        if is_admin and result != "failed":
            reasons[output_index].append("Administrative or permission-changing activity needs review")

    frame["reasons"] = ["; ".join(dict.fromkeys(items)) for items in reasons]
    return frame


def _assign_risk(frame: pd.DataFrame) -> pd.DataFrame:
    risk: list[str] = []
    titles: list[str] = []
    reason_values = frame["reasons"].tolist()
    for position, row in enumerate(frame.itertuples(index=False)):
        reasons = row.reasons.split("; ") if row.reasons else []
        is_anomaly = bool(reasons) or row.cluster == -1
        if not is_anomaly:
            risk.append("None")
            titles.append("")
            continue
        failed_burst = any("failed sign-in attempts" in reason for reason in reasons)
        overnight = any("overnight hour" in reason for reason in reasons)
        administrative = any("Administrative" in reason for reason in reasons)
        new_origin = any("new IP" in reason or "new device" in reason for reason in reasons)
        failed_count = max(
            (
                int(reason.split()[0])
                for reason in reasons
                if reason.split() and reason.split()[0].isdigit() and "failed sign-in attempts" in reason
            ),
            default=0,
        )
        if failed_count >= 8:
            level = "Critical"
        elif failed_burst or any("Sudden activity increase" in reason for reason in reasons) or (administrative and overnight) or (new_origin and overnight):
            level = "Medium"
        else:
            level = "Low"
        if reasons:
            title = reasons[0].split(" (", maxsplit=1)[0].capitalize()
        else:
            title = "Activity outside the learned DBSCAN clusters"
            reasons = ["Event was classified as DBSCAN noise; this is a possible anomaly, not a confirmed attack."]
            reason_values[position] = "; ".join(reasons)
        risk.append(level)
        titles.append(title)
    frame["reasons"] = reason_values
    frame["risk"] = risk
    frame["alert_title"] = titles
    frame["is_anomaly"] = frame["risk"].ne("None")
    frame["detected_at"] = pd.Series(pd.NaT, index=frame.index, dtype="datetime64[ns, UTC]")
    detected_at = pd.Timestamp(datetime.now(timezone.utc))
    frame.loc[frame["is_anomaly"], "detected_at"] = detected_at
    return frame


def analyze_events(
    events: pd.DataFrame,
    eps: float = 2.8,
    min_samples: int = 4,
    test_fraction: float = 0.25,
) -> AnalysisResult:
    """Fit DBSCAN only on earlier events; score later events against its core points."""
    if events.empty:
        raise ValueError("Add at least one security event before analysis.")
    if len(events) > MAX_EVENTS_PER_ANALYSIS:
        raise ValueError(
            f"DBSCAN analysis is limited to {MAX_EVENTS_PER_ANALYSIS:,} events at a time. "
            "Split larger logs into chronological files before analysis."
        )
    if not 0.05 <= test_fraction <= 0.5:
        raise ValueError("The later test portion must be between 5% and 50%.")
    if eps <= 0 or min_samples < 2:
        raise ValueError("DBSCAN epsilon must be positive and min_samples must be at least 2.")

    frame = events.sort_values("timestamp", na_position="last").reset_index(drop=True).copy()
    frame["cluster"] = -2
    frame["anomaly_score"] = 0.0
    count = len(frame)
    test_count = max(1, int(np.ceil(count * test_fraction))) if count >= 8 else 0
    train_count = count - test_count
    model_trained = count >= 8 and train_count >= 5

    if model_trained:
        training = frame.iloc[:train_count]
        testing = frame.iloc[train_count:]
        train_numeric, train_categorical = build_activity_features(training)
        test_numeric, test_categorical = build_activity_features(testing, reference=training)
        scaler = StandardScaler()
        train_scaled = scaler.fit_transform(train_numeric)
        test_scaled = scaler.transform(test_numeric)
        encoder = OneHotEncoder(handle_unknown="ignore", min_frequency=2, sparse_output=False)
        train_encoded = encoder.fit_transform(train_categorical)
        test_encoded = encoder.transform(test_categorical)
        train_matrix = np.column_stack((train_scaled, train_encoded))
        test_matrix = np.column_stack((test_scaled, test_encoded))

        model = DBSCAN(eps=eps, min_samples=min(min_samples, train_count))
        train_labels = model.fit_predict(train_matrix)
        frame.loc[: train_count - 1, "cluster"] = train_labels
        frame.loc[: train_count - 1, "anomaly_score"] = (train_labels == -1).astype(float)

        core_positions = model.core_sample_indices_
        if len(core_positions):
            distances = pairwise_distances(test_matrix, train_matrix[core_positions])
            nearest_positions = distances.argmin(axis=1)
            nearest_distances = distances[np.arange(len(test_matrix)), nearest_positions]
            nearest_labels = train_labels[core_positions[nearest_positions]]
            test_labels = np.where(nearest_distances <= eps, nearest_labels, -1)
            test_scores = np.minimum(nearest_distances / eps, 1.0)
        else:
            test_labels = np.full(len(testing), -1, dtype=int)
            test_scores = np.ones(len(testing), dtype=float)
        frame.loc[train_count:, "cluster"] = test_labels
        frame.loc[train_count:, "anomaly_score"] = test_scores
        note = (
            f"DBSCAN trained on the first {train_count:,} chronological events; "
            f"the later {test_count:,} events were scored against training core points."
        )
    else:
        note = "DBSCAN needs at least 8 events; rule-based checks are still available for this dataset."

    frame = _attach_rule_reasons(frame)
    model_noise = frame["cluster"].eq(-1)
    frame.loc[model_noise & frame["reasons"].eq(""), "reasons"] = (
        "Event did not fit a recurring DBSCAN cluster; this is a possible anomaly, not a confirmed attack."
    )
    frame = _assign_risk(frame)
    return AnalysisResult(
        events=frame,
        train_count=train_count if model_trained else 0,
        test_count=test_count,
        model_trained=model_trained,
        note=note,
    )
