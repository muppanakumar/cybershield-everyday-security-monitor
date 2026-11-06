"""Numeric and categorical features for activity-level anomaly detection."""

from __future__ import annotations

import numpy as np
import pandas as pd

CATEGORICAL_FEATURES = ("event_type", "result", "source")
NUMERIC_FEATURES = (
    "hour_sin",
    "hour_cos",
    "weekday_sin",
    "weekday_cos",
    "window_event_count",
    "bytes_log",
    "new_ip",
    "new_device",
    "is_admin",
    "is_failed",
)


def build_activity_features(
    events: pd.DataFrame, reference: pd.DataFrame | None = None
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Create per-event time, five-minute activity, novelty, and category features."""
    frame = events.reset_index(drop=True).copy()
    timestamps = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    hour = timestamps.dt.hour.fillna(12).astype(float) + timestamps.dt.minute.fillna(0) / 60
    weekday = timestamps.dt.day_of_week.fillna(0).astype(float)
    window = timestamps.dt.floor("5min").astype("string").fillna("unknown")

    group_keys = pd.DataFrame(
        {
            "user": frame["user"].astype(str),
            "src_ip": frame["src_ip"].astype(str),
            "event_type": frame["event_type"].astype(str),
            "window": window,
        }
    )
    window_count = group_keys.groupby(["user", "src_ip", "event_type", "window"], dropna=False)["window"].transform("size")

    if reference is None or reference.empty:
        ip_seen = frame.assign(user=frame["user"].astype(str), src_ip=frame["src_ip"].astype(str)).groupby("user")["src_ip"].transform(
            lambda values: values.duplicated()
        )
        device_seen = frame.assign(user=frame["user"].astype(str), device=frame["device"].astype(str)).groupby("user")["device"].transform(
            lambda values: values.duplicated()
        )
        new_ip = (~ip_seen).astype(float).to_numpy()
        new_device = (~device_seen).astype(float).to_numpy()
    else:
        known_ips = reference.groupby(reference["user"].astype(str))["src_ip"].agg(lambda values: set(values.astype(str))).to_dict()
        known_devices = reference.groupby(reference["user"].astype(str))["device"].agg(
            lambda values: set(values.astype(str))
        ).to_dict()
        new_ip = np.fromiter(
            (
                float(ip not in known_ips.get(user, set()) and bool(known_ips.get(user)))
                for user, ip in zip(frame["user"].astype(str), frame["src_ip"].astype(str))
            ),
            dtype=float,
            count=len(frame),
        )
        new_device = np.fromiter(
            (
                float(device not in known_devices.get(user, set()) and bool(known_devices.get(user)))
                for user, device in zip(frame["user"].astype(str), frame["device"].astype(str))
            ),
            dtype=float,
            count=len(frame),
        )

    event_type = frame["event_type"].astype(str).str.lower()
    result = frame["result"].astype(str).str.lower()
    numeric = pd.DataFrame(
        {
            "hour_sin": np.sin(2 * np.pi * hour / 24),
            "hour_cos": np.cos(2 * np.pi * hour / 24),
            "weekday_sin": np.sin(2 * np.pi * weekday / 7),
            "weekday_cos": np.cos(2 * np.pi * weekday / 7),
            "window_event_count": np.log1p(window_count.to_numpy(dtype=float)),
            "bytes_log": np.log1p(pd.to_numeric(frame["bytes"], errors="coerce").fillna(0).to_numpy(dtype=float)),
            "new_ip": new_ip,
            "new_device": new_device,
            "is_admin": event_type.str.contains(r"admin|privilege|permission|sudo|root", regex=True).astype(float),
            "is_failed": result.eq("failed").astype(float),
        }
    ).loc[:, NUMERIC_FEATURES]
    categorical = frame.loc[:, CATEGORICAL_FEATURES].fillna("unknown").astype(str).reset_index(drop=True)
    return numeric.replace([np.inf, -np.inf], 0).fillna(0), categorical
