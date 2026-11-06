"""Alert summaries and privacy-conscious report export helpers."""

from __future__ import annotations

import hashlib
import io
import secrets

import pandas as pd

SUGGESTIONS = {
    "Critical": "Review the affected account with its official service. If activity is unauthorized, secure the account through that service and enable multi-factor authentication.",
    "Medium": "Check whether the sign-in or administrative change was expected. Review recent account access and enable multi-factor authentication if available.",
    "Low": "Compare this event with your normal activity. An unusual pattern alone does not confirm an attack.",
}


def suggested_action(risk: str) -> str:
    return SUGGESTIONS.get(risk, "Continue monitoring and review any unfamiliar activity.")


def alerts_frame(events: pd.DataFrame) -> pd.DataFrame:
    alerts = events.loc[events.get("is_anomaly", False).astype(bool)].copy()
    if "detected_at" not in alerts:
        alerts["detected_at"] = alerts["timestamp"]
    else:
        alerts["detected_at"] = alerts["detected_at"].fillna(alerts["timestamp"])
    if "status" not in alerts:
        alerts["status"] = "New"
    alerts["suggested_action"] = alerts["risk"].map(suggested_action)
    return alerts.sort_values(["detected_at", "timestamp"], ascending=False, na_position="last")


def export_csv(events: pd.DataFrame, anonymize: bool = True) -> bytes:
    """Build a CSV report; by default mask direct user and IP identifiers."""
    columns = [
        "timestamp",
        "detected_at",
        "source",
        "user",
        "src_ip",
        "device",
        "event_type",
        "result",
        "risk",
        "alert_title",
        "reasons",
        "anomaly_score",
        "cluster",
        "status",
        "origin",
    ]
    report = events[[column for column in columns if column in events]].copy()
    if anonymize:
        salt = secrets.token_bytes(16)
        prefixes = {"user": "u", "src_ip": "i", "device": "d"}
        for column, prefix in prefixes.items():
            if column in report:
                def mask(value: object, field: str = column, tag: str = prefix) -> object:
                    if pd.isna(value) or str(value) == "unknown":
                        return value
                    digest = hashlib.sha256(salt + (field + ":" + str(value)).encode()).hexdigest()[:8]
                    return f"{tag}-{digest}"

                report[column] = report[column].map(mask)
    buffer = io.StringIO()
    report.to_csv(buffer, index=False)
    return buffer.getvalue().encode("utf-8")
