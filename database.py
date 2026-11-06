"""Small local SQLite store for normalized events and alert review state."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

DB_PATH = Path(__file__).resolve().with_name("cybershield.db")
EVENT_COLUMNS = (
    "event_id",
    "timestamp",
    "detected_at",
    "source",
    "user",
    "src_ip",
    "event_type",
    "result",
    "device",
    "bytes",
    "origin",
    "cluster",
    "anomaly_score",
    "risk",
    "alert_title",
    "reasons",
    "is_anomaly",
)


@contextmanager
def _connect(db_path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(str(db_path or DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(db_path: str | Path | None = None) -> None:
    with _connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                detected_at TEXT,
                source TEXT NOT NULL,
                user TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                result TEXT NOT NULL,
                device TEXT NOT NULL,
                bytes REAL NOT NULL DEFAULT 0,
                origin TEXT NOT NULL DEFAULT 'historical',
                cluster INTEGER NOT NULL DEFAULT -2,
                anomaly_score REAL NOT NULL DEFAULT 0,
                risk TEXT NOT NULL DEFAULT 'None',
                alert_title TEXT NOT NULL DEFAULT '',
                reasons TEXT NOT NULL DEFAULT '',
                is_anomaly INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'New',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk);
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(events)")}
        if "detected_at" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN detected_at TEXT")


def save_events(events: pd.DataFrame, db_path: str | Path | None = None) -> int:
    if events.empty:
        return 0
    missing = set(EVENT_COLUMNS).difference(events.columns)
    if missing:
        raise ValueError(f"Cannot save events; missing fields: {', '.join(sorted(missing))}.")
    placeholders = ",".join("?" for _ in EVENT_COLUMNS)
    columns = ",".join(EVENT_COLUMNS)
    updates = ",".join(
        f"{column}=excluded.{column}"
        for column in EVENT_COLUMNS
        if column != "event_id"
    )
    rows: list[tuple[Any, ...]] = []
    for row in events.loc[:, EVENT_COLUMNS].itertuples(index=False, name=None):
        values = dict(zip(EVENT_COLUMNS, row))
        for column in ("timestamp", "detected_at"):
            values[column] = None if pd.isna(values[column]) else pd.Timestamp(values[column]).isoformat()
        values["bytes"] = float(values["bytes"] or 0)
        values["cluster"] = int(values["cluster"])
        values["anomaly_score"] = float(values["anomaly_score"])
        values["is_anomaly"] = int(bool(values["is_anomaly"]))
        rows.append(tuple(values[column] for column in EVENT_COLUMNS))
    with _connect(db_path) as connection:
        before = connection.total_changes
        connection.executemany(
            f"INSERT INTO events ({columns}) VALUES ({placeholders}) "
            f"ON CONFLICT(event_id) DO UPDATE SET {updates}, updated_at=CURRENT_TIMESTAMP",
            rows,
        )
        return connection.total_changes - before


def load_events(db_path: str | Path | None = None, limit: int = 20_000) -> pd.DataFrame:
    if limit < 1:
        raise ValueError("The event limit must be positive.")
    with _connect(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    frame = pd.DataFrame([dict(row) for row in rows])
    if frame.empty:
        return frame
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame["detected_at"] = pd.to_datetime(frame["detected_at"], errors="coerce", utc=True)
    frame["is_anomaly"] = frame["is_anomaly"].astype(bool)
    return frame.sort_values("timestamp", na_position="last").reset_index(drop=True)


def update_alert_status(event_id: str, status: str, db_path: str | Path | None = None) -> None:
    allowed = {"New", "Reviewed", "Resolved", "False positive"}
    if status not in allowed:
        raise ValueError("Choose New, Reviewed, Resolved, or False positive.")
    with _connect(db_path) as connection:
        cursor = connection.execute("UPDATE events SET status=? WHERE event_id=? AND is_anomaly=1", (status, event_id))
        if cursor.rowcount == 0:
            raise ValueError("The alert no longer exists or has already been removed.")


def clear_events(db_path: str | Path | None = None) -> None:
    with _connect(db_path) as connection:
        connection.execute("DELETE FROM events")
