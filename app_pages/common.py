"""Shared helpers for Streamlit pages."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from anomaly_detection import analyze_events
from data_processing import normalize_logs
from database import load_events
from database import save_events


def page_header(title: str, subtitle: str) -> None:
    st.title(title)
    st.caption(subtitle)


def current_events() -> pd.DataFrame:
    return load_events()


def show_empty_state() -> None:
    st.info("No events have been analysed yet. Go to **Upload Logs** to get started.")


def event_summary(events: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "timestamp",
        "source",
        "user",
        "src_ip",
        "device",
        "event_type",
        "result",
        "risk",
        "reasons",
        "origin",
    ]
    return events[[column for column in columns if column in events]].copy()


def analyze_and_save(data: pd.DataFrame, origin: str = "historical"):
    normalized = normalize_logs(data, origin=origin)
    result = analyze_events(
        normalized,
        eps=float(st.session_state.get("dbscan_eps", 2.8)),
        min_samples=int(st.session_state.get("dbscan_min_samples", 4)),
        test_fraction=float(st.session_state.get("test_fraction", 0.25)),
    )
    saved = save_events(result.events)
    return result, saved
