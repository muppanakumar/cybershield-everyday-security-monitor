from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
import streamlit as st

from anomaly_detection import analyze_events
from app_pages.common import page_header
from data_processing import normalize_logs, read_log_file
from database import load_events, save_events


page_header(
    "Live monitoring",
    "Poll an authorized local append-only log file. Existing file contents are skipped; only new lines are labeled live.",
)

with st.container(border=True):
    path_value = st.text_input("Path to your local log file", key="live_source_path")
    authorized = st.checkbox(
        "I own this source or am authorized to monitor it.",
        key="live_authorized",
    )
    interval = st.selectbox("Polling interval", [5, 10, 30], index=0, format_func=lambda value: f"{value} seconds")
    controls = st.columns(2)
    with controls[0]:
        start = st.button("Start polling", type="primary", width="stretch")
    with controls[1]:
        stop = st.button("Stop polling", width="stretch")

if start:
    if not authorized:
        st.error("Confirm that you are authorized to monitor this source.")
    elif not path_value.strip():
        st.error("Enter a path to a local append-only log file.")
    else:
        try:
            source_path = Path(path_value).expanduser().resolve(strict=True)
            if not source_path.is_file() or source_path.suffix.lower() not in {".csv", ".jsonl", ".txt", ".log"}:
                raise ValueError("Choose an existing .csv, .jsonl, .txt, or .log file.")
            header = ""
            with source_path.open("rb") as stream:
                if source_path.suffix.lower() == ".csv":
                    header = stream.readline().decode("utf-8-sig", errors="replace").strip()
                    if not header:
                        raise ValueError("The CSV source must have a header row.")
                offset = source_path.stat().st_size
            st.session_state["live_state"] = {
                "path": str(source_path),
                "offset": offset,
                "remainder": "",
                "header": header,
                "active": True,
            }
        except (OSError, ValueError) as error:
            st.error(f"Could not start monitoring: {error}")

if stop:
    live_state = st.session_state.get("live_state", {})
    live_state["active"] = False
    st.session_state["live_state"] = live_state


def render_live_updates(path: str, poll_seconds: int) -> None:
    @st.fragment(run_every=poll_seconds)
    def poll_source() -> None:
        state = st.session_state.get("live_state", {})
        if not state.get("active") or state.get("path") != path:
            st.info("Polling is stopped. Start monitoring again to select the current end of the file.")
            return
        source_path = Path(path)
        try:
            current_size = source_path.stat().st_size
            offset = int(state["offset"])
            if current_size < offset:
                state.update(offset=current_size, remainder="")
                st.warning("The source file was truncated; monitoring resumed from its new end.")
                if source_path.suffix.lower() == ".csv":
                    with source_path.open("rb") as stream:
                        state["header"] = stream.readline().decode("utf-8-sig", errors="replace").strip()
                        state["offset"] = stream.tell()
                st.session_state["live_state"] = state
                return
            with source_path.open("rb") as stream:
                stream.seek(offset)
                chunk = stream.read().decode("utf-8", errors="replace")
                state["offset"] = stream.tell()
        except OSError as error:
            st.error(f"Unable to read the monitored file: {error}")
            return

        combined = str(state.get("remainder", "")) + chunk
        lines = combined.splitlines(keepends=True)
        complete = [line for line in lines if line.endswith(("\n", "\r"))]
        state["remainder"] = "".join(line for line in lines if not line.endswith(("\n", "\r")))
        st.session_state["live_state"] = state
        if not complete:
            st.caption("Waiting for a complete appended log line…")
            return

        text = "".join(complete)
        try:
            if source_path.suffix.lower() == ".csv":
                raw = pd.read_csv(io.StringIO(f"{state['header']}\n{text}"))
            else:
                raw = read_log_file(source_path.name, text.encode("utf-8"))
            incoming = normalize_logs(raw, origin="live")
            if incoming.empty:
                st.caption("No new complete event was found.")
                return
            history = load_events(limit=5_000)
            combined_events = pd.concat([history, incoming], ignore_index=True) if not history.empty else incoming
            combined_events = combined_events.drop_duplicates("event_id", keep="last")
            result = analyze_events(
                combined_events,
                eps=float(st.session_state.get("dbscan_eps", 2.8)),
                min_samples=int(st.session_state.get("dbscan_min_samples", 4)),
                test_fraction=float(st.session_state.get("test_fraction", 0.25)),
            )
        except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as error:
            st.error(f"Could not parse the appended lines: {error}")
            return

        new_ids = set(incoming["event_id"])
        fresh = result.events.loc[result.events["event_id"].isin(new_ids)]
        save_events(fresh)
        st.success(f"Received {len(fresh):,} new live event(s).")
        st.dataframe(
            fresh[
                ["timestamp", "source", "user", "src_ip", "event_type", "result", "risk", "reasons", "origin"]
            ],
            hide_index=True,
            alt="New events polled from the authorized local log source",
        )

    poll_source()


live_state = st.session_state.get("live_state", {})
if live_state.get("active"):
    st.success(f"Polling {Path(live_state['path']).name} every {interval} seconds.")
    render_live_updates(live_state["path"], interval)
else:
    st.info("Start polling to begin. Existing lines are intentionally skipped and remain historical.")

st.caption(
    "Polling uses Streamlit fragments; no connection is made to other devices or services. "
    "WebSocket streaming can be added later without changing the normalized event pipeline."
)
