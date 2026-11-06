from __future__ import annotations

import streamlit as st

from app_pages.common import current_events, page_header
from database import clear_events

page_header("Settings", "Adjust analysis behavior and review how your security data is handled.")

with st.form("analysis_settings"):
    st.subheader("DBSCAN analysis")
    eps = st.number_input(
        "Epsilon (neighborhood distance)",
        min_value=0.1,
        max_value=20.0,
        value=float(st.session_state.get("dbscan_eps", 2.8)),
        step=0.1,
        key="settings_eps",
        help="Smaller values create tighter activity clusters and can flag more events as unusual.",
    )
    min_samples = st.number_input(
        "Minimum samples per cluster",
        min_value=2,
        max_value=50,
        value=int(st.session_state.get("dbscan_min_samples", 4)),
        step=1,
        key="settings_min_samples",
    )
    test_fraction = st.slider(
        "Chronological test portion",
        min_value=0.05,
        max_value=0.5,
        value=float(st.session_state.get("test_fraction", 0.25)),
        step=0.05,
        format="%.0f%%",
        key="settings_test_fraction",
    )
    if st.form_submit_button("Save analysis settings", type="primary"):
        st.session_state["dbscan_eps"] = float(eps)
        st.session_state["dbscan_min_samples"] = int(min_samples)
        st.session_state["test_fraction"] = float(test_fraction)
        st.success("Analysis settings saved for this session.")

with st.expander("Privacy and local storage", expanded=True):
    st.write(
        "Uploaded files are read in memory and are not written to disk. The app stores normalized event fields "
        "(including usernames and IP addresses), anomaly explanations, and alert review statuses in the local "
        "`cybershield.db` SQLite file. Raw log messages are not retained. Reports omit raw messages and mask "
        "usernames and IP addresses by default."
    )
    st.write(
        "Use only logs you own or are authorized to analyze. Do not upload passwords, private messages, or "
        "unrelated personal information. The app does not block accounts or devices and never asks for passwords."
    )

with st.expander("Model limitations"):
    st.write(
        "DBSCAN is an unsupervised pattern detector, not an intrusion classifier. Noise points are candidates "
        "for human review and may be harmless. New systems, sparse logs, missing timestamps, or changing routines "
        "can produce false positives and missed activity. Rule checks are also heuristic. Verify alerts through "
        "the official service or device before taking action."
    )

events = current_events()
st.metric("Stored normalized events", f"{len(events):,}")
st.caption("Appearance: use the Streamlit menu → Settings → Theme to switch between light and dark.")

if "confirm_clear_events" not in st.session_state:
    st.session_state["confirm_clear_events"] = False
if not st.session_state["confirm_clear_events"]:
    if st.button("Clear local event history", type="secondary"):
        st.session_state["confirm_clear_events"] = True
        st.rerun()
else:
    st.warning("This permanently removes all normalized events and alert review statuses from the local database.")
    confirm, cancel = st.columns(2)
    with confirm:
        if st.button("Permanently clear local data", type="primary"):
            clear_events()
            st.session_state["confirm_clear_events"] = False
            st.success("Local event history cleared.")
            st.rerun()
    with cancel:
        if st.button("Cancel"):
            st.session_state["confirm_clear_events"] = False
            st.rerun()
