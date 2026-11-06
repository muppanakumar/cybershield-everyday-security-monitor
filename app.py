"""CyberShield — Everyday Security Monitor."""

from __future__ import annotations

import streamlit as st

from database import initialize_database

st.set_page_config(
    page_title="CyberShield — Everyday Security Monitor",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

initialize_database()
st.session_state.setdefault("dbscan_eps", 2.8)
st.session_state.setdefault("dbscan_min_samples", 4)
st.session_state.setdefault("test_fraction", 0.25)

pages = {
    "Monitor": [
        st.Page(
            "app_pages/dashboard_page.py",
            title="Dashboard",
            icon=":material/dashboard:",
            help="See the current security status, event totals, recent activity, and daily and weekly trends.",
        ),
        st.Page(
            "app_pages/upload_page.py",
            title="Upload Logs",
            icon=":material/upload_file:",
            help="Import authorized CSV, JSON, JSONL, or text security logs and analyse them locally.",
        ),
        st.Page(
            "app_pages/live_page.py",
            title="Live Monitoring",
            icon=":material/sensors:",
            help="Poll an authorized local append-only log file and display only newly appended events as live.",
        ),
        st.Page(
            "app_pages/anomaly_page.py",
            title="Anomaly Detection",
            icon=":material/auto_awesome:",
            help="Review DBSCAN clusters, the chronological holdout, anomaly scores, and detection limitations.",
        ),
    ],
    "Investigate": [
        st.Page(
            "app_pages/alerts_page.py",
            title="Security Alerts",
            icon=":material/notifications_active:",
            help="Review potential alerts, understand their reasons, and record a review status.",
        ),
        st.Page(
            "app_pages/workbench_page.py",
            title="Threat-Hunting Workbench",
            icon=":material/search:",
            help="Search, filter, and compare analyzed event sequences and export a focused report.",
        ),
        st.Page(
            "app_pages/reports_page.py",
            title="Reports",
            icon=":material/description:",
            help="Export analyzed events and alerts to CSV with identifier masking enabled by default.",
        ),
    ],
    "Configure": [
        st.Page(
            "app_pages/settings_page.py",
            title="Settings",
            icon=":material/settings:",
            help="Set DBSCAN analysis parameters, review local data handling, and inspect model limitations.",
        ),
    ],
}

page = st.navigation(pages, position="sidebar")
with st.sidebar:
    st.divider()
    st.caption("CyberShield analyses only logs you are authorized to access.")
    st.caption("Uploads are processed in memory; normalized events are stored in local SQLite.")

page.run()
