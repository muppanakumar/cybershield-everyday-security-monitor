from __future__ import annotations

import pandas as pd
import streamlit as st

from alerts import export_csv
from app_pages.common import current_events, page_header

page_header(
    "Threat-hunting workbench",
    "Search and compare activity sequences. Filtered exports mask account, IP, and device identifiers by default.",
)
events = current_events()
if events.empty:
    st.info("Upload or load logs before using the workbench.")
    st.stop()

timed = events.dropna(subset=["timestamp"])
if timed.empty:
    st.warning("These events have no parseable timestamps; date filtering is unavailable.")
    start_date = end_date = None
else:
    min_date = timed["timestamp"].min().date()
    max_date = timed["timestamp"].max().date()
    first, second = st.columns(2)
    with first:
        start_date = st.date_input("From date", value=min_date, min_value=min_date, max_value=max_date)
    with second:
        end_date = st.date_input("To date", value=max_date, min_value=min_date, max_value=max_date)

user_options = ["All"] + sorted(events["user"].dropna().astype(str).unique().tolist())
ip_options = ["All"] + sorted(events["src_ip"].dropna().astype(str).unique().tolist())
type_options = ["All"] + sorted(events["event_type"].dropna().astype(str).unique().tolist())
filters = st.columns(3)
with filters[0]:
    selected_user = st.selectbox("User", user_options)
with filters[1]:
    selected_ip = st.selectbox("IP address", ip_options)
with filters[2]:
    selected_type = st.selectbox("Event type", type_options)
search = st.text_input("Search events", placeholder="Search reasons, source, device, or results")

filtered = events.copy()
if start_date is not None and end_date is not None:
    if start_date > end_date:
        st.error("The start date must be on or before the end date.")
        st.stop()
    event_dates = filtered["timestamp"].dt.date
    filtered = filtered.loc[event_dates.between(start_date, end_date) | event_dates.isna()]
if selected_user != "All":
    filtered = filtered.loc[filtered["user"].eq(selected_user)]
if selected_ip != "All":
    filtered = filtered.loc[filtered["src_ip"].eq(selected_ip)]
if selected_type != "All":
    filtered = filtered.loc[filtered["event_type"].eq(selected_type)]
if search.strip():
    searchable = filtered.astype(str).agg(" ".join, axis=1)
    filtered = filtered.loc[searchable.str.contains(search.strip(), case=False, regex=False, na=False)]

normal_count = int((~filtered["is_anomaly"]).sum())
unusual_count = int(filtered["is_anomaly"].sum())
left, right = st.columns(2)
left.metric("Normal events", f"{normal_count:,}", border=True)
right.metric("Potential anomalies", f"{unusual_count:,}", border=True)

st.caption(f"{len(filtered):,} event(s) match the filters.")
st.dataframe(
    filtered.sort_values("timestamp", ascending=False, na_position="last"),
    hide_index=True,
    alt="Filtered security events with anomaly score, cluster, and reason",
)

if not filtered.empty:
    st.download_button(
        "Download filtered CSV",
        data=export_csv(filtered),
        file_name="cybershield-filtered-report.csv",
        mime="text/csv",
        type="primary",
    )
