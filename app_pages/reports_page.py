from __future__ import annotations

import streamlit as st

from alerts import export_csv
from app_pages.common import current_events, page_header

page_header("Reports", "Download a portable CSV summary of analyzed activity and potential alerts.")
events = current_events()
if events.empty:
    st.info("There are no stored events to export.")
    st.stop()

alerts_only = st.toggle("Export potential alerts only", value=False)
mask_ids = st.checkbox("Mask usernames and IP addresses in the export", value=True)
report = events.loc[events["is_anomaly"]] if alerts_only else events
st.metric("Rows in report", f"{len(report):,}")
st.caption(
    "Raw log messages and original uploaded files are not included. "
    "When masking is enabled, usernames, IP addresses, and device names are replaced with salted per-report hashes."
)
st.download_button(
    "Download CSV report",
    data=export_csv(report, anonymize=mask_ids),
    file_name="cybershield-alerts.csv" if alerts_only else "cybershield-events.csv",
    mime="text/csv",
    type="primary",
    width="stretch",
)
