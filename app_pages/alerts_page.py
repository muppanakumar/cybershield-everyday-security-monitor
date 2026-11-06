from __future__ import annotations

import streamlit as st

from alerts import alerts_frame, suggested_action
from app_pages.common import current_events, page_header
from database import update_alert_status

page_header("Security alerts", "Every alert includes a plain-language reason and a safe next step.")
alerts = alerts_frame(current_events())
if alerts.empty:
    st.info("No potential alerts are stored. This does not guarantee that all activity is safe.")
    st.stop()

status_filter = st.multiselect("Show review status", ["New", "Reviewed", "Resolved", "False positive"], default=["New", "Reviewed"])
visible = alerts.loc[alerts["status"].isin(status_filter)] if status_filter else alerts.iloc[0:0]
st.caption(f"{len(visible):,} alert(s) match the selected statuses.")

if not visible.empty:
    labels = {
        row.event_id: f"{row.timestamp} · {row.risk} · {row.alert_title}"
        for row in visible.itertuples()
    }
    selected_id = st.selectbox("Select an alert to review", list(labels), format_func=labels.get)
    alert = visible.loc[visible["event_id"].eq(selected_id)].iloc[0]
    with st.container(border=True):
        st.subheader(str(alert["alert_title"]))
        st.caption(
            f"Detected {alert['detected_at']} · event time {alert['timestamp']} · "
            f"{alert['source']} · {alert['risk']} risk · "
            f"{alert['origin']} activity"
        )
        st.write(f"**Why it was flagged:** {alert['reasons']}")
        st.write(f"**Suggested safe action:** {suggested_action(str(alert['risk']))}")
        st.caption(
            f"User: {alert['user']} · IP address: {alert['src_ip']} · "
            f"Event: {alert['event_type']} · Cluster: {alert['cluster']}"
        )
        next_status = st.selectbox(
            "Review status",
            ["New", "Reviewed", "Resolved", "False positive"],
            index=["New", "Reviewed", "Resolved", "False positive"].index(str(alert["status"])),
            key=f"alert_status_{selected_id}",
        )
        if st.button("Save review status", type="primary"):
            try:
                update_alert_status(str(selected_id), next_status)
            except ValueError as error:
                st.error(f"Could not update this alert: {error}")
            else:
                st.success(f"Alert marked as {next_status.lower()}.")
                st.rerun()

st.subheader("Alert list")
display_columns = [
    "detected_at",
    "timestamp",
    "alert_title",
    "source",
    "risk",
    "reasons",
    "suggested_action",
    "status",
]
st.dataframe(
    visible[[column for column in display_columns if column in visible]],
    hide_index=True,
    alt="Potential security alerts with reasons, suggested actions, and review status",
)
