"""Reusable dashboard views for CyberShield."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from alerts import alerts_frame


def render_dashboard(events: pd.DataFrame) -> None:
    if events.empty:
        st.info("Upload a log file or load the sample dataset to begin monitoring.")
        return

    anomalies = events.loc[events["is_anomaly"]]
    critical = int(anomalies["risk"].eq("Critical").sum())
    priority = int(anomalies["risk"].isin(["Critical", "Medium"]).sum())
    normal = int((~events["is_anomaly"]).sum())
    status = "Review needed" if critical else "Monitoring"
    if not anomalies.empty and not critical:
        status = "Some activity to review"

    with st.container(horizontal=True):
        st.metric("Security status", status, border=True)
        st.metric("Events analysed", f"{len(events):,}", border=True)
        st.metric("Normal activity", f"{normal:,}", border=True)
        st.metric("Potential anomalies", f"{len(anomalies):,}", border=True)
        st.metric("Priority alerts", f"{priority:,}", border=True)

    st.caption(
        f"{critical:,} critical alert(s). An anomaly is a review signal—not confirmation of an attack. "
        "Only appended lines from an explicitly monitored local file are labeled live."
    )

    trend = events.dropna(subset=["timestamp"]).copy()
    if not trend.empty:
        trend["day"] = trend["timestamp"].dt.floor("D")
        daily = (
            trend.groupby(["day", "is_anomaly"], as_index=False)
            .size()
            .rename(columns={"size": "Events", "is_anomaly": "Potential anomaly"})
        )
        week_start = trend["timestamp"].dt.floor("D") - pd.to_timedelta(
            trend["timestamp"].dt.day_of_week, unit="D"
        )
        weekly_events = trend.assign(week=week_start)
        weekly = (
            weekly_events.groupby(["week", "is_anomaly"], as_index=False)
            .size()
            .rename(columns={"size": "Events", "is_anomaly": "Potential anomaly"})
        )
        left, right = st.columns(2)
        with left:
            figure = px.bar(
                daily,
                x="day",
                y="Events",
                color="Potential anomaly",
                barmode="stack",
                title="Daily security activity",
            )
            st.plotly_chart(figure, width="stretch", alt="Daily event volume, with potential anomalies highlighted")
        with right:
            figure = px.bar(
                weekly,
                x="week",
                y="Events",
                color="Potential anomaly",
                barmode="stack",
                title="Weekly security activity",
            )
            st.plotly_chart(figure, width="stretch", alt="Weekly event volume, with potential anomalies highlighted")

    st.subheader("Recent security activity")
    recent = events.sort_values("timestamp", ascending=False, na_position="last").head(12)
    columns = ["timestamp", "source", "user", "src_ip", "event_type", "result", "risk", "reasons", "origin"]
    st.dataframe(
        recent[[column for column in columns if column in recent]],
        hide_index=True,
        alt="Most recent analyzed security events",
    )

    if not anomalies.empty:
        st.subheader("Alerts to review")
        latest_alerts = alerts_frame(events).head(5)
        st.dataframe(
            latest_alerts[
                ["detected_at", "timestamp", "alert_title", "risk", "user", "src_ip", "reasons", "status"]
            ],
            hide_index=True,
            alt="Five most recent potential security alerts",
        )
