from __future__ import annotations

import plotly.express as px
import streamlit as st

from anomaly_detection import analyze_events
from app_pages.common import current_events, page_header
from database import save_events

page_header(
    "Anomaly detection",
    "DBSCAN groups recurring activity. Events outside its clusters are possible anomalies, not confirmed attacks.",
)
events = current_events()
if events.empty:
    st.info("Upload or load logs before running anomaly detection.")
    st.stop()

with st.form("dbscan_analysis"):
    first, second, third = st.columns(3)
    with first:
        eps = st.number_input("DBSCAN epsilon", min_value=0.1, max_value=20.0, value=float(st.session_state["dbscan_eps"]), step=0.1)
    with second:
        min_samples = st.number_input(
            "Minimum cluster size", min_value=2, max_value=50, value=int(st.session_state["dbscan_min_samples"]), step=1
        )
    with third:
        test_fraction = st.slider(
            "Later test portion",
            min_value=0.05,
            max_value=0.5,
            value=float(st.session_state["test_fraction"]),
            step=0.05,
            format="%.0f%%",
        )
    submitted = st.form_submit_button("Train and test DBSCAN", type="primary")

if submitted:
    try:
        result = analyze_events(events, eps=float(eps), min_samples=int(min_samples), test_fraction=float(test_fraction))
    except ValueError as error:
        st.error(f"Could not run analysis: {error}")
    else:
        st.session_state["dbscan_eps"] = float(eps)
        st.session_state["dbscan_min_samples"] = int(min_samples)
        st.session_state["test_fraction"] = float(test_fraction)
        st.session_state["analysis_note"] = result.note
        st.session_state["analysis_train_count"] = result.train_count
        st.session_state["analysis_test_count"] = result.test_count
        save_events(result.events)
        events = result.events
        st.success("Analysis complete. Cluster labels and scores have been saved locally.")

if st.session_state.get("analysis_note"):
    st.info(st.session_state["analysis_note"])
else:
    st.info(
        "Current event labels were produced during ingestion. Select **Train and test DBSCAN** to run a fresh "
        "chronological training/holdout analysis with the parameters above."
    )

train_count = int(st.session_state.get("analysis_train_count", 0))
test_count = int(st.session_state.get("analysis_test_count", 0))
with st.container(horizontal=True):
    st.metric("Training events", f"{train_count:,}", border=True)
    st.metric("Later test events", f"{test_count:,}", border=True)
    st.metric("Cluster noise", f"{int(events['cluster'].eq(-1).sum()):,}", border=True)
    st.metric("Potential anomalies", f"{int(events['is_anomaly'].sum()):,}", border=True)

scored = events.dropna(subset=["timestamp"]).copy()
if not scored.empty:
    figure = px.scatter(
        scored,
        x="timestamp",
        y="anomaly_score",
        color="risk",
        hover_data=["user", "src_ip", "event_type", "cluster", "reasons"],
        title="Event anomaly scores over time",
    )
    st.plotly_chart(figure, width="stretch", alt="Anomaly scores by event time and risk level")

st.subheader("Scored events")
st.dataframe(
    events[
        ["timestamp", "user", "src_ip", "event_type", "result", "cluster", "anomaly_score", "risk", "reasons"]
    ].sort_values("anomaly_score", ascending=False),
    hide_index=True,
    alt="DBSCAN cluster assignment, score, and explanation for each event",
)

with st.expander("How to interpret this model"):
    st.write(
        "DBSCAN groups events using time, activity-volume, outcome, and broad event-source features. "
        "Training uses the earlier chronological portion; the later holdout is transformed with encoders and "
        "scalers fitted only on training events, then compared with training core points. Cluster IDs are "
        "descriptive, not threat labels. Data quality, a small dataset, or ordinary changes in behavior can "
        "produce false positives or missed activity. Review alerts before taking action."
    )
