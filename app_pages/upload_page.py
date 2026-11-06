from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from app_pages.common import analyze_and_save, page_header
from data_processing import read_log_file

page_header(
    "Upload security logs",
    "Import authorized logs for local analysis. Historical uploads are never labeled as live activity.",
)

with st.container(border=True):
    with st.form("upload_logs"):
        uploaded = st.file_uploader(
            "Choose a CSV, JSON, JSONL, TXT, or LOG file",
            type=["csv", "json", "jsonl", "txt", "log"],
            max_upload_size=25,
        )
        authorized = st.checkbox("I own these logs or am authorized to analyze them.")
        submitted = st.form_submit_button("Analyze uploaded logs", type="primary")

    if submitted:
        if not authorized:
            st.error("Confirm that you are authorized to analyze these logs.")
        elif uploaded is None:
            st.error("Choose a supported log file first.")
        else:
            try:
                raw = read_log_file(uploaded.name, uploaded.getvalue())
                result, saved = analyze_and_save(raw, origin="historical")
            except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as error:
                st.error(f"Could not analyze this file: {error}")
            else:
                st.success(f"Analyzed {len(result.events):,} events. {saved:,} normalized event(s) saved locally.")
                st.info(result.note)
                st.caption(
                    "Only normalized event fields and alert review status are stored in the local SQLite database. "
                    "The original uploaded file and raw message text are not retained."
                )
                alert_count = int(result.events["is_anomaly"].sum())
                st.metric("Potential anomalies to review", f"{alert_count:,}")
                if alert_count:
                    st.dataframe(
                        result.events.loc[
                            result.events["is_anomaly"],
                            ["timestamp", "alert_title", "risk", "user", "src_ip", "reasons"],
                        ],
                        hide_index=True,
                        alt="Potential anomalies detected in the uploaded historical logs",
                    )

st.subheader("Try the sample dataset")
st.write(
    "The bundled dataset is synthetic and includes routine events plus examples of repeated failed sign-ins, "
    "a new device/IP, and administrative activity."
)
if st.button("Analyze sample logs", type="secondary"):
    sample_path = Path(__file__).resolve().parents[1] / "sample_data" / "security_events.csv"
    if not sample_path.is_file():
        st.error("The sample dataset is missing from sample_data/security_events.csv.")
    else:
        try:
            raw = read_log_file(sample_path.name, sample_path.read_bytes())
            result, saved = analyze_and_save(raw, origin="sample")
        except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as error:
            st.error(f"Could not analyze the sample dataset: {error}")
        else:
            st.success(f"Analyzed {len(result.events):,} synthetic events. {saved:,} saved locally.")
            st.info(result.note)

st.caption("Supported fields are detected from common Windows, Linux, router, firewall, and application log schemas.")
