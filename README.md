# CyberShield — Everyday Security Monitor

CyberShield is a local-first Streamlit app for reviewing authorized Windows, Linux, router, firewall, and application logs. It normalizes common CSV/JSON/text formats, combines explainable safety checks with unsupervised DBSCAN clustering, and presents possible anomalies for human review.

## Run locally

Python 3.11 or newer is recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the local URL printed by Streamlit. Use **Upload Logs** to analyze a CSV, JSON, JSONL, TXT, or LOG file, or select **Analyze sample logs** to try the synthetic data in `sample_data/security_events.csv`. The upload page requires an authorization confirmation. Supported uploads are limited to 25 MB and 5,000 events per analysis to keep DBSCAN memory use bounded; split larger files into chronological chunks.

## What the app does

- **Dashboard:** security status, event and alert counts, daily/weekly charts, and recent activity.
- **Upload Logs:** reads files in memory, normalizes common field names, removes exact duplicates, trains DBSCAN, and scores the later chronological holdout.
- **Live Monitoring:** polls an explicitly selected local append-only CSV, JSONL, TXT, or LOG file every 5–30 seconds. It starts at the end of the file, so existing historical lines are not mislabeled as live.
- **Anomaly Detection:** tune DBSCAN epsilon, minimum cluster size, and test portion; inspect cluster labels and anomaly scores.
- **Security Alerts:** see each alert's risk, reason, safe next step, and review status (New, Reviewed, Resolved, or False positive).
- **Threat-Hunting Workbench:** search and filter by date, user, IP, and event type; compare normal and unusual events and export filtered CSV.
- **Reports:** export events or alerts, with user and IP masking enabled by default.
- **Settings:** adjust model parameters and review data-retention details. Streamlit supports both light and dark appearance through its Settings menu.

## Detection and model limits

Feature engineering groups related events in five-minute windows and derives time-of-day, day-of-week, event volume, outcome, byte-volume, and IP/device novelty signals. The categorical encoder and numerical scaler are fitted on training data only.

Events are sorted chronologically. DBSCAN trains on the earlier portion; later events are transformed using the training encoders and scaler, then compared with training core points. A later event beyond DBSCAN's epsilon distance is treated as noise. For training rows, DBSCAN's own noise label is used. Rule checks also highlight repeated failed sign-ins (five or more in ten minutes), successful overnight sign-ins (00:00–04:59 UTC), new IP/device activity, administrative or permission changes, and sudden account activity increases. Rules and cluster noise are indicators for review, not proof of compromise. Expect false positives and missed activity, especially with small, incomplete, or changing logs.

The app does not block accounts or devices, connect to external systems, collect passwords, or retain original uploads or raw log-message text. Review alerts before taking action.

## Storage and privacy

Normalized fields (which can include usernames, IP addresses, and device names), anomaly explanations, alert detection times, and review status are stored in the local `cybershield.db` SQLite file beside the app. Protect this file like the original authorized logs. The Settings page can clear stored data after an in-app confirmation. CSV reports omit raw messages and mask user/IP/device identifiers by default.

The app has no authentication layer. Do not expose a deployment to the public internet with real security logs. For shared or cloud deployment, add suitable authentication, access controls, protected persistent storage, retention policies, and transport security first. Streamlit Community Cloud is suitable for the synthetic sample only unless the deployment has been appropriately secured.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Deployment

For a private deployment, install the packages from `requirements.txt` and run `streamlit run app.py` behind an authenticated, TLS-protected service. The included SQLite database is local to the app process and is not a shared or managed database.
