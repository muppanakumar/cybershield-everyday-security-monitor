from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from alerts import export_csv
from anomaly_detection import analyze_events
from data_processing import normalize_logs, read_log_file
from database import initialize_database, load_events, save_events, update_alert_status

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class LogProcessingTests(unittest.TestCase):
    def test_csv_aliases_deduplicate_and_extract_fields(self) -> None:
        raw = read_log_file(
            "auth.csv",
            b"time,username,remote_ip,message\n2026-11-01T10:00:00Z,alice,,Failed password for alice from 203.0.113.9\n"
            b"2026-11-01T10:00:00Z,alice,,Failed password for alice from 203.0.113.9\n",
        )
        events = normalize_logs(raw)
        self.assertEqual(len(events), 1)
        self.assertEqual(events.loc[0, "user"], "alice")
        self.assertEqual(events.loc[0, "src_ip"], "203.0.113.9")
        self.assertEqual(events.loc[0, "result"], "failed")
        self.assertEqual(events.loc[0, "origin"], "historical")

    def test_jsonl_and_plain_text_are_supported(self) -> None:
        jsonl = read_log_file(
            "events.jsonl",
            b'{"timestamp":"2026-11-01T10:00:00Z","user":"bob","event":"login","status":"success"}\n',
        )
        text = read_log_file(
            "auth.txt",
            b"Nov  1 10:00:00 host sshd[1]: Failed password for alice from 198.51.100.4 port 22\n",
        )
        self.assertEqual(normalize_logs(jsonl).loc[0, "result"], "success")
        parsed_text = normalize_logs(text)
        self.assertEqual(parsed_text.loc[0, "user"], "alice")
        self.assertEqual(parsed_text.loc[0, "src_ip"], "198.51.100.4")
        self.assertEqual(parsed_text.loc[0, "result"], "failed")

    def test_upload_size_and_extension_are_checked(self) -> None:
        with self.assertRaises(ValueError):
            read_log_file("logs.exe", b"event")


class AnomalyDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sample_path = PROJECT_ROOT / "sample_data" / "security_events.csv"
        cls.events = normalize_logs(pd.read_csv(sample_path), origin="sample")

    def test_dbscan_uses_later_holdout_and_explains_rule_alerts(self) -> None:
        result = analyze_events(self.events)
        self.assertTrue(result.model_trained)
        self.assertGreater(result.train_count, result.test_count)
        self.assertEqual(result.train_count + result.test_count, len(self.events))
        self.assertIn("later", result.note)
        burst = result.events.loc[result.events["result"].eq("failed")]
        self.assertTrue(burst["is_anomaly"].all())
        self.assertTrue(burst["reasons"].str.contains("failed sign-in attempts").all())
        self.assertTrue(burst["risk"].isin(["Medium", "Critical"]).all())
        self.assertTrue(result.events["cluster"].notna().all())
        first_alert = result.events.loc[result.events["is_anomaly"]].iloc[0]
        self.assertTrue(pd.notna(first_alert["detected_at"]))
        self.assertNotEqual(first_alert["detected_at"], first_alert["timestamp"])

    def test_small_dataset_still_runs_rule_checks_without_claiming_model(self) -> None:
        result = analyze_events(self.events.head(5))
        self.assertFalse(result.model_trained)
        self.assertEqual(result.train_count, 0)
        self.assertIn("at least 8", result.note)

    def test_overnight_new_device_admin_and_activity_spike_are_explained(self) -> None:
        added = [
            {
                "timestamp": "2026-11-07T02:00:00Z",
                "source": "Windows Security",
                "user": "alice",
                "src_ip": "203.0.113.55",
                "event_type": "login",
                "result": "success",
                "device": "new-device",
            },
            {
                "timestamp": "2026-11-07T02:02:00Z",
                "source": "Linux auth",
                "user": "bob",
                "src_ip": "192.0.2.20",
                "event_type": "privilege_change",
                "result": "success",
                "device": "server-01",
            },
        ]
        added.extend(
            {
                "timestamp": f"2026-11-07T17:{minute:02d}:00Z",
                "source": "Windows Security",
                "user": "alice",
                "src_ip": "192.0.2.10",
                "event_type": "login",
                "result": "success",
                "device": "laptop-01",
            }
            for minute in range(8)
        )
        new_events = normalize_logs(pd.DataFrame(added), origin="sample")
        result = analyze_events(pd.concat([self.events, new_events], ignore_index=True))
        overnight = result.events.loc[result.events["src_ip"].eq("203.0.113.55")].iloc[0]
        self.assertIn("new IP address", overnight["reasons"])
        self.assertIn("new device", overnight["reasons"])
        self.assertIn("overnight hour", overnight["reasons"])
        admin = result.events.loc[result.events["event_type"].eq("administrative")].iloc[-1]
        self.assertIn("Administrative or permission-changing", admin["reasons"])
        spike = result.events.loc[result.events["timestamp"].ge(pd.Timestamp("2026-11-07T17:00:00Z"))]
        self.assertTrue(spike["reasons"].str.contains("Sudden activity increase").any())

    def test_future_holdout_does_not_change_fitted_training_split(self) -> None:
        result = analyze_events(self.events)
        training_ids = set(result.events.head(result.train_count)["event_id"])
        self.assertTrue(training_ids)
        self.assertTrue(result.events.iloc[result.train_count :]["timestamp"].min() >= result.events.iloc[: result.train_count]["timestamp"].max())


class StorageAndReportTests(unittest.TestCase):
    def test_review_status_survives_event_refresh_and_report_masks_identifiers(self) -> None:
        source = PROJECT_ROOT / "sample_data" / "security_events.csv"
        result = analyze_events(normalize_logs(pd.read_csv(source), origin="sample"))
        alert = result.events.loc[result.events["is_anomaly"]].iloc[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "test.db"
            initialize_database(path)
            save_events(result.events, path)
            update_alert_status(str(alert["event_id"]), "Reviewed", path)
            save_events(result.events, path)
            stored = load_events(path)
            reviewed = stored.loc[stored["event_id"].eq(alert["event_id"])].iloc[0]
            self.assertEqual(reviewed["status"], "Reviewed")
            report = export_csv(result.events.loc[result.events["is_anomaly"]], anonymize=True).decode()
            self.assertNotIn(str(alert["user"]), report)
            self.assertNotIn(str(alert["src_ip"]), report)
            self.assertNotIn(str(alert["device"]), report)


if __name__ == "__main__":
    unittest.main()
