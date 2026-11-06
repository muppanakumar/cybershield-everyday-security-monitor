"""Safe, vendor-agnostic parsing and normalization for security logs."""

from __future__ import annotations

import hashlib
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

import pandas as pd

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_EVENTS_PER_ANALYSIS = 5_000

ALIASES = {
    "timestamp": {"timestamp", "time", "datetime", "date", "event_time", "created_at"},
    "source": {"source", "source_type", "log_source", "provider", "facility"},
    "user": {"user", "username", "account", "principal", "user_id", "actor"},
    "src_ip": {"src_ip", "source_ip", "remote_ip", "client_ip", "ip", "ip_address"},
    "event_type": {"event", "event_type", "action", "type", "event_name", "activity"},
    "result": {"result", "status", "outcome", "auth_result", "login_result"},
    "device": {"device", "hostname", "host", "computer", "machine"},
    "bytes": {"bytes", "byte_count", "size", "sent_bytes", "data_volume"},
    "details": {"details", "message", "description", "log", "raw_message"},
}

_IP_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<device>\S+)\s+(?P<details>.+)$"
)
_USER_RE = re.compile(
    r"(?:for\s+(?:invalid\s+user\s+)?|user(?:name)?[=: ]+)\s*['\"]?([a-zA-Z0-9_.@-]+)",
    re.I,
)


def _column_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def _parse_syslog_timestamp(value: str) -> str | None:
    try:
        parsed = datetime.strptime(f"{datetime.now(timezone.utc).year} {value}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def _records_from_text(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _SYSLOG_RE.match(line)
        if match:
            record = match.groupdict()
            record["timestamp"] = _parse_syslog_timestamp(record["timestamp"]) or ""
        else:
            record = {"details": line}
        records.append(record)
    return records


def read_log_file(name: str, content: bytes) -> pd.DataFrame:
    """Read CSV, JSON/JSONL, or plain-text logs without writing the upload to disk."""
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if suffix not in {"csv", "json", "jsonl", "txt", "log"}:
        raise ValueError("Choose a CSV, JSON, JSONL, TXT, or LOG file.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("The upload is larger than the 25 MB safety limit.")

    text = content.decode("utf-8-sig", errors="replace")
    if suffix == "csv":
        frame = pd.read_csv(io.StringIO(text))
    elif suffix in {"json", "jsonl"}:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                parsed = parsed.get("events", parsed.get("records", [parsed]))
            frame = pd.DataFrame(parsed)
        except json.JSONDecodeError:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
            frame = pd.DataFrame(records)
    else:
        frame = pd.DataFrame(_records_from_text(text))
    if frame.empty:
        raise ValueError("No log events were found in this file.")
    return frame


def normalize_logs(data: pd.DataFrame, origin: str = "historical") -> pd.DataFrame:
    """Map common log schemas to a small, normalized event model."""
    if data.empty:
        raise ValueError("The log file contains no events.")
    if len(data) > MAX_EVENTS_PER_ANALYSIS:
        raise ValueError(
            f"This version analyzes at most {MAX_EVENTS_PER_ANALYSIS:,} events at a time. "
            "Split larger logs into chronological files before uploading."
        )

    source = data.copy()
    renamed: dict[Any, str] = {}
    used: set[str] = set()
    for column in source.columns:
        normalized = _column_name(column)
        target = next((name for name, aliases in ALIASES.items() if normalized in aliases), normalized)
        if target not in used:
            renamed[column] = target
            used.add(target)
    source = source.rename(columns=renamed)

    details = source.get("details", pd.Series("", index=source.index)).fillna("").astype(str)
    for column in ("timestamp", "source", "user", "src_ip", "event_type", "result", "device", "bytes"):
        if column not in source:
            source[column] = pd.NA

    source["src_ip"] = source["src_ip"].astype("object")
    source["user"] = source["user"].astype("object")
    missing_ip = source["src_ip"].isna() | source["src_ip"].astype(str).str.strip().eq("")
    extracted_ip = details.str.extract(_IP_RE, expand=False)
    source.loc[missing_ip, "src_ip"] = extracted_ip.loc[missing_ip]

    missing_user = source["user"].isna() | source["user"].astype(str).str.strip().eq("")
    extracted_user = details.str.extract(_USER_RE, expand=False)
    source.loc[missing_user, "user"] = extracted_user.loc[missing_user]

    source["timestamp"] = pd.to_datetime(source["timestamp"], errors="coerce", utc=True, format="mixed")
    source["bytes"] = pd.to_numeric(source["bytes"], errors="coerce").clip(lower=0).fillna(0)
    for column in ("source", "user", "src_ip", "event_type", "device"):
        source[column] = source[column].fillna("unknown").astype(str).str.strip()
        source.loc[source[column].eq(""), column] = "unknown"

    event_text = (source["event_type"].fillna("unknown").astype(str) + " " + details).str.lower()
    source["event_type"] = source["event_type"].where(source["event_type"].ne("unknown"), "other")
    source.loc[event_text.str.contains(r"login|logon|auth|sign.?in|password", regex=True), "event_type"] = "authentication"
    source.loc[event_text.str.contains(r"sudo|admin|privilege|permission|role change", regex=True), "event_type"] = "administrative"
    source.loc[event_text.str.contains(r"firewall|network|dns|connection|packet|traffic", regex=True), "event_type"] = "network"

    result_text = (source["result"].fillna("").astype(str) + " " + details).str.lower()
    raw_result = source["result"].astype("string").str.strip().str.lower()
    is_failed = result_text.str.contains(
        r"\b(?:fail(?:ed|ure)?|denied|invalid|blocked|unsuccessful)\b", regex=True
    ) | raw_result.isin({"false", "no"})
    is_success = result_text.str.contains(
        r"\b(?:success(?:ful)?|accepted|allowed|granted|logged in)\b", regex=True
    ) | raw_result.isin({"true", "yes"})
    source["result"] = "unknown"
    source.loc[is_success, "result"] = "success"
    source.loc[is_failed, "result"] = "failed"

    source["details"] = details
    source["origin"] = origin
    source = source[
        ["timestamp", "source", "user", "src_ip", "event_type", "result", "device", "bytes", "details", "origin"]
    ]
    source = source.drop_duplicates(
        subset=["timestamp", "source", "user", "src_ip", "event_type", "result", "device", "bytes", "details"]
    ).reset_index(drop=True)
    source["event_id"] = source.apply(
        lambda row: hashlib.sha256(
            "|".join(
                [
                    str(row["timestamp"]),
                    row["source"],
                    row["user"],
                    row["src_ip"],
                    row["event_type"],
                    row["result"],
                    row["device"],
                    str(row["bytes"]),
                ]
            ).encode("utf-8")
        ).hexdigest()[:24],
        axis=1,
    )
    return source
