"""
RITA -> LSTM 特征导出器

从 RITA 的 ClickHouse `threat_mixtape` 表中提取 `ts_intervals` 与
`ts_interval_counts`，转换为 LSTM 需要的 15 维 iat_oresp 特征。
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
from collections.abc import Iterable
from typing import Any


def _to_float_list(values: Iterable) -> list[float]:
    out: list[float] = []
    for v in values:
        try:
            out.append(float(v))
        except (TypeError, ValueError):
            out.append(0.0)
    return out


def _build_iat_features(ts_intervals: list[float], ts_counts: list[float]) -> dict[str, float]:
    """由 (interval, count) 直方图计算 iat_oresp_* 15 维特征。"""
    pairs = [
        (ival, cnt)
        for ival, cnt in zip(ts_intervals, ts_counts)
        if cnt > 0
    ]

    if not pairs:
        features = {
            "iat_oresp_total": 0.0,
            "iat_oresp_min": 0.0,
            "iat_oresp_max": 0.0,
            "iat_oresp_mean": 0.0,
            "iat_oresp_stddev": 0.0,
        }
        for i in range(10):
            features[f"iat_oresp_nf_{i}"] = 0.0
        return features

    total_count = sum(cnt for _, cnt in pairs)
    weighted_sum = sum(ival * cnt for ival, cnt in pairs)
    mean_val = weighted_sum / total_count if total_count > 0 else 0.0
    variance = (
        sum(((ival - mean_val) ** 2) * cnt for ival, cnt in pairs) / total_count
        if total_count > 0
        else 0.0
    )

    # nf_0..9: 取最常见 10 个间隔值的归一化频率（降序），不足补 0
    top_freqs = sorted((cnt / total_count for _, cnt in pairs), reverse=True)[:10]
    top_freqs += [0.0] * (10 - len(top_freqs))

    features = {
        "iat_oresp_total": weighted_sum,
        "iat_oresp_min": min(ival for ival, _ in pairs),
        "iat_oresp_max": max(ival for ival, _ in pairs),
        "iat_oresp_mean": mean_val,
        "iat_oresp_stddev": variance ** 0.5,
    }
    for i, f in enumerate(top_freqs):
        features[f"iat_oresp_nf_{i}"] = f

    return features


def export_lstm_feature_csv_from_rita_db(
    database: str,
    clickhouse_container: str = "rita-clickhouse",
) -> str:
    """
    从 RITA ClickHouse 数据库导出 LSTM 特征 CSV 文本。

    Returns:
        包含 header 的 CSV 文本，字段至少包括:
        src,dst,port,proto,packet_nb,iat_oresp_total...iat_oresp_nf_9
    """
    query = (
        "SELECT src,dst,port_proto_service,count,ts_intervals,ts_interval_counts "
        f"FROM {database}.threat_mixtape "
        "WHERE length(ts_intervals) > 0 AND length(ts_interval_counts) > 0 "
        "FORMAT JSONEachRow"
    )

    cmd = [
        "docker",
        "exec",
        clickhouse_container,
        "clickhouse-client",
        "-q",
        query,
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    raw = (proc.stdout or "").strip()
    if not raw:
        return ""

    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))

    if not rows:
        return ""

    fieldnames = [
        "src",
        "dst",
        "port",
        "proto",
        "packet_nb",
        "iat_oresp_total",
        "iat_oresp_min",
        "iat_oresp_max",
        "iat_oresp_mean",
        "iat_oresp_stddev",
        "iat_oresp_nf_0",
        "iat_oresp_nf_1",
        "iat_oresp_nf_2",
        "iat_oresp_nf_3",
        "iat_oresp_nf_4",
        "iat_oresp_nf_5",
        "iat_oresp_nf_6",
        "iat_oresp_nf_7",
        "iat_oresp_nf_8",
        "iat_oresp_nf_9",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        pps = row.get("port_proto_service") or []
        port = ""
        proto = ""
        if pps:
            first = str(pps[0])
            parts = first.split(":")
            if len(parts) >= 2:
                port = parts[0]
                proto = parts[1]

        ts_intervals = _to_float_list(row.get("ts_intervals") or [])
        ts_counts = _to_float_list(row.get("ts_interval_counts") or [])
        iat_features = _build_iat_features(ts_intervals, ts_counts)

        packet_nb = int(float(row.get("count", 0) or 0))
        rec = {
            "src": str(row.get("src", "")),
            "dst": str(row.get("dst", "")),
            "port": str(port),
            "proto": str(proto),
            "packet_nb": packet_nb,
            **iat_features,
        }
        writer.writerow(rec)

    return output.getvalue()


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalise_key(key: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in key.lower()).strip("_")


def _first(row: dict[str, Any], *names: str) -> Any:
    normalised = {_normalise_key(key): value for key, value in row.items()}
    for name in names:
        value = normalised.get(_normalise_key(name))
        if value not in (None, ""):
            return value
    return None


def _service_parts(value: Any) -> tuple[str, str]:
    values = value if isinstance(value, list) else [value]
    if not values:
        return "", ""
    parts = str(values[0] or "").split(":")
    return (parts[0] if parts else "", parts[1] if len(parts) > 1 else "")


def export_rita_connection_evidence(
    database: str,
    clickhouse_container: str = "rita-clickhouse",
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Return real, version-tolerant RITA mixtape evidence for dashboard use.

    RITA v5 schemas vary between releases.  ``SELECT *`` intentionally keeps
    this adapter schema-driven: absent score columns remain ``None`` instead of
    being guessed or filled with presentation values.
    """
    if not database.replace("_", "").isalnum():
        raise ValueError("Invalid RITA database name")
    query = f"SELECT * FROM {database}.threat_mixtape FORMAT JSONEachRow"
    proc = subprocess.run(
        ["docker", "exec", clickhouse_container, "clickhouse-client", "-q", query],
        capture_output=True,
        text=True,
        check=True,
    )
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for line in (proc.stdout or "").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        port, protocol = _service_parts(_first(row, "port_proto_service"))
        src, dst = str(_first(row, "src", "source", "source_ip") or ""), str(_first(row, "dst", "destination", "destination_ip") or "")
        if not src or not dst:
            continue
        intervals = _to_float_list(_first(row, "ts_intervals") or [])
        interval_counts = _to_float_list(_first(row, "ts_interval_counts") or [])
        result[(src, dst, str(port))] = {
            "protocol": protocol or None,
            "timestamp_score": _number(_first(row, "timestamp_score", "time_score")),
            "datasize_score": _number(_first(row, "datasize_score", "data_size_score")),
            "duration_score": _number(_first(row, "duration_score")),
            "histogram_score": _number(_first(row, "histogram_score", "hist_score")),
            "ts_intervals": intervals or None,
            "ts_interval_counts": interval_counts or None,
            "connection_count": _number(_first(row, "count", "connection_count")),
            "total_duration": _number(_first(row, "duration", "total_duration")),
            "total_bytes": _number(_first(row, "total_bytes", "bytes")),
            "long_connection": _number(_first(row, "long_conn_score", "long_connection_score")),
            "c2_over_dns": _number(_first(row, "c2_over_dns_score", "c2_dns_score")),
            "subdomain_count": _number(_first(row, "subdomains", "subdomain_count")),
            "threat_intelligence": _first(row, "threat_intelligence", "threat_intel_score"),
            "available_fields": sorted(row.keys()),
        }
    return result
