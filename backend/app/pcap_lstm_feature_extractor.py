"""Extract all-TCP connection-event features for the C2 beacon LSTM.

Each row represents one reconstructed TCP connection.  Rows belonging to the
same client/server/service group can subsequently be ordered by their start
time to model inter-connection beacon intervals and their jitter.
"""

import csv
import io
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np


IDLE_TIMEOUT_SECONDS = 300.0
ROLLING_GAP_WINDOW = 5
PACKET_IAT_PREFIX = 5

FEATURE_FIELDS = [
    "flow_gap", "log_flow_gap", "gap_rolling_mean", "gap_rolling_std",
    "gap_rolling_cv", "gap_rolling_median", "gap_rolling_iqr",
    "duration", "orig_packets", "resp_packets", "orig_bytes", "resp_bytes",
    "packet_ratio", "byte_ratio", "packet_iat_min", "packet_iat_max",
    "packet_iat_mean", "packet_iat_stddev",
    *[f"packet_iat_{index}" for index in range(PACKET_IAT_PREFIX)],
    "direction_confidence",
]
CSV_FIELDS = [
    "source_file", "start_time", "src_ip", "src_port", "dst_ip", "dst_port",
    "ip_protocol", *FEATURE_FIELDS,
]


@dataclass
class _Connection:
    source_file: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    direction_confidence: float
    syn_sequence: int | None = None
    closed: bool = False
    timestamps: list[float] = field(default_factory=list)
    orig_packets: int = 0
    resp_packets: int = 0
    orig_bytes: int = 0
    resp_bytes: int = 0

    def add_packet(self, timestamp: float, is_originator: bool, packet_bytes: int) -> None:
        self.timestamps.append(timestamp)
        if is_originator:
            self.orig_packets += 1
            self.orig_bytes += packet_bytes
        else:
            self.resp_packets += 1
            self.resp_bytes += packet_bytes


def _should_start_new_connection(
    current: _Connection | None,
    timestamp: float,
    syn_start: bool,
    syn_sequence: int | None,
) -> bool:
    """Decide whether a packet starts a new use of the same TCP four-tuple.

    A retransmitted opening SYN has the same sequence number and belongs to the
    current connection.  A new SYN after FIN/RST, an idle timeout, or with a
    different sequence number starts a new connection.
    """
    if current is None:
        return True
    if current.timestamps and timestamp - current.timestamps[-1] > IDLE_TIMEOUT_SECONDS:
        return True
    if not syn_start:
        return False
    return current.closed or current.syn_sequence != syn_sequence


def _packet_iat_features(timestamps: list[float]) -> dict[str, float]:
    ordered = np.asarray(sorted(timestamps), dtype=np.float64)
    intervals = np.maximum(np.diff(ordered), 0.0) if ordered.size >= 2 else np.empty(0)
    result = {
        "packet_iat_min": float(intervals.min()) if intervals.size else 0.0,
        "packet_iat_max": float(intervals.max()) if intervals.size else 0.0,
        "packet_iat_mean": float(intervals.mean()) if intervals.size else 0.0,
        "packet_iat_stddev": float(intervals.std()) if intervals.size else 0.0,
    }
    for index in range(PACKET_IAT_PREFIX):
        result[f"packet_iat_{index}"] = float(intervals[index]) if index < len(intervals) else 0.0
    return result


def _add_flow_features(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Add inter-connection timing features without crossing communication groups."""
    groups: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for row in rows:
        key = (row["source_file"], row["src_ip"], row["dst_ip"], row["dst_port"], row["ip_protocol"])
        groups.setdefault(key, []).append(row)

    for group_rows in groups.values():
        group_rows.sort(key=lambda row: float(row["start_time"]))
        gaps: list[float] = []
        previous_start: float | None = None
        for row in group_rows:
            current_start = float(row["start_time"])
            gap = max(0.0, current_start - previous_start) if previous_start is not None else 0.0
            previous_start = current_start
            gaps.append(gap)
            history = np.asarray(gaps[max(0, len(gaps) - ROLLING_GAP_WINDOW):], dtype=np.float64)
            mean = float(history.mean()) if history.size else 0.0
            std = float(history.std()) if history.size else 0.0
            q25, q75 = np.percentile(history, [25, 75]) if history.size else (0.0, 0.0)
            row.update({
                "flow_gap": gap,
                "log_flow_gap": math.log1p(gap),
                "gap_rolling_mean": mean,
                "gap_rolling_std": std,
                "gap_rolling_cv": std / mean if mean > 1e-9 else 0.0,
                "gap_rolling_median": float(np.median(history)) if history.size else 0.0,
                "gap_rolling_iqr": float(q75 - q25),
            })
    return rows


class PcapLSTMFeatureExtractor:
    """Extract all TCP connection events from a PCAP/PCAPNG capture."""

    def __init__(self, pcap_path: Path, source_file: str | None = None):
        self.pcap_path = Path(pcap_path)
        self.source_file = source_file or self.pcap_path.name

    def build_rows(self) -> list[dict[str, object]]:
        try:
            from scapy.all import IP, IPv6, TCP, PcapReader
        except ImportError as exc:
            raise RuntimeError("Scapy is required for PCAP LSTM feature extraction") from exc
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        active: dict[tuple[str, int, str, int], _Connection] = {}
        completed: list[_Connection] = []
        with PcapReader(str(self.pcap_path)) as reader:
            for packet in reader:
                if not packet.haslayer(TCP):
                    continue
                ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                if ip_layer is None:
                    continue
                tcp = packet[TCP]
                src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
                forward = (src_ip, int(tcp.sport), dst_ip, int(tcp.dport))
                reverse = (dst_ip, int(tcp.dport), src_ip, int(tcp.sport))
                flags = int(tcp.flags)
                syn_start = bool(flags & 0x02) and not bool(flags & 0x10)
                syn_sequence = int(tcp.seq) if syn_start else None
                timestamp = float(packet.time)

                if syn_start:
                    key, confidence = forward, 1.0
                elif forward in active:
                    key, confidence = forward, active[forward].direction_confidence
                elif reverse in active:
                    key, confidence = reverse, active[reverse].direction_confidence
                else:
                    # A partial capture may not contain the SYN.  Preserve the
                    # observed orientation but make its lower reliability explicit.
                    key, confidence = forward, 0.0

                current = active.get(key)
                if _should_start_new_connection(current, timestamp, syn_start, syn_sequence):
                    if current is not None:
                        completed.append(current)
                    current = _Connection(
                        self.source_file,
                        *key,
                        direction_confidence=confidence,
                        syn_sequence=syn_sequence,
                    )
                    active[key] = current
                is_originator = forward == key
                current.add_packet(timestamp, is_originator, len(packet))
                if flags & (0x01 | 0x04):  # FIN or RST
                    current.closed = True

        completed.extend(active.values())
        rows = [self._connection_row(connection) for connection in completed if connection.timestamps]
        rows = _add_flow_features(rows)
        return sorted(rows, key=lambda row: (str(row["source_file"]), str(row["src_ip"]), str(row["dst_ip"]), int(row["dst_port"]), float(row["start_time"])))

    @staticmethod
    def _connection_row(connection: _Connection) -> dict[str, object]:
        timestamps = connection.timestamps
        total_packets = connection.orig_packets + connection.resp_packets
        total_bytes = connection.orig_bytes + connection.resp_bytes
        return {
            "source_file": connection.source_file,
            "start_time": min(timestamps),
            "src_ip": connection.src_ip,
            "src_port": connection.src_port,
            "dst_ip": connection.dst_ip,
            "dst_port": connection.dst_port,
            "ip_protocol": "tcp",
            "duration": max(timestamps) - min(timestamps),
            "orig_packets": connection.orig_packets,
            "resp_packets": connection.resp_packets,
            "orig_bytes": connection.orig_bytes,
            "resp_bytes": connection.resp_bytes,
            "packet_ratio": connection.orig_packets / total_packets if total_packets else 0.0,
            "byte_ratio": connection.orig_bytes / total_bytes if total_bytes else 0.0,
            "direction_confidence": connection.direction_confidence,
            **_packet_iat_features(timestamps),
        }

    def build_csv(self) -> str:
        rows = self.build_rows()
        if not rows:
            return ""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()


def export_lstm_features_from_pcap(pcap_path: Path, source_file: str | None = None) -> str:
    return PcapLSTMFeatureExtractor(pcap_path, source_file=source_file).build_csv()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Extract all-TCP LSTM connection-event features")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--output", type=Path, help="CSV path (defaults to stdout)")
    args = parser.parse_args()
    csv_text = export_lstm_features_from_pcap(args.pcap)
    if args.output:
        args.output.write_text(csv_text, encoding="utf-8")
    else:
        print(csv_text, end="")


if __name__ == "__main__":
    main()
