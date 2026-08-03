"""Build LSTM timing features from packet timestamps in a PCAP/PCAPNG file.

The model consumes one feature row per HTTP/HTTPS TCP connection.  A row's
``iat_oresp_*`` fields are calculated from the actual packet timestamps; no
connection-level Zeek duration or packet-count approximation is used.
"""

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np


HTTP_HTTPS_PORTS = {80, 443}
IDLE_TIMEOUT_SECONDS = 300.0

FEATURE_FIELDS = [
    "iat_oresp_total", "iat_oresp_min", "iat_oresp_max", "iat_oresp_mean",
    "iat_oresp_stddev", *[f"iat_oresp_nf_{index}" for index in range(10)],
]
CSV_FIELDS = [
    "source_file", "start_time", "src_ip", "src_port", "dst_ip", "dst_port",
    "ip_protocol", "packet_nb", "packet_nb_orig", "packet_nb_resp", *FEATURE_FIELDS,
]


@dataclass
class _Connection:
    source_file: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    timestamps: list[float] = field(default_factory=list)
    orig_packets: int = 0
    resp_packets: int = 0

    def add_packet(self, timestamp: float, is_originator: bool) -> None:
        self.timestamps.append(timestamp)
        if is_originator:
            self.orig_packets += 1
        else:
            self.resp_packets += 1


def _iat_features(timestamps: list[float]) -> dict[str, float]:
    """Calculate summary IATs and the training-compatible first-ten values."""
    ordered = np.asarray(sorted(timestamps), dtype=np.float64)
    intervals = np.diff(ordered) if ordered.size >= 2 else np.asarray([], dtype=np.float64)
    intervals = np.maximum(intervals, 0.0)  # defensive for malformed captures

    if intervals.size:
        features = {
            "iat_oresp_total": float(intervals.sum()),
            "iat_oresp_min": float(intervals.min()),
            "iat_oresp_max": float(intervals.max()),
            "iat_oresp_mean": float(intervals.mean()),
            "iat_oresp_stddev": float(intervals.std()),
        }
    else:
        features = dict.fromkeys(FEATURE_FIELDS[:5], 0.0)

    # The existing training pipeline defines nf_0..nf_9 as the first ten IATs.
    for index in range(10):
        features[f"iat_oresp_nf_{index}"] = float(intervals[index]) if index < len(intervals) else 0.0
    return features


class PcapLSTMFeatureExtractor:
    """Extract HTTP/HTTPS TCP connection timing rows from a capture file."""

    def __init__(self, pcap_path: Path):
        self.pcap_path = Path(pcap_path)

    def build_csv(self) -> str:
        try:
            from scapy.all import IP, IPv6, TCP, PcapReader
        except ImportError as exc:
            raise RuntimeError("Scapy is required for PCAP LSTM feature extraction") from exc

        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        active: dict[tuple[str, int, str, int], _Connection] = {}
        completed: list[_Connection] = []
        source_file = self.pcap_path.name

        with PcapReader(str(self.pcap_path)) as reader:
            for packet in reader:
                if not packet.haslayer(TCP):
                    continue
                ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                if ip_layer is None:
                    continue

                tcp = packet[TCP]
                src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
                src_port, dst_port = int(tcp.sport), int(tcp.dport)
                is_syn_start = bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)

                if dst_port in HTTP_HTTPS_PORTS:
                    key = (src_ip, src_port, dst_ip, dst_port)
                    is_originator = True
                elif src_port in HTTP_HTTPS_PORTS:
                    key = (dst_ip, dst_port, src_ip, src_port)
                    is_originator = False
                else:
                    continue

                timestamp = float(packet.time)
                current = active.get(key)
                is_stale = current and current.timestamps and timestamp - current.timestamps[-1] > IDLE_TIMEOUT_SECONDS
                if is_syn_start or current is None or is_stale:
                    if current is not None:
                        completed.append(current)
                    current = _Connection(source_file, *key)
                    active[key] = current
                current.add_packet(timestamp, is_originator)

        completed.extend(active.values())
        rows = [self._connection_row(connection) for connection in completed]
        rows.sort(key=lambda row: (row["source_file"], row["src_ip"], row["dst_ip"], row["dst_port"], row["start_time"]))
        if not rows:
            return ""

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    @staticmethod
    def _connection_row(connection: _Connection) -> dict[str, object]:
        return {
            "source_file": connection.source_file,
            "start_time": min(connection.timestamps),
            "src_ip": connection.src_ip,
            "src_port": connection.src_port,
            "dst_ip": connection.dst_ip,
            "dst_port": connection.dst_port,
            "ip_protocol": "tcp",
            "packet_nb": connection.orig_packets + connection.resp_packets,
            "packet_nb_orig": connection.orig_packets,
            "packet_nb_resp": connection.resp_packets,
            **_iat_features(connection.timestamps),
        }


def export_lstm_features_from_pcap(pcap_path: Path) -> str:
    """Public entry point used by the FastAPI analysis pipeline and CLI."""
    return PcapLSTMFeatureExtractor(pcap_path).build_csv()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Extract LSTM IAT features from a PCAP/PCAPNG")
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
