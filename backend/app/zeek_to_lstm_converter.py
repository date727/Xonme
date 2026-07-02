"""Convert Zeek conn.log rows into the CSV schema expected by the LSTM model.

The LSTM was trained on HTTP/HTTPS ARES/Zeek-style flow rows.  This converter
therefore exports one row per Zeek connection, keeps only TCP port 80/443
traffic, and leaves sequence construction to ``lstm_predictor``.
"""

import csv
import io
from pathlib import Path
from typing import Dict, List

import numpy as np


HTTP_HTTPS_PORTS = {"80", "443"}


class ZeekToLSTMConverter:
    """Build an LSTM feature CSV from Zeek conn.log."""

    def __init__(self, zeek_log_dir: Path):
        self.zeek_log_dir = Path(zeek_log_dir)
        self.connections: List[Dict[str, str]] = []

    def parse_conn_log(self) -> None:
        conn_log_path = self.zeek_log_dir / "conn.log"
        if not conn_log_path.exists():
            print(f"conn.log not found: {conn_log_path}")
            return

        fields: list[str] = []
        parsed: list[dict[str, str]] = []
        with open(conn_log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#") or not line:
                    continue
                if not fields:
                    continue

                values = line.split("\t")
                if len(values) != len(fields):
                    continue
                parsed.append(dict(zip(fields, values)))

        self.connections = parsed
        print(f"Parsed {len(self.connections)} rows from conn.log")

    def build_iat_features(self) -> str:
        """Return an LSTM-compatible CSV string."""
        if not self.connections:
            self.parse_conn_log()
        if not self.connections:
            return ""

        rows = []
        source_file = self.zeek_log_dir.name or "zeek"

        for conn in self.connections:
            proto = conn.get("proto", "")
            dst_port = conn.get("id.resp_p", "")
            if proto != "tcp" or dst_port not in HTTP_HTTPS_PORTS:
                continue

            src_ip = conn.get("id.orig_h", "")
            dst_ip = conn.get("id.resp_h", "")
            if not src_ip or not dst_ip:
                continue

            duration = self._safe_float(conn.get("duration", "0"))
            orig_pkts = self._safe_int(conn.get("orig_pkts", "0"))
            resp_pkts = self._safe_int(conn.get("resp_pkts", "0"))
            packet_nb = orig_pkts + resp_pkts

            rows.append(
                {
                    "source_file": source_file,
                    "start_time": self._safe_float(conn.get("ts", "0")),
                    "src_ip": src_ip,
                    "src_port": conn.get("id.orig_p", ""),
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "ip_protocol": proto,
                    "packet_nb": packet_nb,
                    "packet_nb_orig": orig_pkts,
                    "packet_nb_resp": resp_pkts,
                    **self._compute_iat_features(duration, packet_nb),
                }
            )

        rows.sort(
            key=lambda r: (
                str(r["source_file"]),
                str(r["src_ip"]),
                str(r["dst_ip"]),
                str(r["dst_port"]),
                str(r["ip_protocol"]),
                float(r["start_time"]),
            )
        )

        print(f"Generated {len(rows)} HTTP/HTTPS LSTM feature rows")
        if not rows:
            return ""

        fieldnames = [
            "source_file",
            "start_time",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "ip_protocol",
            "packet_nb",
            "packet_nb_orig",
            "packet_nb_resp",
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
        writer.writerows(rows)
        return output.getvalue()

    def _compute_iat_features(self, duration: float, packet_nb: int) -> Dict[str, float]:
        """Approximate per-flow IAT features from conn.log-level fields.

        Zeek conn.log does not contain packet timestamps.  The best available
        approximation is to distribute the connection duration uniformly over
        packet gaps.  This keeps units compatible with the training data and is
        much closer than aggregating inter-connection gaps into one row.
        """
        if duration <= 0 or packet_nb < 2:
            intervals = np.array([], dtype=np.float32)
        else:
            interval_count = max(packet_nb - 1, 1)
            intervals = np.full(interval_count, duration / interval_count, dtype=np.float32)

        if intervals.size == 0:
            total = min_val = max_val = mean_val = stddev_val = 0.0
        else:
            total = float(duration)
            min_val = float(np.min(intervals))
            max_val = float(np.max(intervals))
            mean_val = float(np.mean(intervals))
            stddev_val = float(np.std(intervals))

        features = {
            "iat_oresp_total": total,
            "iat_oresp_min": min_val,
            "iat_oresp_max": max_val,
            "iat_oresp_mean": mean_val,
            "iat_oresp_stddev": stddev_val,
        }

        first_ten = intervals[:10].tolist()
        first_ten += [0.0] * (10 - len(first_ten))
        for i, value in enumerate(first_ten):
            features[f"iat_oresp_nf_{i}"] = float(value)

        return features

    @staticmethod
    def _safe_float(value: str) -> float:
        if value in {"", "-"}:
            return 0.0
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _safe_int(value: str) -> int:
        if value in {"", "-"}:
            return 0
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0


def export_lstm_features_from_zeek(zeek_log_dir: Path) -> str:
    converter = ZeekToLSTMConverter(zeek_log_dir)
    return converter.build_iat_features()


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python zeek_to_lstm_converter.py <zeek_log_dir>")
        sys.exit(1)

    zeek_log_dir = Path(sys.argv[1])
    csv_text = export_lstm_features_from_zeek(zeek_log_dir)

    if csv_text:
        output_path = zeek_log_dir / "lstm_features.csv"
        output_path.write_text(csv_text, encoding="utf-8")
        print(f"Saved features to: {output_path}")
        print("\n".join(csv_text.splitlines()[:5]))
    else:
        print("No LSTM features generated")


if __name__ == "__main__":
    main()
