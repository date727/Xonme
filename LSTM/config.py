"""Configuration for the all-TCP C2 beacon LSTM pipeline."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RAW_DATA_DIR = BASE_DIR / "data"
SPLIT_MANIFEST_PATH = RAW_DATA_DIR / "split_manifest.csv"
FEATURE_DATA_DIR = BASE_DIR / "feature_data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

for directory in (FEATURE_DATA_DIR, MODELS_DIR, LOGS_DIR):
    os.makedirs(directory, exist_ok=True)

SEQ_LENGTH = 10
# Neighboring sliding windows are highly correlated.  Cap them per group so a
# long capture cannot dominate model fitting or reported window-level metrics.
MAX_WINDOWS_PER_GROUP = 200
GROUP_COLS = ["source_file", "src_ip", "dst_ip", "dst_port", "ip_protocol"]
SORT_COL = "start_time"
SPLITS = ("train", "val", "test")

BATCH_SIZE = 16
EPOCHS = 30
LSTM_UNITS = 32
DROPOUT_RATE = 0.4
LEARNING_RATE = 0.001

# The decision threshold is selected once on the validation split. We retain
# the highest-recall threshold that keeps the validation FPR under this limit;
# if no threshold reaches it, the selection report makes that explicit.
# C2 detection is recall-first: choose the threshold on validation *windows*
# to retain at least 98% recall while keeping benign FPR controlled.
TARGET_RECALL = 0.98
MAX_VALIDATION_FPR = 0.05
# Keep the training loss class-balanced. Any stronger C2 weighting is treated
# as a separately reported ablation, not silently deployed.
C2_CLASS_WEIGHT_MULTIPLIER = 1.0
RUN_SEEDS = (2026, 2027, 2028, 2029, 2030)

# Every feature is produced by backend/app/pcap_lstm_feature_extractor.py.
FEATURE_COLS = [
    "flow_gap", "log_flow_gap", "gap_rolling_mean", "gap_rolling_std",
    "gap_rolling_cv", "gap_rolling_median", "gap_rolling_iqr",
    "duration", "orig_packets", "resp_packets", "orig_bytes", "resp_bytes",
    "packet_ratio", "byte_ratio", "packet_iat_min", "packet_iat_max",
    "packet_iat_mean", "packet_iat_stddev",
    "packet_iat_0", "packet_iat_1", "packet_iat_2", "packet_iat_3", "packet_iat_4",
    "direction_confidence",
]

SCALER_PATH = MODELS_DIR / "scaler.pkl"
MODEL_PATH = MODELS_DIR / "beacon_lstm_model.keras"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
THRESHOLD_PATH = MODELS_DIR / "decision_threshold.json"
