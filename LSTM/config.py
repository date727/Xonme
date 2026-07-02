import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# Training data layout:
#   csv_comb/benign/*.csv -> label 0
#   csv_comb/cs/*.csv     -> label 1
DATA_DIR = BASE_DIR / "csv_comb"
BENIGN_DIR = DATA_DIR / "benign"
MALICIOUS_DIR = DATA_DIR / "cs"

MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)


# Sequence construction
SEQ_LENGTH = 10
GROUP_COLS = ["source_file", "src_ip", "dst_ip", "dst_port", "ip_protocol"]
SORT_COL = "start_time"


# Training hyperparameters
BATCH_SIZE = 8
EPOCHS = 20
LSTM_UNITS = 32
DROPOUT_RATE = 0.4
LEARNING_RATE = 0.001


# ARES/Zeek timing features used at each time step.
FEATURE_COLS = [
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


SCALER_PATH = MODELS_DIR / "scaler.pkl"
MODEL_PATH = MODELS_DIR / "beacon_lstm_model.keras"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
