# config.py
import os
from pathlib import Path

# 路径配置
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BENIGN_DIR = DATA_DIR / "benign"
MALICIOUS_DIR = DATA_DIR / "malicious"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

# 创建必要的目录
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# 模型超参数
SEQ_LENGTH = 10          # 每个样本的时间步数（小数据集用较短窗口）
BATCH_SIZE = 8           # 小batch让每epoch有更多迭代步
EPOCHS = 100             # 小数据集每epoch很快，配合EarlyStopping
LSTM_UNITS = 32          # 降低模型复杂度，减少过拟合
DROPOUT_RATE = 0.4       # 加强正则化
LEARNING_RATE = 0.001

# 特征列名 — 使用 iat_oresp_* 全部15列作为时序特征
FEATURE_COLS = [
    'iat_oresp_total',
    'iat_oresp_min',
    'iat_oresp_max',
    'iat_oresp_mean',
    'iat_oresp_stddev',
    'iat_oresp_nf_0',
    'iat_oresp_nf_1',
    'iat_oresp_nf_2',
    'iat_oresp_nf_3',
    'iat_oresp_nf_4',
    'iat_oresp_nf_5',
    'iat_oresp_nf_6',
    'iat_oresp_nf_7',
    'iat_oresp_nf_8',
    'iat_oresp_nf_9',
]

# 持久化路径
SCALER_PATH = MODELS_DIR / "scaler.pkl"
MODEL_PATH = MODELS_DIR / "beacon_lstm_model.keras"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
