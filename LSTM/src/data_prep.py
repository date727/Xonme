# src/data_prep.py
"""
数据预处理模块。
负责：加载CSV、构建时序样本、标准化、保存/加载 scaler。

用法：
    训练时调用 prepare_data() 获得 X, y, scaler（scaler会自动保存）。
    预测时调用 load_scaler() + prepare_single_csv() 做推理前预处理。
"""
import sys
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.preprocessing import StandardScaler

# 确保项目根和 src/ 均可导入
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (BENIGN_DIR, MALICIOUS_DIR, SEQ_LENGTH,
                    FEATURE_COLS, SCALER_PATH)


def load_data():
    """读取 benign/ 和 malicious/ 下所有CSV，添加标签后合并。"""
    dfs = []

    benign_files = list(BENIGN_DIR.glob("*.csv"))
    if not benign_files:
        raise FileNotFoundError(f"未在 {BENIGN_DIR} 找到良性样本CSV")
    for f in benign_files:
        df = pd.read_csv(f)
        df = df.fillna(df.median(numeric_only=True))
        df = df.fillna(0)
        df['label'] = 0
        dfs.append(df)

    malicious_files = list(MALICIOUS_DIR.glob("*.csv"))
    if not malicious_files:
        raise FileNotFoundError(f"未在 {MALICIOUS_DIR} 找到恶意样本CSV")
    for f in malicious_files:
        df = pd.read_csv(f)
        df = df.fillna(df.median(numeric_only=True))
        df = df.fillna(0)
        df['label'] = 1
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)

    # 验证特征列都存在
    missing = set(FEATURE_COLS) - set(combined.columns)
    if missing:
        raise KeyError(f"CSV中缺少以下特征列: {missing}")

    return combined


def build_sequences(df, seq_length=SEQ_LENGTH, feature_cols=FEATURE_COLS):
    """
    按通信对 (src_ip, dst_ip) 分组，构建时间序列样本。

    如果 DataFrame 中包含 'label' 列，则同时返回标签；
    否则 y 为全零占位数组（预测场景）。

    返回:
        X:      (样本数, 时间步, 特征数)  float32
        y:      (样本数,)                int64（无label时为全0）
        groups: (样本数,)                每个序列所属通信对的ID
    """
    X, y, groups = [], [], []
    has_labels = 'label' in df.columns

    for group_id, ((src, dst), group) in enumerate(df.groupby(['src_ip', 'dst_ip'])):
        group = group.sort_values('packet_nb')
        features = group[feature_cols].values.astype(np.float32)

        if has_labels:
            labels = group['label'].values
            unique_labels = np.unique(labels)
            if len(unique_labels) > 1:
                print(f"警告: 通信对 ({src}, {dst}) 内存在混合标签 {unique_labels}，"
                      f"将使用多数标签")

        n = len(features)
        if n < seq_length:
            continue

        for i in range(n - seq_length + 1):
            X.append(features[i:i + seq_length])
            if has_labels:
                y.append(1 if np.mean(labels[i:i + seq_length]) > 0.5 else 0)
            else:
                y.append(0)  # 预测时占位
            groups.append(group_id)

    if len(X) == 0:
        raise ValueError(
            f"未能生成任何序列。每个通信对至少需要 {seq_length} 行数据。"
            f"当前数据共有 {df.groupby(['src_ip', 'dst_ip']).ngroups} 个通信对。"
        )

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64), np.array(groups)


def prepare_data():
    """完整训练数据预处理流程。返回 X, y, groups, scaler。scaler自动保存。"""
    df = load_data()
    print(f"总行数: {len(df)}, 通信对数: {df.groupby(['src_ip', 'dst_ip']).ngroups}")

    X, y, groups = build_sequences(df)
    print(f"生成序列数: {len(X)}, 序列形状: {X.shape[1:]}")

    # 标准化：在全部数据上fit，用于训练时transform
    scaler = StandardScaler()
    original_shape = X.shape
    X_flat = X.reshape(-1, X.shape[-1])
    X_scaled = scaler.fit_transform(X_flat).reshape(original_shape)

    # 保存 scaler 供预测使用
    joblib.dump(scaler, SCALER_PATH)
    print(f"Scaler 已保存至 {SCALER_PATH}")

    return X_scaled, y, groups, scaler


def load_scaler():
    """加载已保存的 StandardScaler（预测时使用）。"""
    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            f"Scaler 未找到: {SCALER_PATH}。请先运行训练脚本。"
        )
    return joblib.load(SCALER_PATH)


def prepare_single_csv(csv_path, scaler, seq_length=SEQ_LENGTH,
                       feature_cols=FEATURE_COLS):
    """
    加载单个CSV并准备预测用序列。

    参数:
        csv_path:    CSV文件路径
        scaler:      已训练的 StandardScaler（用 transform 而非 fit_transform）
        seq_length:  时间窗口大小
        feature_cols:特征列名列表

    返回:
        X_scaled: (序列数, 时间步, 特征数) float32
    """
    df = pd.read_csv(csv_path)
    df = df.fillna(df.median(numeric_only=True))
    df = df.fillna(0)

    # 验证特征列
    missing = set(feature_cols) - set(df.columns)
    if missing:
        raise KeyError(f"CSV中缺少以下特征列: {missing}")

    # 用与训练一致的逻辑构建序列（无需标签）
    X, y, groups = build_sequences(df, seq_length=seq_length,
                                   feature_cols=feature_cols)

    if len(X) == 0:
        raise ValueError(
            f"未能从 {csv_path} 生成任何序列。"
            f"每个通信对至少需要 {seq_length} 行数据。"
        )

    # 用已训练的 scaler 做 transform（不能 fit）
    original_shape = X.shape
    X_flat = X.reshape(-1, X.shape[-1])
    X_scaled = scaler.transform(X_flat).reshape(original_shape)

    return X_scaled


if __name__ == "__main__":
    X, y, groups, scaler = prepare_data()
    print(f"X形状: {X.shape}, y形状: {y.shape}, 组数: {len(np.unique(groups))}")
    print(f"标签分布: 良性={np.sum(y==0)}, 恶意={np.sum(y==1)}")
