# src/predict.py
"""
预测脚本 — 用训练好的LSTM模型对单个CSV做恶意/良性判定。

用法:
    python src/predict.py data/benign/benign_jquery_http.csv
    python src/predict.py data/malicious/cs2_jquery_http.csv
"""
import sys
import json
import numpy as np
from pathlib import Path

# 确保项目根和 src/ 均可导入
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import MODEL_PATH, METADATA_PATH, SEQ_LENGTH, FEATURE_COLS
from data_prep import load_scaler, prepare_single_csv
from tensorflow.keras.models import load_model as keras_load_model


def load_model():
    """加载已训练的 Keras 模型。"""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"模型未找到: {MODEL_PATH}。请先运行训练脚本。"
        )
    return keras_load_model(str(MODEL_PATH))


def predict_csv(csv_path):
    """
    对单个CSV文件做预测。

    返回:
        probs:       每条序列的恶意概率
        predictions: 每条序列的二分类结果 (0=良性, 1=恶意)
        verdict:     整体判定 "MALICIOUS" 或 "BENIGN"
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"文件不存在: {csv_path}")

    print(f"加载模型: {MODEL_PATH}")
    model = load_model()

    print(f"加载 Scaler: ...")
    scaler = load_scaler()

    print(f"预处理: {csv_path}")
    X = prepare_single_csv(str(csv_path), scaler,
                           seq_length=SEQ_LENGTH,
                           feature_cols=FEATURE_COLS)
    print(f"构建 {len(X)} 条序列, 形状 {X.shape[1:]}")

    # 逐序列预测
    probs = model.predict(X, verbose=0).flatten()
    predictions = (probs >= 0.5).astype(int)

    # 输出逐序列结果
    print(f"\n{'=' * 60}")
    print(f"预测结果: {csv_path.name}")
    print(f"{'=' * 60}")
    for i, (prob, pred) in enumerate(zip(probs, predictions)):
        label = "恶意" if pred == 1 else "良性"
        print(f"  序列 {i:3d}:  prob={prob:.4f}  →  {label}")

    # 聚合判定
    mean_prob = np.mean(probs)
    malicious_ratio = np.mean(predictions)
    if malicious_ratio >= 0.5:
        verdict = "MALICIOUS"
    else:
        verdict = "BENIGN"

    print(f"\n{'=' * 60}")
    print(f"汇总:")
    print(f"  平均恶意概率:     {mean_prob:.4f}")
    print(f"  恶意序列占比:     {malicious_ratio:.2%}  ({int(np.sum(predictions))}/{len(predictions)})")
    print(f"  整体判定:         {verdict}")
    print(f"{'=' * 60}")

    return probs, predictions, verdict


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python src/predict.py <csv_path>")
        print("示例:")
        print("  python src/predict.py data/benign/benign_jquery_http.csv")
        print("  python src/predict.py data/malicious/cs2_jquery_http.csv")
        sys.exit(1)

    try:
        predict_csv(sys.argv[1])
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)
