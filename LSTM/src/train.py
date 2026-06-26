# src/train.py
"""模型训练脚本。"""
import sys
import json
import numpy as np
from pathlib import Path

# 确保项目根和 src/ 均可导入
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from config import (MODELS_DIR, LOGS_DIR, EPOCHS, BATCH_SIZE,
                    SEQ_LENGTH, MODEL_PATH, METADATA_PATH, FEATURE_COLS)
from data_prep import prepare_data
from model import build_lstm_model

from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.utils.class_weight import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint


def train():
    # 1. 准备数据
    print("=" * 60)
    print("加载数据...")
    print("=" * 60)
    X, y, groups, scaler = prepare_data()

    if len(X) < 20:
        print(f"警告: 仅有 {len(X)} 条序列，样本量偏少，模型可能严重过拟合。")
        print("建议增加训练数据后再训练。")
        return

    # 2. 拆分训练集/测试集
    #    优先按通信对分组拆分以避免数据泄露；
    #    当组数太少（<4）或分组拆分导致某类别缺失时，回退为随机分层拆分
    unique_groups = np.unique(groups)
    use_group_split = len(unique_groups) >= 4

    if use_group_split:
        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, test_idx = next(gss.split(X, y, groups))
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        # 检查拆分后两个集合是否都包含了两类样本
        train_has_both = len(np.unique(y_train)) == 2
        test_has_both = len(np.unique(y_test)) == 2
        if not (train_has_both and test_has_both):
            print("警告: 分组拆分导致训练/测试集中缺少某一类别。"
                  "回退为随机分层拆分。")
            use_group_split = False

    if not use_group_split:
        if len(unique_groups) < 4:
            print(f"警告: 仅 {len(unique_groups)} 个通信对，不足以做分组拆分。"
                  "回退为随机分层拆分（评估指标将偏乐观）。")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

    print(f"训练集序列: {len(X_train)}, 测试集序列: {len(X_test)}")
    print(f"训练集标签分布: 良性={np.sum(y_train==0)}, 恶意={np.sum(y_train==1)}")
    print(f"测试集标签分布: 良性={np.sum(y_test==0)}, 恶意={np.sum(y_test==1)}")

    # 3. 构建模型
    model = build_lstm_model(input_shape=(SEQ_LENGTH, X.shape[2]))
    model.summary()

    # 4. 类别权重（处理不平衡）
    class_weights = compute_class_weight(
        'balanced', classes=np.unique(y_train), y=y_train
    )
    class_weight_dict = dict(enumerate(class_weights))
    print(f"类别权重: {class_weight_dict}")

    # 5. 回调函数
    callbacks = [
        EarlyStopping(
            monitor='val_loss',
            patience=15,
            restore_best_weights=True,
            verbose=1,
        ),
        ModelCheckpoint(
            filepath=str(MODEL_PATH),
            save_best_only=True,
            monitor='val_loss',
            verbose=1,
        ),
    ]

    # 6. 训练
    print("=" * 60)
    print("开始训练...")
    print("=" * 60)
    history = model.fit(
        X_train, y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.2,          # 从训练集中分出一部分做验证
        class_weight=class_weight_dict,
        callbacks=callbacks,
        verbose=1,
    )

    # 7. 保存训练历史
    history_file = LOGS_DIR / "training_history.json"
    with open(history_file, "w") as f:
        # 将 numpy 类型转为 Python 原生类型
        serializable = {
            k: [float(v) for v in vals]
            for k, vals in history.history.items()
        }
        json.dump(serializable, f, indent=2)
    print(f"训练历史已保存至 {history_file}")

    # 8. 保存模型元数据
    metadata = {
        "feature_cols": FEATURE_COLS,
        "seq_length": SEQ_LENGTH,
        "input_shape": list(X.shape[1:]),
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"模型元数据已保存至 {METADATA_PATH}")

    # 9. 评估
    print("=" * 60)
    print("测试集评估...")
    print("=" * 60)
    loss, acc = model.evaluate(X_test, y_test, verbose=1)
    print(f"测试集 Loss: {loss:.4f}, Accuracy: {acc:.4f}")

    return model


if __name__ == "__main__":
    train()
