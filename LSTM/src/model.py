# src/model.py
"""LSTM 二分类模型定义。"""
import sys
from pathlib import Path

# 确保可导入 config
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from config import LSTM_UNITS, DROPOUT_RATE, LEARNING_RATE

from tensorflow.keras import layers, models, optimizers, regularizers


def build_lstm_model(input_shape, lstm_units=LSTM_UNITS,
                     dropout_rate=DROPOUT_RATE,
                     learning_rate=LEARNING_RATE):
    """
    构建双层LSTM二分类模型。

    参数:
        input_shape:   (时间步, 特征数)
        lstm_units:    第一层LSTM单元数（第二层为其一半）
        dropout_rate:  Dropout比例
        learning_rate: Adam优化器学习率

    返回:
        编译好的 Keras Sequential 模型
    """
    model = models.Sequential([
        layers.LSTM(
            lstm_units, return_sequences=True,
            input_shape=input_shape,
            kernel_regularizer=regularizers.l2(1e-4),
            recurrent_regularizer=regularizers.l2(1e-4),
        ),
        layers.Dropout(dropout_rate),

        layers.LSTM(lstm_units // 2),
        layers.Dropout(dropout_rate),

        layers.Dense(32, activation='relu',
                     kernel_regularizer=regularizers.l2(1e-4)),
        layers.Dense(1, activation='sigmoid'),
    ])

    model.compile(
        optimizer=optimizers.Adam(learning_rate=learning_rate),
        loss='binary_crossentropy',
        metrics=['accuracy'],
    )

    return model
