# LSTM 网络流量二分类器

基于 LSTM 的网络流量恶意/良性二分类模型，使用 ARES 数据集中的 **iat_oresp_*（包间到达时间）** 共 15 列作为时序特征。

## 目录结构

```
LSTM/
├── config.py             # 配置文件（路径、超参数、特征列）
├── requirements.txt      # Python 依赖
├── data/
│   ├── benign/           # 良性流量 CSV
│   └── malicious/        # 恶意流量 CSV
├── src/
│   ├── data_prep.py      # 数据预处理（加载、序列构建、标准化）
│   ├── model.py          # LSTM 模型定义
│   ├── train.py          # 训练脚本
│   └── predict.py        # 预测脚本
├── models/               # 训练产物（模型、scaler、元数据）
└── logs/                 # 训练历史
```

## 环境安装

```bash
pip install -r requirements.txt
```

需要 Python ≥ 3.8，TensorFlow ≥ 2.12.0。

## 训练

```bash
cd LSTM
python src/train.py
```

训练完成后，`models/` 目录下会生成：
- `beacon_lstm_model.keras` — 训练好的 Keras 模型
- `scaler.pkl` — StandardScaler（预测时必须使用）
- `model_metadata.json` — 特征列名、序列长度等元数据

## 预测

```bash
# 预测良性流量
python src/predict.py data/benign/benign_jquery_http.csv

# 预测恶意流量
python src/predict.py data/malicious/cs2_jquery_http.csv

# 预测任意 CSV
python src/predict.py /path/to/your/traffic.csv
```

输出包含：每条序列的预测概率、二分类结果，以及整体判定（恶意序列占比 ≥ 50% 即判为恶意）。

## 数据格式

CSV 需包含以下 15 个 `iat_oresp_*` 列（以及 `src_ip`, `dst_ip`, `packet_nb` 用于分组排序）：

```
iat_oresp_total, iat_oresp_min, iat_oresp_max, iat_oresp_mean, iat_oresp_stddev,
iat_oresp_nf_0 ~ iat_oresp_nf_9
```

## 注意事项

- 当前样本量较少（~144行），模型参数量已做压减和正则化处理，但仍可能存在过拟合。
- 增加更多训练数据可显著提升模型泛化能力。
