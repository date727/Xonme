# ARES/Zeek LSTM binary classifier

This directory trains an LSTM binary classifier for HTTP/HTTPS ARES/Zeek flow sequences:

- `benign` -> label `0`
- `cs` -> label `1`

## Data Layout

The training script reads:

```text
LSTM/csv_comb/benign/*.csv  -> label 0
LSTM/csv_comb/cs/*.csv      -> label 1
```

Each CSV must contain:

```text
start_time, src_ip, dst_ip, dst_port, ip_protocol
iat_oresp_total, iat_oresp_min, iat_oresp_max, iat_oresp_mean, iat_oresp_stddev
iat_oresp_nf_0 ~ iat_oresp_nf_9
```

Sequences are built by grouping rows with:

```text
source_file + src_ip + dst_ip + dst_port + ip_protocol
```

Rows inside each group are sorted by `start_time`. Every 10 consecutive rows become one LSTM sample.

## Install

```bash
cd LSTM
pip install -r requirements.txt
```

## Train

```bash
cd LSTM
python src/train.py
```

Outputs:

```text
models/beacon_lstm_model.keras
models/scaler.pkl
models/model_metadata.json
logs/training_history.json
```

## Predict

Batch-validate all CSV files under `csv_comb/benign` and `csv_comb/cs`:

```bash
cd LSTM
python src/predict.py
```

Predict one CSV:

```bash
cd LSTM
python src/predict.py csv_comb/benign/benign_jquery_http.csv
python src/predict.py csv_comb/cs/cs_jquery_http.csv
```

Batch mode prints one row per CSV and reports file-level and sequence-level accuracy.

## Current Features

Each time step uses these 15 `iat_oresp_*` features:

```text
iat_oresp_total
iat_oresp_min
iat_oresp_max
iat_oresp_mean
iat_oresp_stddev
iat_oresp_nf_0
iat_oresp_nf_1
iat_oresp_nf_2
iat_oresp_nf_3
iat_oresp_nf_4
iat_oresp_nf_5
iat_oresp_nf_6
iat_oresp_nf_7
iat_oresp_nf_8
iat_oresp_nf_9
```

If the Zeek feature export changes, update `FEATURE_COLS` in `config.py`.
