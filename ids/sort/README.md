# AI-NIDS Model Verification & Testing Scripts (`ids/sort`)

This directory contains standalone testing, validation, and feature inspection scripts used to verify the AI-NIDS machine learning models, datasets, and feature alignments.

For each test script, a corresponding `.txt` file contains its recorded execution output log.

---

## Files Overview

| Script (`.py`) | Output Log (`.txt`) | Purpose & Description |
|---|---|---|
| **`check_model.py`** | `check_model.txt` | Validates file integrity and existence of saved artifacts (`models/scaler.pkl`, `cnn1d_binary.pth`, `cnn1d_attacks_only.pth`, `label_encoder_attacks.pkl`). Checks feature counts and classes. |
| **`compare_features.py`** | `compare_feature.txt` | Inspects dataset columns in `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` and verifies that the 78 features match the order expected by the models. |
| **`inspect_binary_model.py`** | `inspect_binary_model.txt` | Inspects PyTorch checkpoint tensor layer names and shapes inside `models/cnn1d_binary.pth`. |
| **`peek_portscan1.py`** | `peek_portscan1.txt` | Tests PortScan dataset rows from `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` against the live Flask API (`http://127.0.0.1:5001/predict`). |
| **`predict_test.py`** | `predict_test.txt` | Offline local Python inference test directly using PyTorch and joblib without the Flask service. Evaluates both Binary CNN and 14-class Attack CNN. |
| **`test_binary_benign.py`** | `test_binary_benign.txt` | Evaluates the binary 1D-CNN classifier against clean normal traffic (`Monday-WorkingHours.pcap_ISCX.csv`) to calculate false positive rate and baseline accuracy. |
| **`test_model.py`** | `test_model.txt` | Tests architecture definitions and weights loading for both `CNN1D_Binary` and `CNN1D_Attack` models on CPU. |
| **`test_real_portscan.py`** | `test_real_portscan.txt` | Evaluates isolated PortScan flow rows against the ML model to show why single-flow ML predictions classify scans as BENIGN and why multi-flow behavioral detection in `flow_cat.py` is needed. |

---

## Utility Files

- **`any cod.txt`**: Quick one-liner commands for checking model weights and scaler properties from the command line.
