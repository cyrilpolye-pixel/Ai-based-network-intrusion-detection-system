import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib


# ============================================================
# PATHS
# ============================================================

DATA_FILE = "data/Monday-WorkingHours.pcap_ISCX.csv"
MODEL_PATH = "models/cnn1d_binary.pth"
SCALER_PATH = "models/scaler.pkl"


# ============================================================
# EXACT 78 FEATURES
# ============================================================

FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


# ============================================================
# BINARY CNN
# MATCHES THE ACTUAL cnn1d_binary.pth CHECKPOINT
# ============================================================

class CNN1D_Binary(nn.Module):
    def __init__(self):
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv1d(1, 64, 3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.Conv1d(64, 64, 3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.MaxPool1d(2),
            nn.Dropout(0.2),

            nn.Conv1d(64, 128, 3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.Conv1d(128, 128, 3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.MaxPool1d(2),
            nn.Dropout(0.3),

            nn.Conv1d(128, 256, 3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),

            nn.AdaptiveAvgPool1d(1),
            nn.Dropout(0.3),
        )

        self.classifier = nn.Sequential(
            nn.Flatten(),

            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.Dropout(0.3),

            nn.Linear(128, 2),
        )

    def forward(self, x):
        return self.classifier(
            self.features(x.unsqueeze(1))
        )


# ============================================================
# MAIN
# ============================================================

print("=" * 70)
print("BINARY MODEL - BENIGN TEST")
print("=" * 70)

# ------------------------------------------------------------
# Load scaler
# ------------------------------------------------------------

print("\nLoading scaler...")

scaler = joblib.load(SCALER_PATH)

print("Scaler loaded.")
print("Scaler features:", scaler.n_features_in_)


# ------------------------------------------------------------
# Load binary model
# ------------------------------------------------------------

print("\nLoading binary model...")

model = CNN1D_Binary()

state_dict = torch.load(
    MODEL_PATH,
    map_location="cpu",
    weights_only=True
)

model.load_state_dict(state_dict)
model.eval()

print("Binary model loaded successfully.")


# ------------------------------------------------------------
# Load dataset
# ------------------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATA_FILE)

print("Dataset rows:", len(df))


# ------------------------------------------------------------
# Clean label
# ------------------------------------------------------------

# ------------------------------------------------------------
# Find label column
# ------------------------------------------------------------

label_column = None

for col in df.columns:
    if str(col).strip().lower() == "label":
        label_column = col
        break

if label_column is None:
    print("\nLabel column not found.")
    print("Available columns:")
    for col in df.columns:
        print(repr(col))
    raise SystemExit

print("Label column:", repr(label_column))

df[label_column] = df[label_column].astype(str).str.strip()

# ------------------------------------------------------------
# Select actual BENIGN rows
# ------------------------------------------------------------

benign = df[
    df[label_column].str.upper() == "BENIGN"
].head(20).copy()

print("Actual BENIGN samples selected:", len(benign))

if len(benign) == 0:
    print("No BENIGN rows found.")
    raise SystemExit


# ------------------------------------------------------------
# Normalize CSV column names
# ------------------------------------------------------------

benign.columns = benign.columns.str.strip()

# CICIDS2017 abbreviated column names -> model feature names
COLUMN_RENAME = {
    "Total Length of Bwd Packets": "Total Length of Bwd Packets",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Avg Fwd Segment Size": "Avg Fwd Segment Size",
    "Avg Bwd Segment Size": "Avg Bwd Segment Size",
    "Fwd Header Length.1": "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk": "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk": "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate": "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk": "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk": "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate": "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "Init_Win_bytes_forward": "Init_Win_bytes_forward",
    "Init_Win_bytes_backward": "Init_Win_bytes_backward",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "min_seg_size_forward": "min_seg_size_forward",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
}

benign = benign.rename(columns=COLUMN_RENAME)

X = benign[FEATURE_NAMES].copy()

# Convert everything to numeric
X = X.apply(pd.to_numeric, errors="coerce")

# Replace infinity
X = X.replace([np.inf, -np.inf], np.nan)

# Replace missing values
X = X.fillna(0)

print("Feature shape:", X.shape)


# ------------------------------------------------------------
# Scale
# ------------------------------------------------------------

X_scaled = scaler.transform(X.to_numpy())

X_tensor = torch.tensor(
    X_scaled,
    dtype=torch.float32
)


# ------------------------------------------------------------
# Predict
# ------------------------------------------------------------

print("\nRunning predictions...\n")

with torch.no_grad():
    outputs = model(X_tensor)

    probabilities = torch.softmax(outputs, dim=1)

    predictions = torch.argmax(
        probabilities,
        dim=1
    )


# ------------------------------------------------------------
# Display results
# ------------------------------------------------------------

correct = 0

for i in range(len(predictions)):

    prediction = predictions[i].item()

    benign_probability = probabilities[i][0].item()
    attack_probability = probabilities[i][1].item()

    if prediction == 0:
        predicted_label = "BENIGN"
    else:
        predicted_label = "ATTACK"

    if predicted_label == "BENIGN":
        correct += 1

    confidence = max(
        benign_probability,
        attack_probability
    )

    print(
        f"Row {i + 1:2d} | "
        f"Actual: BENIGN | "
        f"Predicted: {predicted_label:7s} | "
        f"Confidence: {confidence * 100:.2f}%"
    )


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

accuracy = (correct / len(predictions)) * 100

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

print(f"Actual BENIGN samples tested : {len(predictions)}")
print(f"Correctly identified BENIGN  : {correct}/{len(predictions)}")
print(f"BENIGN accuracy              : {accuracy:.2f}%")

print("=" * 70)