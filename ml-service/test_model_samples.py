import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import requests


# ============================================================
# PATHS
# ============================================================

DATA_DIR = "data"

BINARY_MODEL_PATH = "models/cnn1d_binary.pth"
ATTACK_MODEL_PATH = "models/cnn1d_attacks_only.pth"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/label_encoder_attacks.pkl"

ML_API_URL = "http://127.0.0.1:5001/predict"


# ============================================================
# EXACT ATTACK MODEL FROM app.py
# ============================================================

class CNN1D_Attack(nn.Module):
    def __init__(self, num_classes):
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

            nn.Conv1d(256, 256, 3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),

            nn.AdaptiveAvgPool1d(1),
            nn.Dropout(0.3),
        )

        self.classifier = nn.Sequential(
            nn.Flatten(),

            nn.Linear(256, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.4),

            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(128, num_classes),
        )

    def forward(self, x):
        return self.classifier(self.features(x.unsqueeze(1)))


# ============================================================
# 78 FEATURES
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
# DATASET FILES
# ============================================================

DATASETS = {
    "PortScan":
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",

    "DDoS":
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",

    "DoS Hulk":
        "Wednesday-workingHours.pcap_ISCX.csv",

    "SSH-Patator":
        "Tuesday-WorkingHours.pcap_ISCX.csv",

    "BENIGN":
        "Monday-WorkingHours.pcap_ISCX.csv",
}


# ============================================================
# LOAD ATTACK MODEL
# ============================================================

print("=" * 70)
print("MODEL VALIDATION TEST")
print("=" * 70)

print()
print("Loading scaler...")

scaler = joblib.load(SCALER_PATH)

print("Loading label encoder...")

encoder = joblib.load(ENCODER_PATH)

print("Attack classes:")
print(list(encoder.classes_))


print()
print("Loading attack model...")

state_dict = torch.load(
    ATTACK_MODEL_PATH,
    map_location="cpu",
    weights_only=False
)

attack_model = CNN1D_Attack(
    len(encoder.classes_)
)

attack_model.load_state_dict(state_dict)
attack_model.eval()

print("Attack model loaded successfully.")


# ============================================================
# TEST FUNCTION
# ============================================================

def test_dataset(name, filename, rows=20):

    path = f"{DATA_DIR}/{filename}"

    print()
    print("=" * 70)
    print(f"TESTING: {name}")
    print(f"FILE: {filename}")
    print("=" * 70)

    # Read only first 20 rows
    df = pd.read_csv(
        path,
        nrows=rows
    )

    df.columns = df.columns.str.strip()

    # Clean labels
    label_column = "Label"

    if label_column in df.columns:
        actual_labels = (
            df[label_column]
            .astype(str)
            .str.strip()
        )
    else:
        actual_labels = pd.Series(
            ["UNKNOWN"] * len(df)
        )

    # Select 78 features
    X = df[FEATURE_NAMES].apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    ).fillna(0)

    # Scale
    X_scaled = scaler.transform(X)

    # Tensor
    tensor = torch.tensor(
        X_scaled,
        dtype=torch.float32
    )

    # Attack prediction
    with torch.no_grad():

        output = attack_model(tensor)

        probabilities = torch.softmax(
            output,
            dim=1
        )

        predictions = torch.argmax(
            probabilities,
            dim=1
        )

    predicted_labels = encoder.inverse_transform(
        predictions.numpy()
    )

    # Display
    for i in range(len(df)):

        confidence = probabilities[
            i,
            predictions[i]
        ].item()

        actual = actual_labels.iloc[i]

        predicted = predicted_labels[i]

        print(
            f"Row {i + 1:02d} | "
            f"Actual={actual} | "
            f"Predicted={predicted} | "
            f"Confidence={confidence:.4f}"
        )

    # Accuracy against requested class
    correct = sum(
        predicted_labels[i] == name
        for i in range(len(df))
    )

    print()
    print(
        f"{name} identified correctly: "
        f"{correct}/{len(df)}"
    )

    return correct, len(df)


# ============================================================
# RUN TESTS
# ============================================================

results = {}

for name, filename in DATASETS.items():

    try:

        correct, total = test_dataset(
            name,
            filename,
            rows=20
        )

        results[name] = (
            correct,
            total
        )

    except Exception as e:

        print()
        print(f"ERROR testing {name}: {e}")

        results[name] = (
            0,
            0
        )


# ============================================================
# FINAL SUMMARY
# ============================================================

print()
print("=" * 70)
print("FINAL SUMMARY")
print("=" * 70)

for name, (correct, total) in results.items():

    if total > 0:

        accuracy = (
            correct / total
        ) * 100

        print(
            f"{name:15s}: "
            f"{correct:2d}/{total:2d} "
            f"({accuracy:.1f}%)"
        )

    else:

        print(
            f"{name:15s}: TEST FAILED"
        )

print("=" * 70)
