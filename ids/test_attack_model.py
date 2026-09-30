import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib

# ============================================================
# PATHS
# ============================================================

DATASET = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
MODEL_PATH = "models/cnn1d_attacks_only.pth"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/label_encoder_attacks.pkl"


# ============================================================
# EXACT CNN1D_ATTACK ARCHITECTURE FROM app.py
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
# START
# ============================================================

print("=" * 70)
print("DIRECT TEST - ATTACK-ONLY MODEL")
print("=" * 70)


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv(
    DATASET,
    nrows=20
)

df.columns = df.columns.str.strip()

print(f"Rows loaded: {len(df)}")
print(f"Columns: {len(df.columns)}")


# ============================================================
# SELECT FEATURES
# ============================================================

X = df[FEATURE_NAMES].apply(
    pd.to_numeric,
    errors="coerce"
)

X = X.replace(
    [np.inf, -np.inf],
    np.nan
).fillna(0)

print(f"Features selected: {X.shape[1]}")


# ============================================================
# LOAD SCALER
# ============================================================

scaler = joblib.load(SCALER_PATH)

X_scaled = scaler.transform(X)


# ============================================================
# LOAD LABEL ENCODER
# ============================================================

encoder = joblib.load(ENCODER_PATH)

print()
print("Attack classes:")
print(list(encoder.classes_))


# ============================================================
# LOAD ATTACK MODEL
# ============================================================

state_dict = torch.load(
    MODEL_PATH,
    map_location="cpu",
    weights_only=False
)

model = CNN1D_Attack(
    len(encoder.classes_)
)

model.load_state_dict(state_dict)

model.eval()

print()
print("Attack model loaded successfully.")


# ============================================================
# PREPARE INPUT
# ============================================================

tensor = torch.tensor(
    X_scaled,
    dtype=torch.float32
)


# ============================================================
# PREDICT
# ============================================================

with torch.no_grad():

    output = model(tensor)

    probabilities = torch.softmax(
        output,
        dim=1
    )

    predictions = torch.argmax(
        probabilities,
        dim=1
    )


# ============================================================
# DISPLAY RESULTS
# ============================================================

print()
print("=" * 70)
print("PREDICTIONS")
print("=" * 70)

for i in range(len(df)):

    predicted_index = predictions[i].item()

    predicted_label = encoder.inverse_transform(
        [predicted_index]
    )[0]

    confidence = probabilities[
        i,
        predicted_index
    ].item()

    port = int(df.iloc[i]["Destination Port"])

    print(
        f"Row {i + 1:02d} | "
        f"Port={port} | "
        f"Prediction={predicted_label} | "
        f"Confidence={confidence:.4f}"
    )


# ============================================================
# SUMMARY
# ============================================================

predicted_labels = encoder.inverse_transform(
    predictions.numpy()
)

unique, counts = np.unique(
    predicted_labels,
    return_counts=True
)

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)

for label, count in zip(unique, counts):
    print(f"{label}: {count}")

print("=" * 70)