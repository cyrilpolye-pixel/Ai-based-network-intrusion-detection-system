import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib


# ============================================================
# Configuration
# ============================================================

DEVICE = torch.device("cpu")

CSV_FILE = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

BINARY_MODEL_PATH = "models/cnn1d_binary.pth"
ATTACK_MODEL_PATH = "models/cnn1d_attacks_only.pth"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/label_encoder_attacks.pkl"


# ============================================================
# Binary CNN
# ============================================================

class CNN1D_Binary(nn.Module):
    def __init__(self, num_features):
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.Conv1d(64, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.MaxPool1d(2),
            nn.Dropout(0.2),

            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.Conv1d(128, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.MaxPool1d(2),
            nn.Dropout(0.3),

            nn.Conv1d(128, 256, kernel_size=3, padding=1),
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
# Attack Classification CNN
# ============================================================

class CNN1D_Attack(nn.Module):
    def __init__(self, num_features, num_classes):
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.Conv1d(64, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.MaxPool1d(2),
            nn.Dropout(0.2),

            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.Conv1d(128, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.MaxPool1d(2),
            nn.Dropout(0.3),

            nn.Conv1d(128, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),

            nn.Conv1d(256, 256, kernel_size=3, padding=1),
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
        return self.classifier(
            self.features(x.unsqueeze(1))
        )


# ============================================================
# Load preprocessing artifacts
# ============================================================

print("Loading scaler...")

scaler = joblib.load(SCALER_PATH)

print("Loading label encoder...")

label_encoder = joblib.load(ENCODER_PATH)

num_features = scaler.n_features_in_
num_classes = len(label_encoder.classes_)

print("Features:", num_features)
print("Attack classes:", num_classes)


# ============================================================
# Load pretrained models
# ============================================================

print("Loading binary CNN...")

binary_model = CNN1D_Binary(num_features)

binary_state = torch.load(
    BINARY_MODEL_PATH,
    map_location=DEVICE,
    weights_only=True,
)

binary_model.load_state_dict(binary_state)
binary_model.to(DEVICE)
binary_model.eval()

print("Binary CNN loaded.")


print("Loading attack CNN...")

attack_model = CNN1D_Attack(
    num_features,
    num_classes
)

attack_state = torch.load(
    ATTACK_MODEL_PATH,
    map_location=DEVICE,
    weights_only=True,
)

attack_model.load_state_dict(attack_state)
attack_model.to(DEVICE)
attack_model.eval()

print("Attack CNN loaded.")


# ============================================================
# Original preprocessing
# ============================================================

def preprocess(df):

    df.columns = df.columns.str.strip()

    cols_to_drop = [
        "Flow ID",
        "Src IP",
        "Src Port",
        "Dst IP",
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Label",
    ]

    for col in cols_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])

    rename_dict = {
        "Tot Fwd Pkts": "Total Fwd Packets",
        "Tot Bwd Pkts": "Total Backward Packets",
        "TotLen Fwd Pkts": "Total Length of Fwd Packets",
        "TotLen Bwd Pkts": "Total Length of Bwd Packets",
        "Fwd Pkt Len Max": "Fwd Packet Length Max",
        "Fwd Pkt Len Min": "Fwd Packet Length Min",
        "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
        "Fwd Pkt Len Std": "Fwd Packet Length Std",
        "Bwd Pkt Len Max": "Bwd Packet Length Max",
        "Fwd Header Len": "Fwd Header Length",
        "Bwd Header Len": "Bwd Header Length",
        "Fwd Pkts/s": "Fwd Packets/s",
        "Bwd Pkts/s": "Bwd Packets/s",
        "Pkt Len Min": "Min Packet Length",
        "Pkt Len Max": "Max Packet Length",
        "Pkt Len Mean": "Packet Length Mean",
        "Pkt Len Std": "Packet Length Std",
        "Pkt Len Var": "Packet Length Variance",
        "FIN Flag Cnt": "FIN Flag Count",
        "SYN Flag Cnt": "SYN Flag Count",
        "RST Flag Cnt": "RST Flag Count",
        "PSH Flag Cnt": "PSH Flag Count",
        "ACK Flag Cnt": "ACK Flag Count",
        "URG Flag Cnt": "URG Flag Count",
        "Pkt Size Avg": "Average Packet Size",
        "Fwd Seg Size Avg": "Avg Fwd Segment Size",
        "Bwd Seg Size Avg": "Avg Bwd Segment Size",
        "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
        "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
        "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
        "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
        "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
        "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
        "Subflow Fwd Pkts": "Subflow Fwd Packets",
        "Subflow Bwd Pkts": "Subflow Bwd Packets",
        "Init Fwd Win Byts": "Init_Win_bytes_forward",
        "Init Bwd Win Byts": "Init_Win_bytes_backward",
        "Fwd Act Data Pkts": "act_data_pkt_fwd",
        "Fwd Seg Size Min": "min_seg_size_forward",
    }

    df = df.rename(columns=rename_dict)

    df = df.select_dtypes(include=[np.number])

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df.fillna(0, inplace=True)

    if hasattr(scaler, "feature_names_in_"):

        for col in scaler.feature_names_in_:

            if col not in df.columns:
                df[col] = 0

        df = df[scaler.feature_names_in_]

    else:

        while df.shape[1] < 78:
            df["missing_" + str(df.shape[1])] = 0

        df = df.iloc[:, :78]

    return scaler.transform(df.values)


# ============================================================
# Read ONE real CICIDS2017 flow
# ============================================================

print()
print("Reading dataset...")

df_all = pd.read_csv(CSV_FILE)

# CICIDS2017 CSV has spaces in some column names
df_all.columns = df_all.columns.str.strip()

attack_rows = df_all[
    df_all["Label"].astype(str).str.strip().str.upper() != "BENIGN"
]

if attack_rows.empty:
    print("No attack row found in this CSV.")
    raise SystemExit

df = attack_rows.iloc[[0]]

print("Original dataset label:", df["Label"].iloc[0])

if attack_rows.empty:
    print("No attack row found in this CSV.")
    raise SystemExit

df = attack_rows.iloc[[0]]

print("Original label:", df["Label"].iloc[0])

print("CSV columns:", len(df.columns))


# ============================================================
# Preprocess
# ============================================================

X_scaled = preprocess(df)

print("Preprocessed shape:", X_scaled.shape)


# ============================================================
# Convert to tensor
# ============================================================

X = torch.tensor(
    X_scaled,
    dtype=torch.float32
).to(DEVICE)


# ============================================================
# Stage 1: BENIGN vs ATTACK
# ============================================================

with torch.no_grad():

    binary_output = binary_model(X)

    binary_probabilities = torch.softmax(
        binary_output,
        dim=1
    )

    binary_prediction = torch.argmax(
        binary_output,
        dim=1
    ).item()


# ============================================================
# Stage 2: Attack classification
# ============================================================

if binary_prediction == 0:

    result = "BENIGN"

    confidence = binary_probabilities[0, 0].item()

    attack_confidence = None

else:

    attack_output = attack_model(X)

    attack_probabilities = torch.softmax(
        attack_output,
        dim=1
    )

    attack_prediction = torch.argmax(
        attack_output,
        dim=1
    ).item()

    result = label_encoder.classes_[attack_prediction]

    confidence = binary_probabilities[0, 1].item()

    attack_confidence = attack_probabilities[
        0,
        attack_prediction
    ].item()


# ============================================================
# Display result
# ============================================================

print()
print("========================================")
print("          AI-NIDS TEST RESULT")
print("========================================")

print("Binary result:",
      "ATTACK" if binary_prediction == 1 else "BENIGN")

print("Final classification:", result)

print(
    "Binary confidence:",
    f"{confidence * 100:.2f}%"
)

if attack_confidence is not None:

    print(
        "Attack classification confidence:",
        f"{attack_confidence * 100:.2f}%"
    )

print("========================================")