from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib


app = Flask(__name__)

DEVICE = torch.device("cpu")

BINARY_MODEL_PATH = "models/cnn1d_binary.pth"
ATTACK_MODEL_PATH = "models/cnn1d_attacks_only.pth"
SCALER_PATH = "models/scaler.pkl"
ENCODER_PATH = "models/label_encoder_attacks.pkl"


# ============================================================
# MODEL DEFINITIONS
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
        return self.classifier(self.features(x.unsqueeze(1)))


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
# LOAD PRETRAINED COMPONENTS
# ============================================================

scaler = joblib.load(SCALER_PATH)
label_encoder = joblib.load(ENCODER_PATH)

binary_model = CNN1D_Binary()
binary_model.load_state_dict(
    torch.load(
        BINARY_MODEL_PATH,
        map_location=DEVICE,
        weights_only=True
    )
)
binary_model.eval()

attack_model = CNN1D_Attack(
    len(label_encoder.classes_)
)
attack_model.load_state_dict(
    torch.load(
        ATTACK_MODEL_PATH,
        map_location=DEVICE,
        weights_only=True
    )
)
attack_model.eval()


# ============================================================
# PREPROCESSING
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
        "Label"
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
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "AI-NIDS ML Service",
        "status": "running",
        "models": {
            "binary_cnn": "loaded",
            "attack_cnn": "loaded"
        }
    })


# ============================================================
# PREDICTION API
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400

        # Accept either:
        # { "features": {...} }
        # or directly { "feature1": value, ... }

        if "features" in data:
            features = data["features"]
        else:
            features = data

        df = pd.DataFrame([features])

        X_scaled = preprocess(df)

        X = torch.tensor(
            X_scaled,
            dtype=torch.float32
        )

        # ----------------------------------------------------
        # Stage 1: Binary detection
        # ----------------------------------------------------

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

        if binary_prediction == 0:

            return jsonify({
                "is_attack": False,
                "attack_type": "BENIGN",
                "confidence": round(
                    binary_probabilities[0, 0].item(),
                    4
                )
            })

        # ----------------------------------------------------
        # Stage 2: Attack classification
        # ----------------------------------------------------

        with torch.no_grad():

            attack_output = attack_model(X)

            attack_probabilities = torch.softmax(
                attack_output,
                dim=1
            )

            attack_prediction = torch.argmax(
                attack_output,
                dim=1
            ).item()

        attack_type = label_encoder.classes_[
            attack_prediction
        ]

        return jsonify({
            "is_attack": True,
            "attack_type": str(attack_type),
            "confidence": round(
                attack_probabilities[
                    0,
                    attack_prediction
                ].item(),
                4
            ),
            "binary_confidence": round(
                binary_probabilities[0, 1].item(),
                4
            )
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("AI-NIDS ML service starting...")
    print("Models loaded successfully.")
    print("API: http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )