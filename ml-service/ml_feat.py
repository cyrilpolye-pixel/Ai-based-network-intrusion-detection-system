import pandas as pd
import joblib

# Path to your existing CICIDS2017 CSV
CSV_FILE = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

# Path to the existing scaler
SCALER_FILE = "models/scaler.pkl"


print("=" * 60)
print("AI-NIDS FEATURE INSPECTION")
print("=" * 60)

print("\nLoading dataset...")
df = pd.read_csv(CSV_FILE)

df.columns = df.columns.str.strip()

print("Original CSV columns:", len(df.columns))

# Same columns removed by the existing prediction pipeline
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

# Same renaming used by predict_test.py
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

# Keep numerical features only
df = df.select_dtypes(include=["number"])

# Clean invalid values
df = df.replace([float("inf"), float("-inf")], 0)
df = df.fillna(0)

# Load the actual scaler used by the CNN
print("\nLoading scaler...")
scaler = joblib.load(SCALER_FILE)

print("Scaler expects:", scaler.n_features_in_, "features")

print("\n" + "=" * 60)
print("EXPECTED ML FEATURES")
print("=" * 60)

if hasattr(scaler, "feature_names_in_"):
    features = list(scaler.feature_names_in_)

    for number, feature in enumerate(features, start=1):
        print(f"{number:02d}. {feature}")

    print("\nTotal expected features:", len(features))

    missing = [
        feature
        for feature in features
        if feature not in df.columns
    ]

    print("\nFeatures currently available from CSV:", len(df.columns))
    print("Missing features:", len(missing))

    if missing:
        print("\nMISSING FEATURES:")
        for feature in missing:
            print("-", feature)

else:
    print(
        "\nThe scaler does not contain feature_names_in_."
    )
    print(
        "The existing prediction code therefore uses the first 78 numerical features."
    )

print("\n" + "=" * 60)
print("78 FEATURES USED BY THE CURRENT PIPELINE")
print("=" * 60)

for number, column in enumerate(df.columns[:78], start=1):
    print(f"{number:02d}. {column}")

print("\nTotal:", len(df.columns[:78]))