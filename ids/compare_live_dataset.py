import sys
import os
import pandas as pd
import numpy as np

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_SERVICE = os.path.join(PROJECT_ROOT, "ml-service")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feat import FEATURE_NAMES


CSV_FILE = os.path.join(
    ML_SERVICE,
    "data",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
)


# ------------------------------------------------------------
# Load dataset
# ------------------------------------------------------------

print("=" * 70)
print("AI-NIDS DATASET FEATURE CHECK")
print("=" * 70)

print("\nLoading PortScan dataset...")

df = pd.read_csv(CSV_FILE)

df.columns = df.columns.str.strip()

print("Rows:", len(df))
print("Columns:", len(df.columns))


# ------------------------------------------------------------
# Same column processing used by ml_feat.py
# ------------------------------------------------------------

cols_to_drop = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
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
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
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
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}

df = df.rename(columns=rename_dict)


# ------------------------------------------------------------
# Numerical data
# ------------------------------------------------------------

df = df.select_dtypes(include=["number"])

df = df.replace(
    [np.inf, -np.inf],
    0
)

df = df.fillna(0)


# ------------------------------------------------------------
# Check all expected features exist
# ------------------------------------------------------------

missing = [
    feature
    for feature in FEATURE_NAMES
    if feature not in df.columns
]

if missing:
    print("\nMissing features:")
    for feature in missing:
        print(" -", feature)

    sys.exit(1)


# ------------------------------------------------------------
# Reorder exactly like feat.py
# ------------------------------------------------------------

df = df[FEATURE_NAMES]


# ------------------------------------------------------------
# Display selected dataset rows
# ------------------------------------------------------------

print()
print("=" * 70)
print("PORTSCAN DATASET SAMPLE")
print("=" * 70)

for row_number in [0, 1, 2, 9, 19]:
    if row_number >= len(df):
        continue

    row = df.iloc[row_number]

    print()
    print(f"ROW {row_number + 1}")
    print("-" * 70)

    for i, feature in enumerate(FEATURE_NAMES, start=1):
        print(
            f"{i:02d}. "
            f"{feature:<35} = {row[feature]}"
        )

print()
print("=" * 70)
print("CHECK COMPLETE")
print("=" * 70)