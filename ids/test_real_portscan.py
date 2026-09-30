import pandas as pd
import requests

CSV_PATH = r"data\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
ML_API_URL = "http://127.0.0.1:5001/predict"

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

df = pd.read_csv(CSV_PATH, nrows=20)
df.columns = df.columns.str.strip()

print("=" * 70)
print("REAL CICIDS2017 PORTSCAN TEST - 20 ROWS")
print("=" * 70)

print(f"Rows loaded: {len(df)}")
print(f"Columns: {len(df.columns)}")
print()

attack_count = 0
benign_count = 0
error_count = 0

for index, row in df.iterrows():

    features = []

    for name in FEATURE_NAMES:
        value = pd.to_numeric(row[name], errors="coerce")

        if pd.isna(value):
            value = 0.0

        features.append(float(value))

    try:
        response = requests.post(
            ML_API_URL,
            json={"features": features},
            timeout=10,
        )

        result = response.json()

        is_attack = result.get("is_attack")

        if is_attack:
            attack_count += 1
        else:
            benign_count += 1

        print(
            f"Row {index + 1:02d} | "
            f"Port={features[0]:.0f} | "
            f"Packets={features[2] + features[3]:.0f} | "
            f"Duration={features[1]:.0f} | "
            f"SYN={features[44]:.0f} | "
            f"Prediction={result}"
        )

    except Exception as e:
        error_count += 1
        print(f"Row {index + 1:02d} | ERROR: {e}")

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Actual dataset rows tested : {len(df)}")
print(f"Predicted ATTACK           : {attack_count}")
print(f"Predicted BENIGN           : {benign_count}")
print(f"Errors                     : {error_count}")
print("=" * 70)