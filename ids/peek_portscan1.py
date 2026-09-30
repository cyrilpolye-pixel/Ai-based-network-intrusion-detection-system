import pandas as pd
import requests
import time

# ============================================================
# SETTINGS
# ============================================================

CSV_FILE = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
API_URL = "http://127.0.0.1:5001/predict"

# Number of CICIDS PortScan rows to test
ROWS_TO_TEST = 20

# ============================================================
# THE SAME 78 FEATURE ORDER USED BY app.py
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
# NORMALIZE COLUMN NAMES
# ============================================================

def normalize_columns(df):
    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
        .str.replace("\ufeff", "", regex=False)
    )

    return df


# ============================================================
# MAIN
# ============================================================

print("=" * 70)
print("CICIDS2017 PORTSCAN MODEL TEST")
print("=" * 70)

# ------------------------------------------------------------
# Check ML API
# ------------------------------------------------------------

print("\nChecking ML service...")

try:
    response = requests.get(
        "http://127.0.0.1:5001/",
        timeout=3
    )

    print("ML service is reachable.")

except Exception as e:
    print("ERROR: Could not connect to ML service.")
    print()
    print("Make sure this is running in another terminal:")
    print()
    print("    python app.py")
    print()
    print("Error:", e)
    raise SystemExit


# ------------------------------------------------------------
# Load CSV
# ------------------------------------------------------------

print("\nLoading CICIDS2017 PortScan CSV...")

try:
    df = pd.read_csv(CSV_FILE, low_memory=False)
except Exception as e:
    print("ERROR loading CSV:")
    print(e)
    raise SystemExit

df = normalize_columns(df)

print("Rows loaded   :", len(df))
print("Columns loaded:", len(df))


# ------------------------------------------------------------
# Find Label
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("LABEL INFORMATION")
print("=" * 70)

label_column = None

for column in df.columns:
    if column.lower() == "label":
        label_column = column
        break

if label_column is None:
    print("ERROR: Label column was not found.")
    print("\nAvailable columns:")
    for column in df.columns:
        print(repr(column))

    raise SystemExit

print("Label column:", repr(label_column))

print("\nLabels found:")

print(df[label_column].astype(str).str.strip().value_counts())


# ------------------------------------------------------------
# Check required features
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("FEATURE CHECK")
print("=" * 70)

missing = []

for feature in FEATURE_NAMES:
    if feature not in df.columns:
        missing.append(feature)

if missing:
    print("ERROR: Missing required features:")
    for feature in missing:
        print(" -", feature)

    raise SystemExit

print("All 78 required features are present.")


# ------------------------------------------------------------
# Select PortScan rows
# ------------------------------------------------------------

labels = df[label_column].astype(str).str.strip()

portscan_mask = labels.str.lower().str.contains("portscan", na=False)

portscan_df = df[portscan_mask].copy()

print("\nPortScan rows found:", len(portscan_df))

if len(portscan_df) == 0:
    print("ERROR: No PortScan rows found.")
    raise SystemExit


# ------------------------------------------------------------
# Select rows to test
# ------------------------------------------------------------

test_df = portscan_df.head(ROWS_TO_TEST).copy()

print("Rows selected for testing:", len(test_df))


# ------------------------------------------------------------
# Clean feature values
# ------------------------------------------------------------

features_df = test_df[FEATURE_NAMES].copy()

for column in FEATURE_NAMES:
    features_df[column] = pd.to_numeric(
        features_df[column],
        errors="coerce"
    )

features_df = features_df.replace(
    [float("inf"), float("-inf")],
    0
)

features_df = features_df.fillna(0)


# ------------------------------------------------------------
# Send rows to ML service
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("PREDICTIONS")
print("=" * 70)

attack_count = 0
benign_count = 0
error_count = 0

results = []

for index, (_, row) in enumerate(features_df.iterrows(), start=1):

    feature_values = row.tolist()

    payload = {
        "features": feature_values
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=10
        )

        if response.status_code != 200:
            print(
                f"\nRow {index}: API ERROR "
                f"(HTTP {response.status_code})"
            )

            print(response.text)

            error_count += 1
            continue

        result = response.json()

        attack_type = result.get(
            "attack_type",
            "UNKNOWN"
        )

        confidence = result.get(
            "confidence",
            None
        )

        is_attack = result.get(
            "is_attack",
            None
        )

        actual_label = str(
            test_df.iloc[index - 1][label_column]
        ).strip()

        print(
            f"\nRow {index}"
            f"\n  Actual     : {actual_label}"
            f"\n  Prediction : {attack_type}"
            f"\n  Confidence: {confidence}"
            f"\n  Is attack  : {is_attack}"
        )

        results.append({
            "row": index,
            "actual": actual_label,
            "prediction": attack_type,
            "confidence": confidence,
            "is_attack": is_attack
        })

        if is_attack is True:
            attack_count += 1
        elif is_attack is False:
            benign_count += 1

    except Exception as e:
        print(f"\nRow {index}: REQUEST ERROR")
        print(e)

        error_count += 1

    time.sleep(0.05)


# ============================================================
# SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("PORTSCAN TEST SUMMARY")
print("=" * 70)

print("Actual PortScan rows tested :", len(test_df))
print("Predicted ATTACK            :", attack_count)
print("Predicted BENIGN            :", benign_count)
print("Errors                      :", error_count)

if len(test_df) > 0:
    attack_percentage = (
        attack_count / len(test_df)
    ) * 100

    benign_percentage = (
        benign_count / len(test_df)
    ) * 100

    print(
        f"\nAttack detection rate: "
        f"{attack_percentage:.2f}%"
    )

    print(
        f"Benign prediction rate: "
        f"{benign_percentage:.2f}%"
    )


print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)