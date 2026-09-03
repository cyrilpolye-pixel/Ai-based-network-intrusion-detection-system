import os
import pickle
import pandas as pd
import torch
import torch.nn as nn


# ============================================================
# CONFIGURATION
# ============================================================

CSV_FILE = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

SCALER_FILE = "models/scaler.pkl"
MODEL_FILE = "models/cnn1d_binary.pth"

ROWS_TO_TEST = 20


# ============================================================
# MODEL
# ============================================================

class CNN1D_Binary(nn.Module):

    def __init__(self, input_dim=78):

        super().__init__()

        self.conv1 = nn.Conv1d(
            1,
            32,
            kernel_size=3,
            padding=1
        )

        self.conv2 = nn.Conv1d(
            32,
            64,
            kernel_size=3,
            padding=1
        )

        self.pool = nn.AdaptiveAvgPool1d(1)

        self.fc = nn.Linear(
            64,
            2
        )

    def forward(self, x):

        x = x.unsqueeze(1)

        x = torch.relu(
            self.conv1(x)
        )

        x = torch.relu(
            self.conv2(x)
        )

        x = self.pool(x)

        x = x.squeeze(-1)

        return self.fc(x)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("CICIDS2017 PORTSCAN INSPECTION")
print("=" * 70)

if not os.path.exists(CSV_FILE):

    print()
    print("ERROR: CSV file not found:")
    print(CSV_FILE)
    print()

    raise SystemExit


print()
print("Loading CSV...")

df = pd.read_csv(
    CSV_FILE,
    low_memory=False
)

print(
    f"Rows loaded: {len(df)}"
)

print(
    f"Columns loaded: {len(df.columns)}"
)


# ============================================================
# SHOW LABELS
# ============================================================

print()
print("=" * 70)
print("LABELS")
print("=" * 70)

if "Label" in df.columns:

    print(
        df["Label"]
        .value_counts()
        .head(20)
    )

else:

    print("Label column not found.")


# ============================================================
# CLEAN COLUMN NAMES
# ============================================================

df.columns = (
    df.columns
    .str.strip()
)


# ============================================================
# LOAD SCALER
# ============================================================

print()
print("=" * 70)
print("LOADING SCALER")
print("=" * 70)

with open(
    SCALER_FILE,
    "rb"
) as f:

    scaler = pickle.load(f)


expected_features = list(
    scaler.feature_names_in_
)

print(
    f"Scaler expects: {len(expected_features)} features"
)

print()

for i, name in enumerate(
    expected_features,
    start=1
):

    print(
        f"{i:02d}. {name}"
    )


# ============================================================
# PREPARE FEATURES
# ============================================================

print()
print("=" * 70)
print("PREPARING FEATURES")
print("=" * 70)

drop_columns = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Label",
]

feature_df = df.drop(
    columns=[
        c for c in drop_columns
        if c in df.columns
    ],
    errors="ignore"
)


# Convert everything possible to numeric

feature_df = feature_df.apply(
    pd.to_numeric,
    errors="coerce"
)


# Replace invalid values

feature_df = feature_df.replace(
    [float("inf"), float("-inf")],
    0
)

feature_df = feature_df.fillna(0)


# ============================================================
# CHECK MISSING FEATURES
# ============================================================

missing = [
    feature
    for feature in expected_features
    if feature not in feature_df.columns
]

extra = [
    column
    for column in feature_df.columns
    if column not in expected_features
]


print(
    f"Expected features : {len(expected_features)}"
)

print(
    f"Missing features  : {len(missing)}"
)

print(
    f"Extra features    : {len(extra)}"
)

if missing:

    print()
    print("MISSING FEATURES:")

    for feature in missing:

        print(
            "-",
            feature
        )


# ============================================================
# ALIGN FEATURES
# ============================================================

for feature in missing:

    feature_df[feature] = 0


feature_df = feature_df[
    expected_features
]


print()
print(
    f"Final feature count: {feature_df.shape[1]}"
)


# ============================================================
# DISPLAY SAMPLE FEATURES
# ============================================================

print()
print("=" * 70)
print("FIRST PORTSCAN ROW")
print("=" * 70)

first_row = feature_df.iloc[0]

for i, name in enumerate(
    expected_features,
    start=1
):

    print(
        f"{i:02d}. {name}: {first_row[name]}"
    )


# ============================================================
# SCALE DATA
# ============================================================

print()
print("=" * 70)
print("SCALING DATA")
print("=" * 70)

X = scaler.transform(
    feature_df
)


print(
    f"Scaled shape: {X.shape}"
)


# ============================================================
# LOAD MODEL
# ============================================================

print()
print("=" * 70)
print("LOADING BINARY MODEL")
print("=" * 70)

model = CNN1D_Binary(
    input_dim=78
)

state = torch.load(
    MODEL_FILE,
    map_location="cpu"
)

model.load_state_dict(
    state
)

model.eval()

print(
    "Binary model loaded successfully."
)


# ============================================================
# PREDICT SAMPLE ROWS
# ============================================================

print()
print("=" * 70)
print(
    f"TESTING FIRST {ROWS_TO_TEST} PORTSCAN ROWS"
)
print("=" * 70)


rows = min(
    ROWS_TO_TEST,
    len(X)
)

X_test = torch.tensor(
    X[:rows],
    dtype=torch.float32
)


with torch.no_grad():

    outputs = model(
        X_test
    )

    probabilities = torch.softmax(
        outputs,
        dim=1
    )

    predictions = torch.argmax(
        probabilities,
        dim=1
    )


# ============================================================
# DISPLAY PREDICTIONS
# ============================================================

attack_count = 0
benign_count = 0


for i in range(rows):

    prediction = int(
        predictions[i]
    )

    benign_probability = float(
        probabilities[i][0]
    )

    attack_probability = float(
        probabilities[i][1]
    )

    if prediction == 1:

        result = "ATTACK"

        attack_count += 1

    else:

        result = "BENIGN"

        benign_count += 1

    print(
        f"Row {i + 1:02d} | "
        f"{result:7s} | "
        f"BENIGN={benign_probability:.4f} | "
        f"ATTACK={attack_probability:.4f}"
    )


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)

print(
    f"Rows tested : {rows}"
)

print(
    f"ATTACK      : {attack_count}"
)

print(
    f"BENIGN      : {benign_count}"
)

if attack_count > 0:

    print()
    print(
        "The binary model recognizes at least "
        "one PortScan row as ATTACK."
    )

else:

    print()
    print(
        "None of the tested rows were classified "
        "as ATTACK."
    )

print("=" * 70)