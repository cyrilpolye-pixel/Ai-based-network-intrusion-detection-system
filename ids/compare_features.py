import pandas as pd

CSV_FILE = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(CSV_FILE)
df.columns = df.columns.str.strip()

print("=" * 80)
print("CICIDS2017 FEATURE CHECK")
print("=" * 80)

print(f"Rows   : {len(df)}")
print(f"Columns: {len(df.columns)}")

print("\nThe 78 ML columns used by the pretrained model:\n")

for i, column in enumerate(df.columns[:78], 1):
    print(f"{i:02d}. {column}")

print("\n" + "=" * 80)
print("CHECKING LAST 8 FEATURES")
print("=" * 80)

for column in df.columns[70:78]:
    print(f"\n{column}")
    print(df[column].head(3).to_string(index=False))

print("\n" + "=" * 80)
print("CHECK COMPLETE")
print("=" * 80)