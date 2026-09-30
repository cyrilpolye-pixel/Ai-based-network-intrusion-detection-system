# ============================================================
# AI-NIDS CSV READER
# ============================================================

import csv
from pathlib import Path
from datetime import datetime


# ------------------------------------------------------------
# OUTPUT DIRECTORY
# ------------------------------------------------------------

OUTPUT_DIR = Path("Outputs")


# ------------------------------------------------------------
# GET TODAY'S CSV FILE
# ------------------------------------------------------------

def get_csv_file():
    """
    Return today's AI-NIDS CSV file.

    Example:
        Outputs/output-30-09-26.csv
    """

    date_string = datetime.now().strftime("%d-%m-%y")

    return (
        OUTPUT_DIR
        / f"output-{date_string}.csv"
    )


# ------------------------------------------------------------
# READ TODAY'S CSV
# ------------------------------------------------------------

def read_today_csv():
    """
    Read all flow records from today's CSV file.

    Returns:
        list[dict]
    """

    csv_file = get_csv_file()

    if not csv_file.exists():

        print(
            f"[CSV] File not found: {csv_file}"
        )

        return []

    rows = []

    try:

        with open(
            csv_file,
            "r",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            reader = csv.DictReader(
                csvfile
            )

            for row in reader:

                rows.append(row)

        print(
            f"[CSV] Loaded {len(rows)} flow records"
        )

        return rows

    except Exception as error:

        print(
            f"[CSV] Read error: {error}"
        )

        return []


# ------------------------------------------------------------
# READ LATEST N FLOWS
# ------------------------------------------------------------

def read_latest_flows(limit=100):
    """
    Return the latest N flow records.
    """

    rows = read_today_csv()

    if not rows:

        return []

    return rows[-limit:]


# ------------------------------------------------------------
# READ ONLY ATTACKS
# ------------------------------------------------------------

def read_attacks():
    """
    Return only rows where the final attack type
    is not BENIGN.
    """

    rows = read_today_csv()

    attacks = []

    for row in rows:

        attack_type = (
            row.get(
                "attack_type",
                ""
            )
            .strip()
        )

        if (
            attack_type
            and
            attack_type.upper()
            != "BENIGN"
        ):

            attacks.append(row)

    return attacks


# ------------------------------------------------------------
# READ ONLY BENIGN TRAFFIC
# ------------------------------------------------------------

def read_benign():
    """
    Return only benign flow records.
    """

    rows = read_today_csv()

    benign = []

    for row in rows:

        attack_type = (
            row.get(
                "attack_type",
                ""
            )
            .strip()
            .upper()
        )

        if attack_type == "BENIGN":

            benign.append(row)

    return benign


# ------------------------------------------------------------
# CSV STATISTICS
# ------------------------------------------------------------

def get_csv_statistics():
    """
    Generate basic statistics from today's CSV.
    """

    rows = read_today_csv()

    total = len(rows)

    attacks = 0
    benign = 0

    attack_types = {}

    for row in rows:

        attack_type = (
            row.get(
                "attack_type",
                "UNKNOWN"
            )
            .strip()
        )

        if attack_type.upper() == "BENIGN":

            benign += 1

        else:

            attacks += 1

            attack_types[attack_type] = (
                attack_types.get(
                    attack_type,
                    0
                )
                + 1
            )

    return {

        "total_flows":
            total,

        "attacks":
            attacks,

        "benign":
            benign,

        "attack_types":
            attack_types,
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    rows = read_latest_flows(10)

    print(
        "\nLATEST FLOWS"
    )

    print(
        "=" * 70
    )

    for row in rows:

        print(
            f"{row.get('timestamp')} | "
            f"{row.get('src_ip')} -> "
            f"{row.get('dst_ip')} | "
            f"{row.get('attack_type')} | "
            f"{row.get('confidence')}"
        )

    print(
        "\nSTATISTICS"
    )

    print(
        "=" * 70
    )

    print(
        get_csv_statistics()
    )