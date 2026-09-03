import pickle
import os


print("=" * 70)
print("MODEL FILE CHECK")
print("=" * 70)


# ------------------------------------------------------------
# CHECK SCALER
# ------------------------------------------------------------

scaler_path = os.path.join(
    "models",
    "scaler.pkl"
)

print()
print("Scaler:")
print(scaler_path)

print(
    "Exists:",
    os.path.exists(scaler_path)
)

print(
    "Size:",
    os.path.getsize(scaler_path),
    "bytes"
)


try:

    with open(
        scaler_path,
        "rb"
    ) as f:

        scaler = pickle.load(f)

    print(
        "Scaler loaded successfully."
    )

    print(
        "Type:",
        type(scaler)
    )

    if hasattr(
        scaler,
        "feature_names_in_"
    ):

        print(
            "Feature count:",
            len(scaler.feature_names_in_)
        )

        print()
        print("First 5 features:")

        for name in scaler.feature_names_in_[:5]:

            print(
                "-",
                name
            )

except Exception as e:

    print()
    print(
        "SCALER ERROR:"
    )

    print(
        repr(e)
    )


# ------------------------------------------------------------
# CHECK BINARY MODEL
# ------------------------------------------------------------

model_path = os.path.join(
    "models",
    "cnn1d_binary.pth"
)

print()
print("=" * 70)
print("BINARY MODEL")
print("=" * 70)

print(
    "Exists:",
    os.path.exists(model_path)
)

print(
    "Size:",
    os.path.getsize(model_path),
    "bytes"
)


try:

    import torch

    state = torch.load(
        model_path,
        map_location="cpu"
    )

    print(
        "Binary model loaded successfully."
    )

    print(
        "Object type:",
        type(state)
    )

except Exception as e:

    print()
    print(
        "MODEL ERROR:"
    )

    print(
        repr(e)
    )


print()
print("=" * 70)
print("CHECK COMPLETE")
print("=" * 70)