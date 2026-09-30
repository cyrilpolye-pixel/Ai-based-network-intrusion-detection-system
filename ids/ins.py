import pickle
import torch

MODEL_PATH = "models/cnn1d_binary.pth"
ENCODER_PATH = "models/label_encoder_attacks.pkl"

print("=" * 70)
print("MODEL / LABEL INSPECTION")
print("=" * 70)

print("\nLoading binary model...")
model = torch.load(
    MODEL_PATH,
    map_location="cpu",
    weights_only=False
)

print("Binary model loaded.")
print("Type:", type(model))

print("\nLoading label encoder...")
with open(ENCODER_PATH, "rb") as f:
    encoder = pickle.load(f)

print("Encoder loaded.")
print("Type:", type(encoder))

if hasattr(encoder, "classes_"):
    print("\nEncoder classes:")
    for i, cls in enumerate(encoder.classes_):
        print(f"{i}: {cls}")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)