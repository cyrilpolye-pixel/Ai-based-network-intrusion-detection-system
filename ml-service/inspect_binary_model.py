import torch

MODEL_PATH = "models/cnn1d_binary.pth"

state_dict = torch.load(
    MODEL_PATH,
    map_location="cpu",
    weights_only=True
)

print("=" * 70)
print("ACTUAL BINARY MODEL CHECKPOINT")
print("=" * 70)

for key, value in state_dict.items():
    print(f"{key:45s} {tuple(value.shape)}")

print("=" * 70)
print("Total keys:", len(state_dict))