# ============================================================
# SCRIPT: inspect_binary_model.py
# PURPOSE: Inspects the PyTorch state_dict checkpoint in
#          models/cnn1d_binary.pth, listing each layer name
#          (Conv1D, BatchNorm1d, Linear) and its tensor shape.
# OUTPUT: Output log saved in inspect_binary_model.txt
# ============================================================

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



