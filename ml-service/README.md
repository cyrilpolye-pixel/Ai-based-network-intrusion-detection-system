# ML Service

The ML service contains the Python components for training and serving the intrusion-detection model used by AI-NIDS.

## Responsibilities

- Prepare CICIDS2017-style network traffic datasets.
- Train and evaluate intrusion-detection models.
- Store generated model artifacts under `models/`.
- Expose prediction endpoints for the Node/React application.

## Project Layout

```text
ml-service/
├── app.py                 # Service entry point
├── requirements.txt       # Python dependencies
├── src/
│   ├── app.py             # Prediction API implementation
│   ├── predict.py         # Model inference helpers
│   └── train.py           # Training workflow
├── data/.gitkeep          # Dataset placeholder
└── models/.gitkeep        # Model artifact placeholder
```

## Setup

```bash
cd ml-service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Data and Model Artifacts

Large datasets and trained model artifacts are intentionally ignored by Git. Keep dataset files in `ml-service/data/` and generated model files in `ml-service/models/`. The `.gitkeep` files preserve the folder structure for new checkouts.

## Development Notes

- The recommended dataset for experiments is CICIDS2017.
- Random Forest and XGBoost are strong candidates for the tabular traffic features used in this project.
- Keep reusable preprocessing, training, and inference logic in `src/` so the service entry points stay small.
