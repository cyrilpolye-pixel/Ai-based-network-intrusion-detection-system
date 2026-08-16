# AI-Based Network Intrusion Detection System (AI-NIDS)

AI-NIDS is a full-stack academic project for monitoring network traffic, detecting suspicious activity with machine-learning models, and presenting security events through a React dashboard.

## Project Goals

- Monitor live and historical network traffic.
- Detect suspicious or malicious activity with AI/ML models.
- Visualize traffic, alerts, incidents, and reports in a web dashboard.
- Help administrators review threats and decide response actions.

## Features

- User authentication with login and signup screens.
- Dashboard with high-level traffic and alert metrics.
- Live monitoring and traffic-analysis pages.
- Intrusion alert listing and incident detail pages.
- Report, profile, and system-settings screens.
- Backend API structure for authentication, dashboards, traffic, alerts, and AI integration.
- Python ML service structure for training and prediction workflows.

## Tech Stack

### Frontend

- React
- TypeScript
- Vite
- React Router
- CSS
- Recharts

### Backend

- Node.js
- Express
- MongoDB/Mongoose models
- REST API routes
- Socket support for realtime updates

### ML Service

- Python
- CICIDS2017-style datasets
- Machine-learning model training and prediction scripts

## Project Structure

```text
Ai-based-network-intrusion-detection-system/
├── backend/              # Express API, routes, controllers, models, sockets
├── frontend/             # React + TypeScript + Vite application
├── ml-service/           # Python ML training and prediction service
├── package.json          # Root workspace scripts/dependencies
└── README.md
```

## Application Modules

- Login
- Signup
- Dashboard
- Live Monitoring
- Traffic Analysis
- Intrusion Alerts
- Incident Details
- Reports
- Settings
- Profile

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/cyrilpolye-pixel/Ai-based-network-intrusion-detection-system.git
cd Ai-based-network-intrusion-detection-system
```

### 2. Install frontend dependencies

```bash
cd frontend
npm install
npm run dev
```

### 3. Install backend dependencies

```bash
cd backend
npm install
npm run dev
```

Configure backend environment variables in a local `.env` file. Environment files are ignored by Git.

### 4. Set up the ML service

```bash
cd ml-service
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Place large datasets in `ml-service/data/` and trained models in `ml-service/models/`. These generated assets are ignored by Git while `.gitkeep` files preserve the directories.

## Dataset

The recommended dataset for experiments is CICIDS2017:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”, 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

## Candidate Algorithms

| Algorithm | Difficulty | Good for CICIDS2017? | Project Fit |
| --- | --- | --- | --- |
| Random Forest | Easy | Very good | Excellent baseline |
| Decision Tree | Easy | Good | Good baseline |
| XGBoost | Medium | Very good | Excellent candidate |
| Logistic Regression | Easy | Good baseline | Useful comparison |
| SVM | Medium/Hard | Yes | Less attractive for larger datasets |
| KNN | Medium | Possible | Not a first choice |
| Naive Bayes | Easy | Possible | Baseline |
| Isolation Forest | Medium | Good for anomaly detection | Interesting option |
| Neural Network/MLP | Harder | Yes | Optional advanced model |
| Hybrid RF + XGBoost | Harder | Yes | Strong project option |

## Development Status

The project is under active development. Current work includes improving frontend pages, refining API integrations, and organizing ML-service workflows.

## Team

- Cyril Poly
- Adheena Maria
- Rinza

## License

This project is developed for academic and educational purposes.
