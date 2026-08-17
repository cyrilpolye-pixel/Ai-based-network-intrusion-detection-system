# AI-Based Network Intrusion Detection System (AI-NIDS)

AI-NIDS is a full-stack academic network intrusion detection system designed to monitor network traffic, detect suspicious activity using machine-learning models, and present security events through a web-based dashboard.

The system combines a React frontend, Node.js/Express backend, MongoDB database, and a Python-based ML service.

## Project Goals

- Monitor live and historical network traffic.
- Detect normal and malicious network traffic using machine-learning models.
- Classify detected attacks into supported attack categories.
- Store traffic and security events in MongoDB.
- Provide real-time intrusion alerts.
- Visualize traffic, alerts, incidents, reports, and system information through a web dashboard.
- Allow authenticated users to review detected threats and system activity.

## Features

- User registration and login.
- JWT-based authentication and protected routes.
- User profile with authenticated user information.
- Dashboard with traffic and security metrics.
- Live network monitoring.
- Traffic analysis using backend traffic records.
- Intrusion alert management.
- Incident details.
- Reports.
- System settings.
- Real-time alert updates using Socket.IO.
- AI-based network traffic prediction.
- Binary attack detection.
- Attack-type classification.
- MongoDB persistence for application data.

## Tech Stack

### Frontend

- React
- TypeScript
- Vite
- React Router
- CSS
- Recharts
- Axios
- Socket.IO Client

### Backend

- Node.js
- Express
- MongoDB
- Mongoose
- REST API
- JWT authentication
- Socket.IO

### ML Service

- Python
- PyTorch
- Scikit-learn
- Joblib
- CICIDS2017 dataset
- 1D Convolutional Neural Networks (CNN)

The ML service currently uses two pretrained CNN models:

- Binary CNN for normal/attack detection.
- Attack-class CNN for attack-type classification.

---

## Project Structure

```text
Ai-based-network-intrusion-detection-system/
├── backend/              # Node.js + Express backend
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   └── ...
│
├── frontend/             # React + TypeScript frontend
│   ├── src/
│   │   ├── components/
│   │   ├── layouts/
│   │   ├── pages/
│   │   ├── services/
│   │   └── ...
│   └── ...
│
├── ml-service/           # Python ML service
│   ├── data/
│   ├── models/
│   ├── src/
│   ├── app.py
│   ├── predict_test.py
│   ├── test_model.py
│   ├── requirements.txt
│   └── README.md
│
├── package.json
└── README.md


Application Modules
Login
Signup
Dashboard
Live Monitoring
Traffic Analysis
Intrusion Alerts
Incident Details
Reports
Settings
Profile
Machine Learning
Current ML Pipeline

The current AI-NIDS prediction pipeline uses pretrained 1D Convolutional Neural Network (CNN) models.

The prediction process consists of two stages:

1. Binary Classification

The binary CNN determines whether the supplied network traffic is:

BENIGN
ATTACK
2. Attack Classification

If the traffic is classified as an attack, the attack-class CNN determines the specific attack category.

The current pretrained attack classifier supports 14 attack classes.

Before prediction, the traffic features are processed using the saved feature scaler and the attack labels are decoded using the saved label encoder.

Model Artifacts

The following pretrained model files are used by the ML service:

File	Purpose
cnn1d_binary.pth	Binary classifier for BENIGN vs ATTACK
cnn1d_attacks_only.pth	Attack-type classifier for 14 attack classes
scaler.pkl	Feature scaler used during preprocessing
label_encoder_attacks.pkl	Label encoder for attack-class predictions

These files are stored in:

ml-service/models/
Source of the Pretrained Models

The pretrained ML models and related Python implementation were obtained from the following Hugging Face source:

Hugging Face user: saidimn

Hugging Face – saidimn

The IDS backend implementation from the same source was also used as a reference for the pretrained model service:

IDS Backend – saidimn

The referenced IDS backend contains Python components including:

app.py
requirements.txt
Docker configuration
ML prediction/service implementation

The pretrained model artifacts used in this project were adapted and integrated into the project's own Python ML service and connected to the Node.js backend.

ML Service Testing

The ML service has been tested using CICIDS2017 traffic data.

A DDoS traffic record was supplied to the prediction endpoint and produced a result equivalent to:

Binary result: ATTACK
Final classification: DDoS

The tested model reported high confidence for both binary attack detection and attack classification.

Dataset

The project uses traffic data based on the CICIDS2017 dataset.

The dataset was created by:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani

"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"

4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, 2018.

Dataset files used for ML testing are stored under:

ml-service/data/

The available traffic files include CICIDS2017 working-hour traffic captures such as:

Monday Working Hours
Tuesday Working Hours
Wednesday Working Hours
Thursday Morning Web Attacks
Thursday Afternoon Infiltration
Friday Working Hours Morning
Friday Afternoon DDoS
Friday Afternoon PortScan

Large dataset files are kept locally and are not intended to be committed to the Git repository.

Backend and ML Integration

The Node.js backend communicates with the Python ML service for AI-based traffic prediction.

The general processing flow is:

Network Traffic
      ↓
Node.js Backend
      ↓
Python ML Service
      ↓
Feature Preprocessing
      ↓
Binary CNN
      ↓
BENIGN / ATTACK
      ↓
Attack CNN
      ↓
Attack Type
      ↓
Backend
      ↓
MongoDB / Dashboard / Alerts

The frontend does not directly communicate with the Python ML service. The backend acts as the application API layer and handles communication with the ML service.

Installation
1. Clone the Repository
git clone https://github.com/cyrilpolye-pixel/Ai-based-network-intrusion-detection-system.git
cd Ai-based-network-intrusion-detection-system
2. Install Frontend Dependencies
cd frontend
npm install
npm run dev

The frontend development server runs on the configured Vite port.

3. Install Backend Dependencies
cd backend
npm install
npm run dev

The backend runs on the configured API port.

Configure the backend environment variables in a local .env file.

Environment files containing secrets are excluded from Git.

4. Set Up the ML Service
cd ml-service
python -m venv .venv

Activate the virtual environment.

Windows
.venv\Scripts\activate
Linux/macOS
source .venv/bin/activate

Install the required Python packages:

pip install -r requirements.txt

Place the required datasets in:

ml-service/data/

Place the pretrained model artifacts in:

ml-service/models/
Services

The application consists of three main services:

Service	Technology	Purpose
Frontend	React + Vite	User interface and dashboard
Backend	Node.js + Express	Authentication, APIs, database and application logic
ML Service	Python + PyTorch	Network traffic prediction

MongoDB is used by the backend for persistent application data.

During local development, the services are run independently and communicate through their configured local ports.

Authentication

The application uses JWT-based authentication.

Authentication functionality includes:

User registration.
User login.
Invalid-login handling.
JWT/token storage.
Protected application routes.
Authenticated API requests.
User profile retrieval.
Logout.
Redirecting unauthenticated users to the login page.

Protected pages include:

Dashboard
Live Monitoring
Traffic Analysis
Intrusion Alerts
Reports
Settings
Profile
Real-Time Alerts

The backend uses Socket.IO to provide real-time alert updates to the frontend.

When a new intrusion alert is created, the frontend can receive the event and update the alerts page without requiring a complete page reload.

Alert statuses include:

Unread
Read
Resolved
Development and Testing

The project has been tested across the main application layers.

Frontend

The production frontend build is verified using:

npm run build

The build performs TypeScript checking and Vite production compilation.

Backend

Backend API endpoints are tested for:

Authentication
Protected requests
Dashboard data
Traffic records
Alerts
AI prediction integration
ML Service

The ML service is tested using real CICIDS2017 traffic records and the pretrained CNN models.

A sample DDoS record has been successfully processed through the prediction endpoint and classified as an attack.

Additional Algorithms

Random Forest and other machine-learning algorithms may be used for future comparison or experimentation.

Algorithms considered include:

Random Forest
Decision Tree
XGBoost
Logistic Regression
SVM
KNN
Naive Bayes
Isolation Forest

These algorithms should not be considered part of the current production prediction pipeline unless they are implemented and integrated into the ML service.

Development Status

The core full-stack application is implemented with:

React frontend
Node.js/Express backend
MongoDB database
JWT authentication
Real-time Socket.IO alerts
Python ML service
Pretrained CNN models
Backend-to-ML prediction integration
Traffic analysis
Intrusion alerts
Reports
Profile
Settings
Live monitoring

Further work can include additional ML model comparison, model retraining, performance evaluation, and deployment improvements.

Team
Cyril Poly
Adheena Maria
Rinza

 ## License

This project is developed for academic and educational purposes.