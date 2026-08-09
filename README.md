# AI-Based Network Intrusion Detection System (AI-NIDS)

An AI-powered Network Intrusion Detection System (AI-NIDS) that monitors network traffic in real time, detects malicious activities using Artificial Intelligence, visualizes security events through an interactive dashboard, and assists administrators in responding to cyber threats.

---

## 📌 Project Overview

The objective of this project is to develop a modern Network Intrusion Detection System capable of:

- Monitoring live network traffic
- Detecting suspicious and malicious activities using AI models
- Visualizing network statistics and intrusion alerts
- Providing incident analysis and reporting
- Assisting administrators with threat investigation

The system is designed as a web-based dashboard with a React frontend and a backend responsible for network monitoring, AI inference, and report generation.

---

## 🚀 Features

### Planned Features

- User Authentication
- Interactive Dashboard
- Live Network Monitoring
- Traffic Analysis
- Intrusion Detection Alerts
- Incident Details
- Report Generation
- User Profile & Settings
- AI-assisted Threat Detection
- Real-time Data Visualization

---

## 🛠️ Tech Stack

### Frontend

- React
- TypeScript
- Vite
- React Router
- CSS
- Recharts *(planned)*

### Backend

- Node.js / Express *(or Python services for AI modules)*
- REST API

### AI & Networking

- Machine Learning / Deep Learning models
- Packet Capture
- Network Traffic Analysis

---

## 📂 Project Structure

```
AI-Based-Network-Intrusion-Detection-System
│
├── frontend
│   ├── src
│   │   ├── assets
│   │   ├── components
│   │   ├── layouts
│   │   ├── pages
│   │   └── services
│   └── ...
│
├── backend
│
└── README.md
```

---

## 📄 Application Modules

- Login
- Dashboard
- Live Monitoring
- Traffic Analysis
- Intrusion Alerts
- Incident Details
- Reports
- Settings
- Profile

---

## 👥 Team

- **Cyril Poly**
- **Adheena maria**
- **Rinza**
---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/cyrilpolye-pixel/Ai-based-network-intrusion-detection-system.git
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Backend

Backend setup will be added during development.

---

## 📅 Development Status

🚧 Currently under active development.

Completed:
- Initial project setup
- React + TypeScript + Vite
- Project folder structure
- Dashboard layout planning

Upcoming:
- Dashboard UI
- Backend API
- AI Integration
- Real-time Monitoring
- Report Generation

---

## 📜 License

This project is developed for academic and educational purposes.

datasheet
CICIDS2017 

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”, 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

usable algorithms
| Algorithm               | Difficulty      | Good for CICIDS2017?         | Our project                  |
| ----------------------- | --------------- | ---------------------------- | ---------------------------- |
| **Random Forest**       | ⭐⭐ Easy         | ✅ Very good                  | **Excellent**                |
| **Decision Tree**       | ⭐ Easy          | ✅ Good                       | Good baseline                |
| **XGBoost**             | ⭐⭐⭐ Medium      | ✅ Very good                  | **Excellent**                |
| **Logistic Regression** | ⭐ Easy          | ✅ Good baseline              | Useful comparison            |
| **SVM**                 | ⭐⭐⭐ Medium/Hard | ✅ Yes                        | Less attractive for our size |
| **KNN**                 | ⭐⭐ Medium       | ✅ Possible                   | Not a first choice          |
| **Naive Bayes**         | ⭐⭐ Easy         | ✅ Possible                   | Baseline                     |
| **Isolation Forest**    | ⭐⭐ Medium       | ✅ Good for anomaly detection | **Interesting**              |
| **Neural Network/MLP**  | ⭐⭐⭐⭐ Harder     | ✅ Yes                        | Probably unnecessary         |
| **Hybrid RF + XGBoost** | ⭐⭐⭐⭐            | ✅                            | **Very good project option** |
