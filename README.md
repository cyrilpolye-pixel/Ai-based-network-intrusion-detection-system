# AI-Based Network Intrusion Detection System (AI-NIDS)

AI-NIDS is a comprehensive, full-stack network intrusion detection system designed to monitor live network traffic, detect cyber attacks using deep learning and behavioral heuristics, and deliver real-time security events through an interactive web dashboard.

The system combines:
- A **React + TypeScript + Vite** responsive security operations dashboard.
- A **Node.js + Express + MongoDB** backend with **Socket.IO** real-time event streaming.
- A **Python IDS engine** integrating live **Scapy** packet sniffing, 78-feature CICIDS2017 extraction, **PyTorch 1D-CNN** models, and multi-vector **behavioral attack detectors**.

---

## Key Features

- **Hybrid Attack Detection**:
  - **Machine Learning**: Two-stage deep learning pipeline (Binary 1D-CNN for normal vs. attack classification, and Multi-Class 1D-CNN supporting 14 attack classes).
  - **Behavioral Detection**: Real-time sliding-window behavioral engines for **PortScan**, **BruteForce**, **HTTP DoS**, **TCP Connection Flood**, **UDP Flood**, and **ICMP Flood**.
- **Live Monitoring & Alerting**:
  - Non-blocking live traffic flow streaming using WebSockets (`Socket.IO`).
  - Real-time intrusion alerts with severity scoring (`Critical`, `High`, `Medium`, `Low`).
- **Comprehensive SOC Dashboard**:
  - Executive security overview with threat level indicators and protocol charts.
  - Historical traffic analysis with multi-field search and filtering.
  - Incident investigation forensics detailing packet timestamps, metrics, and detection methods.
  - Exportable security reports and system configurations.
- **Controlled Attack Simulation Suite**:
  - Built-in test scripts in `ids/attack/` for simulating all 6 attack categories in controlled local testbeds.

---

## System Architecture

```text
               +---------------------------------------------------+
               |             Network Interface / Scapy            |
               +---------------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |     ids/flow_cat.py Engine    |
                         +-------------------------------+
                            /                         \
                           v                           v
              +-------------------------+   +-------------------------+
              | 6 Behavioral Detectors  |   | 78-Feature Extractor    |
              | (PortScan, BruteForce,  |   | (CICIDS2017 feat.py)    |
              |  DoS, SYN/UDP/ICMP Flood)|   +-------------------------+
              +-------------------------+                |
                           \                             v
                            \               +-------------------------+
                             \              |  Flask ML API (app.py)  |
                              \             |  Stage 1: Binary CNN    |
                               \            |  Stage 2: Attack CNN    |
                                \           +-------------------------+
                                 \                       /
                                  v                     v
                        +---------------------------------------+
                        |   Node.js + Express Backend (5000)   |
                        +---------------------------------------+
                           /                |                \
                          v                 v                 v
                   +------------+    +------------+    +---------------+
                   |  MongoDB   |    | Socket.IO  |    | JWT Security  |
                   |  Database  |    | (Live Feed)|    | & Controller  |
                   +------------+    +------------+    +---------------+
                                            |
                                            v
                        +---------------------------------------+
                        |      React Web Dashboard (5173)       |
                        +---------------------------------------+
```

---

## Project Structure

```text
Ai-based-network-intrusion-detection-system/
├── backend/                  # Node.js + Express + Socket.IO API server
│   ├── server.js             # Main server entry point
│   ├── package.json          # Dependencies and scripts
│   ├── src/
│   │   ├── config/           # Database and Socket.IO configurations
│   │   ├── controllers/      # Route handlers (auth, detections, alerts, traffic)
│   │   ├── middleware/       # JWT authentication middleware
│   │   ├── models/           # Mongoose schemas (User, TrafficLog, Alert, Incident)
│   │   └── routes/           # REST API endpoints
│   └── README.md             # Backend service documentation
│
├── frontend/                 # React 18 + TypeScript + Vite web dashboard
│   ├── src/
│   │   ├── components/       # UI components (Navbar, Sidebar, ProtectedRoute)
│   │   ├── context/          # React contexts (AuthContext)
│   │   ├── layouts/          # Layout shells (MainLayout)
│   │   ├── pages/            # Dashboard views & modular CSS
│   │   └── services/         # Axios API & Socket.IO client
│   └── README.md             # Frontend application documentation
│
├── ids/                      # Network capture & ML inference subsystem
│   ├── app.py                # Flask ML prediction API (port 5001)
│   ├── flow_cat.py           # Live Scapy packet sniffer & behavioral engine
│   ├── feat.py               # 78-feature CICIDS2017 extractor
│   ├── capture_config.py     # Network capture settings & detector thresholds
│   ├── requirements.txt      # Python dependencies
│   ├── models/               # Pretrained PyTorch models & scalers
│   │   ├── cnn1d_binary.pth  # Binary classifier (BENIGN vs ATTACK)
│   │   ├── cnn1d_attacks_only.pth # 14-class attack classifier
│   │   ├── scaler.pkl        # StandardScaler (78 features)
│   │   └── label_encoder_attacks.pkl # LabelEncoder for attack categories
│   ├── attack/               # Controlled attack test simulation suite
│   │   ├── portscan_test.py  # PortScan test script
│   │   ├── bruteforce_server.py # Authentication test server (port 8080)
│   │   ├── bruteforce_test.py # BruteForce attack test script
│   │   ├── http_dos_test.py  # HTTP DoS attack test script
│   │   ├── tcp_flood_test.py # TCP Connection Flood test script
│   │   ├── udp_flood_test.py # UDP Flood attack test script
│   │   └── icmp_flood_test.py # ICMP Ping Flood test script
│   ├── sort/                 # Standalone model verification scripts & logs
│   │   ├── check_model.py    # Model artifact integrity check
│   │   ├── test_model.py     # Architecture compatibility test
│   │   ├── test_real_portscan.py # Real dataset PortScan validation
│   │   └── ...               # Matching .txt execution logs
│   ├── Outputs/              # Daily traffic flow CSV logs
│   └── README.md             # IDS & ML service documentation
│
└── README.md                 # Root project documentation
```

---

## Detection Capabilities

### 1. Machine Learning (1D-CNN)
Trained on the **CICIDS2017** benchmark dataset using 78 tabular statistical flow features:
- **Binary Detection**: Fast determination of `BENIGN` vs. `ATTACK`.
- **Attack Classification**: Classifies detected attacks into specific categories including DDoS, DoS GoldenEye, DoS Hulk, DoS Slowloris, DoS Slowhttptest, FTP-Patator, SSH-Patator, PortScan, Bot, and Infiltration.

### 2. Behavioral Attack Detectors
Sliding-window algorithms running directly on live packet streams in `flow_cat.py`:

| Attack Category | Detection Criteria | Default Threshold |
|---|---|---|
| **PortScan** | Probing multiple distinct ports from a single source | 10 ports within 5s |
| **BruteForce** | Rapid authentication requests targeting auth ports (8080, 80, 443, 22, 21) | 8 attempts within 10s |
| **HTTP DoS** | High-frequency HTTP request bursts (Hulk / Slowloris) | 25 requests within 5s |
| **TCP Connection Flood**| Volumetric SYN packet floods targeting a single port | 30 SYNs within 3s |
| **UDP Flood** | Volumetric UDP datagram floods | 35 packets within 3s |
| **ICMP Flood** | High-rate ICMP Echo Request ping floods | 20 packets within 3s |

---

## Getting Started

### Prerequisites
- **Node.js** (v18+) & **npm**
- **Python** (v3.10+)
- **MongoDB** instance (local or Atlas)
- **Npcap** (Windows) or **libpcap** (Linux/macOS) for Scapy live capture

---

### Step-by-Step Setup

#### 1. Start the Backend API & Socket Server
```bash
cd backend
npm install
npm run dev
```
*(Runs at `http://localhost:5000`)*

#### 2. Start the Frontend Web Dashboard
In a new terminal:
```bash
cd frontend
npm install
npm run dev
```
*(Runs at `http://localhost:5173`)*

#### 3. Start the Python Machine Learning Service
In a new terminal:
```bash
cd ids
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```
*(Runs at `http://127.0.0.1:5001`)*

#### 4. Start Live Network Packet Sniffing
In a new terminal (elevated/Administrator privileges recommended for Scapy):
```bash
cd ids
python flow_cat.py
```
*(Automatically detects your active IP, begins monitoring traffic, and streams live data to the dashboard)*

---

### Running Attack Tests

To verify detection in a controlled local environment:
```bash
cd ids/attack

# 1. Test BruteForce:
python bruteforce_server.py    # In one terminal (runs on port 8080)
python bruteforce_test.py      # In another terminal

# 2. Test Scans & Floods:
python portscan_test.py        # PortScan test
python http_dos_test.py        # HTTP DoS burst test
python tcp_flood_test.py       # TCP Connection Flood test
python udp_flood_test.py       # UDP datagram flood test
python icmp_flood_test.py      # ICMP ping flood test
```

All simulated attacks will immediately trigger behavioral alerts in `flow_cat.py`, emit real-time notifications via Socket.IO, and display in the React dashboard.

---

## Dataset Reference

The deep learning models are trained on the **CICIDS2017** dataset:
> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani,  
> *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"*,  
> 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.

---

## Team

- **Cyril Poly**
- **Adheena Maria**
- **Rinza**

---

## License

This project is developed for academic, educational, and research purposes.