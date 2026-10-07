# AI-NIDS Packet Capture & Machine Learning Engine (`ids/`)

The core intrusion detection subsystem of AI-NIDS. Contains the live network traffic capture engine, real-time behavioral attack detectors, 78-feature extractor, PyTorch 1D-CNN inference service, and attack simulation tools.

---

## Directory Overview

```text
ids/
├── app.py                   # Flask ML Prediction API (port 5001)
├── flow_cat.py              # Live network capture, behavioral analysis & flow exporter
├── feat.py                  # 78-feature CICIDS2017 extractor
├── capture_config.py        # Capture settings, thresholds & IP detection
├── requirements.txt         # Python dependencies
├── models/                  # Pretrained PyTorch models & scalers
│   ├── cnn1d_binary.pth     # Binary CNN (BENIGN vs ATTACK)
│   ├── cnn1d_attacks_only.pth # Multi-class attack classifier (14 attack types)
│   ├── scaler.pkl           # StandardScaler for 78 features
│   └── label_encoder_attacks.pkl # LabelEncoder for attack categories
├── attack/                  # Controlled attack simulation suite
│   ├── portscan_test.py     # PortScan attack test
│   ├── bruteforce_server.py # Local authentication server (port 8080)
│   ├── bruteforce_test.py   # BruteForce attack test
│   ├── http_dos_test.py     # HTTP DoS attack test
│   ├── tcp_flood_test.py    # TCP Connection Flood (SYN Flood) test
│   ├── udp_flood_test.py    # UDP Flood attack test
│   └── icmp_flood_test.py   # ICMP Ping Flood test
├── sort/                    # Model validation scripts & output logs
│   ├── check_model.py / check_model.txt
│   ├── compare_features.py / compare_feature.txt
│   ├── inspect_binary_model.py / inspect_binary_model.txt
│   ├── peek_portscan1.py / peek_portscan1.txt
│   ├── predict_test.py / predict_test.txt
│   ├── test_binary_benign.py / test_binary_benign.txt
│   ├── test_model.py / test_model.txt
│   └── test_real_portscan.py / test_real_portscan.txt
└── Outputs/                 # Daily generated flow CSV files (e.g. output-07-10-26.csv)
```

---

## Architecture & Workflows

### 1. Live Packet Sniffing & Flow Assembly (`flow_cat.py`)
- Automatically detects the active network interface and local IPv4 address.
- Groups bidirectional IPv4 packets (TCP, UDP, ICMP) into network flows.
- Times out inactive flows after `FLOW_TIMEOUT` seconds and triggers feature extraction.
- Saves flows with all 78 extracted features and predictions into daily CSVs (`Outputs/output-DD-MM-YY.csv`).
- Sends live flows and alerts to the Node.js backend (`http://localhost:5000/api/detections/live-flow` and `/attack`).

### 2. Behavioral Attack Detection Engine
Integrated directly into `flow_cat.py` using sliding-window tracking:
1. **PortScan**: Detects multi-port TCP SYN scanning (`PORTSCAN_PORT_THRESHOLD = 10` ports in 5s).
2. **BruteForce**: Monitors rapid login attempts and auth port probing (`BRUTEFORCE_THRESHOLD = 8` attempts in 10s).
3. **HTTP DoS**: Detects high-rate HTTP GET/POST bursts / Hulk patterns (`HTTP_DOS_THRESHOLD = 25` reqs in 5s).
4. **TCP Connection Flood**: Detects volumetric single-port SYN floods (`TCP_SYN_FLOOD_THRESHOLD = 30` SYNs in 3s).
5. **UDP Flood**: Detects rapid UDP datagram floods (`UDP_FLOOD_THRESHOLD = 35` packets in 3s).
6. **ICMP Flood**: Detects high-rate ping echo floods (`ICMP_FLOOD_THRESHOLD = 20` packets in 3s).

*Note: Behavioral attack detections override ML classifications with 100% confidence to guarantee zero false negatives on active attacks.*

### 3. Machine Learning Prediction API (`app.py`)
- Runs a lightweight Flask service on `http://127.0.0.1:5001/predict`.
- Evaluates flows through a two-stage deep learning pipeline:
  - **Stage 1 (Binary CNN)**: Predicts `BENIGN` vs. `ATTACK`.
  - **Stage 2 (Attack-Class CNN)**: If `ATTACK`, classifies the traffic into 14 distinct attack classes.

---

## Getting Started

### 1. Set Up Environment
```bash
cd ids
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Start the ML Prediction Service
In one terminal:
```bash
python app.py
```
*(Runs at `http://127.0.0.1:5001`)*

### 3. Start Live Packet Capture
In a second terminal (run with Administrator/elevated privileges if required for Scapy/Npcap):
```bash
python flow_cat.py
```
*(Press `Ctrl+C` once to gracefully flush flows and stop, or twice to force exit)*

### 4. Running Attack Simulations
In a third terminal:
```bash
cd ids/attack

# Brute force attack (start bruteforce_server.py first):
python bruteforce_server.py
python bruteforce_test.py

# Volumetric & scan attacks:
python portscan_test.py
python http_dos_test.py
python tcp_flood_test.py
python udp_flood_test.py
python icmp_flood_test.py
```
