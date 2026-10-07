# AI-NIDS Backend

The backend service for the AI-Based Network Intrusion Detection System (AI-NIDS). Built with Node.js, Express, MongoDB (Mongoose), and Socket.IO.

---

## Key Features

- **Authentication & Security**: User registration, login, and profile management secured by JSON Web Tokens (JWT) and bcrypt password hashing.
- **Real-Time Attack & Traffic Ingestion**:
  - `POST /api/detections/live-flow`: High-throughput live flow ingestion that broadcasts real-time traffic to the React dashboard via Socket.IO without exhausting MongoDB storage.
  - `POST /api/detections/attack`: Ingests confirmed behavioral and ML attacks (PortScan, BruteForce, HTTP DoS, TCP Connection Flood, UDP Flood, ICMP Flood), stores them as `TrafficLog` and `Alert` records, and emits live notifications.
- **Live WebSocket Server (Socket.IO)**:
  - Broadcasts `live-traffic`, `alert-created`, `traffic-update`, and `dashboard-update` events to connected frontend clients.
- **Threat & Alert Management**: Real-time intrusion alert tracking, severity assignment (`Critical`, `High`, `Medium`, `Low`), status updates (`Unread`, `Read`, `Dismissed`).
- **Traffic Analysis & Reporting**: Filtering, pagination, and historical traffic summaries by protocol, attack category, and timestamp.
- **Incident Investigation**: Complete details view for tracked security incidents.

---

## Project Structure

```text
backend/
├── server.js                 # Entry point: initializes Express, HTTP, Socket.IO, and DB
├── package.json              # Backend dependencies and scripts
├── .env                      # Environment variables (PORT, MONGO_URI, JWT_SECRET)
└── src/
    ├── config/
    │   ├── db.js             # Mongoose MongoDB connection
    │   └── socket.js         # Socket.IO instance and connection handling
    ├── controllers/
    │   ├── alertController.js      # Alert queries and status management
    │   ├── authController.js       # Register, login, profile authentication
    │   ├── detectionController.js  # Live flow & attack detection ingestion
    │   ├── incidentController.js   # Security incident investigation
    │   ├── reportController.js     # Historical report generation
    │   ├── settingsController.js   # System preferences
    │   └── trafficController.js    # Traffic logs & aggregation
    ├── middleware/
    │   └── authMiddleware.js       # JWT authorization guard
    ├── models/
    │   ├── Alert.js          # Intrusion alert schema
    │   ├── Incident.js       # Security incident schema
    │   ├── Report.js         # Security report schema
    │   ├── Settings.js       # System configuration schema
    │   ├── TrafficLog.js     # Network flow record schema
    │   └── User.js           # User account schema
    └── routes/
        ├── alertRoutes.js
        ├── authRoutes.js
        ├── detectionRoutes.js
        ├── incidentRoutes.js
        ├── reportRoutes.js
        ├── settingsRoutes.js
        └── trafficRoutes.js
```

---

## Setup & Running

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Configure Environment (`.env`)
```env
PORT=5000
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/ainids
JWT_SECRET=your_jwt_secret_key
CLIENT_URL=http://localhost:5173
```

### 3. Start the Server
```bash
# Development mode (with nodemon):
npm run dev

# Production mode:
npm start
```
The server will run at `http://localhost:5000`.

---

## API Endpoints Overview

| Category | Method | Endpoint | Description |
|---|---|---|---|
| **Auth** | `POST` | `/api/auth/register` | Register a new user |
| | `POST` | `/api/auth/login` | Authenticate and obtain JWT |
| | `GET` | `/api/auth/profile` | Get current authenticated user profile |
| **Detections** | `POST` | `/api/detections/live-flow` | Broadcast live flow via Socket.IO (non-persistent stream) |
| | `POST` | `/api/detections/attack` | Ingest behavioral/ML attacks, persist TrafficLog + Alert |
| | `POST` | `/api/detections/portscan` | Ingest PortScan detections |
| **Traffic** | `GET` | `/api/traffic/logs` | Fetch historical network traffic logs |
| | `GET` | `/api/traffic/summary` | Get aggregated protocol/label counts |
| **Alerts** | `GET` | `/api/alerts` | Get all intrusion alerts with pagination/filters |
| | `PATCH` | `/api/alerts/:id/status` | Mark alert as Read or Dismissed |
| **Incidents** | `GET` | `/api/incidents` | Fetch correlated incident records |
| **Reports** | `GET` | `/api/reports` | Fetch generated security reports |
| **Settings** | `GET` / `PUT` | `/api/settings` | Get and update user/system preferences |
