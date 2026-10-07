# AI-NIDS Frontend

The web dashboard for the AI-Based Network Intrusion Detection System (AI-NIDS). Built with React 18, TypeScript, Vite, Recharts, and Socket.IO Client.

---

## Key Features

- **Modern Cyber-Security UI**: Sleek, responsive dark mode interface designed for high-density network analytics and SOC operations.
- **Authentication**: JWT-based login and signup screens with route protection and session persistence.
- **Executive Dashboard**: Real-time traffic throughput, threat level status, protocol breakdown charts, and top targeted ports.
- **Live Monitoring**:
  - Real-time packet and flow streaming driven by WebSockets (`Socket.IO`).
  - Active detection badges displaying ML classification and behavioral attack alerts instantly.
  - Interactive stream controls (Pause, Resume, Clear, Auto-scroll).
- **Traffic Analysis**:
  - Filterable, searchable table of historical traffic logs from backend/MongoDB.
  - Query by IP address, port, protocol (TCP, UDP, ICMP), or attack label.
  - Aggregated statistical distributions (protocol volume, duration, packet count).
- **Intrusion Alerts**:
  - Real-time alert list with severity indicators (`Critical`, `High`, `Medium`, `Low`).
  - One-click status management (`Read`, `Dismissed`).
- **Incident Details**: Detailed forensics view showing complete flow metrics, features, timestamps, and detection methodology.
- **Reports**: Historical threat summaries, classification distributions, and exportable security logs.
- **Settings & Profile**: Theme configurations, notification toggles, and user account management.

---

## Project Structure

```text
frontend/
├── index.html                # Single-page HTML entry point
├── package.json              # Frontend dependencies and scripts
├── vite.config.ts            # Vite build configuration
└── src/
    ├── App.tsx               # Main application routing
    ├── main.tsx              # React DOM mounting
    ├── index.css             # Global design tokens and base styles
    ├── components/           # Reusable UI components
    │   ├── Navbar.tsx        # Top navigation header
    │   ├── Sidebar.tsx       # Collapsible side navigation
    │   └── ProtectedRoute.tsx # Route authentication guard
    ├── context/
    │   └── AuthContext.tsx   # Global authentication state
    ├── layouts/
    │   └── MainLayout.tsx    # Dashboard layout shell
    ├── pages/                # Route-level pages and modular stylesheets
    │   ├── Alerts.tsx / Alerts.css
    │   ├── Dashboard.tsx / Dashboard.css
    │   ├── IncidentDetails.tsx / IncidentDetails.css
    │   ├── LiveMonitoring.tsx / LiveMonitoring.css
    │   ├── Login.tsx / Login.css
    │   ├── Profile.tsx / Profile.css
    │   ├── Reports.tsx / Reports.css
    │   ├── Settings.tsx / Settings.css
    │   ├── Signup.tsx / Signup.css
    │   └── TrafficAnalysis.tsx / TrafficAnalysis.css
    └── services/
        ├── api.ts            # Axios client with JWT interceptors
        └── socket.ts         # Socket.IO client instance
```

---

## Setup & Running

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Configure Environment (`.env`)
Create a `.env` file in `frontend/` if needed (defaults to `http://localhost:5000`):
```env
VITE_API_URL=http://localhost:5000
```

### 3. Start Development Server
```bash
npm run dev
```
Open `http://localhost:5173` in your browser.

### 4. Build for Production
```bash
npm run build      # Type-checks and creates production bundle in dist/
npm run preview    # Previews production bundle locally
```
