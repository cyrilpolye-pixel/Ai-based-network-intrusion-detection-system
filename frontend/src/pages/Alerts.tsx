import { useState } from "react";

type Alert = {
  id: number;
  time: string;
  type: string;
  source: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "Blocked" | "Investigating" | "Detected";
};

export default function Alerts() {
  const [alerts] = useState<Alert[]>([
    {
      id: 1,
      time: "10:30 AM",
      type: "DDoS Attack",
      source: "192.168.1.5",
      severity: "Critical",
      status: "Blocked",
    },
    {
      id: 2,
      time: "11:10 AM",
      type: "Port Scan",
      source: "192.168.1.8",
      severity: "Medium",
      status: "Detected",
    },
    {
      id: 3,
      time: "11:45 AM",
      type: "Brute Force",
      source: "192.168.1.12",
      severity: "High",
      status: "Investigating",
    },
    {
      id: 4,
      time: "12:15 PM",
      type: "SQL Injection",
      source: "172.16.0.25",
      severity: "High",
      status: "Blocked",
    },
  ]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "#ef4444";
      case "High":
        return "#f97316";
      case "Medium":
        return "#f59e0b";
      default:
        return "#22c55e";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Blocked":
        return "#22c55e";
      case "Investigating":
        return "#f59e0b";
      default:
        return "#60a5fa";
    }
  };

  return (
    <div style={{ color: "white" }}>
      <h1 style={{ marginBottom: "25px" }}>Intrusion Alerts</h1>

      <div
        style={{
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "12px",
          overflow: "hidden",
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
          }}
        >
          <thead>
            <tr
              style={{
                background: "#111827",
              }}
            >
              <th style={headerStyle}>Time</th>
              <th style={headerStyle}>Attack Type</th>
              <th style={headerStyle}>Source IP</th>
              <th style={headerStyle}>Severity</th>
              <th style={headerStyle}>Status</th>
            </tr>
          </thead>

          <tbody>
            {alerts.map((alert) => (
              <tr
                key={alert.id}
                style={{
                  borderBottom: "1px solid #334155",
                }}
              >
                <td style={cellStyle}>{alert.time}</td>

                <td style={cellStyle}>{alert.type}</td>

                <td style={cellStyle}>{alert.source}</td>

                <td
                  style={{
                    ...cellStyle,
                    color: getSeverityColor(alert.severity),
                    fontWeight: "bold",
                  }}
                >
                  {alert.severity}
                </td>

                <td
                  style={{
                    ...cellStyle,
                    color: getStatusColor(alert.status),
                    fontWeight: "bold",
                  }}
                >
                  {alert.status}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div
        style={{
          marginTop: "25px",
          display: "flex",
          gap: "20px",
        }}
      >
        <button style={primaryButton}>
          Refresh Alerts
        </button>

        <button style={secondaryButton}>
          Export Alerts
        </button>
      </div>
    </div>
  );
}

const headerStyle = {
  padding: "15px",
  textAlign: "left" as const,
  color: "#cbd5e1",
};

const cellStyle = {
  padding: "15px",
};

const primaryButton = {
  background: "#3b82f6",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};

const secondaryButton = {
  background: "#334155",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};
