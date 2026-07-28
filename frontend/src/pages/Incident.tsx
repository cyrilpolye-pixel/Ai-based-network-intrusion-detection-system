import { useState } from "react";

type Incident = {
  attack: string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "Blocked" | "Investigating" | "Detected";
  packetCount: number;
  time: string;
  recommendation: string;
};

export default function Incident() {
  const [incident] = useState<Incident>({
    attack: "DDoS Attack",
    sourceIP: "192.168.1.5",
    destinationIP: "10.0.0.12",
    protocol: "TCP",
    severity: "Critical",
    status: "Blocked",
    packetCount: 15482,
    time: "28 Jul 2026 - 10:30 AM",
    recommendation:
      "Block the source IP, monitor network traffic, and review firewall rules.",
  });

  const severityColor = () => {
    switch (incident.severity) {
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

  const statusColor = () => {
    switch (incident.status) {
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
      <h1 style={{ marginBottom: "25px" }}>Incident Details</h1>

      <div
        style={{
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "12px",
          padding: "25px",
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
          }}
        >
          <tbody>
            <TableRow label="Attack Type" value={incident.attack} />

            <TableRow label="Source IP" value={incident.sourceIP} />

            <TableRow
              label="Destination IP"
              value={incident.destinationIP}
            />

            <TableRow label="Protocol" value={incident.protocol} />

            <tr>
              <td style={labelStyle}>Severity</td>

              <td
                style={{
                  ...valueStyle,
                  color: severityColor(),
                  fontWeight: "bold",
                }}
              >
                {incident.severity}
              </td>
            </tr>

            <tr>
              <td style={labelStyle}>Status</td>

              <td
                style={{
                  ...valueStyle,
                  color: statusColor(),
                  fontWeight: "bold",
                }}
              >
                {incident.status}
              </td>
            </tr>

            <TableRow
              label="Packet Count"
              value={incident.packetCount.toLocaleString()}
            />

            <TableRow label="Detected At" value={incident.time} />

            <tr>
              <td style={labelStyle}>Recommendation</td>

              <td style={valueStyle}>{incident.recommendation}</td>
            </tr>
          </tbody>
        </table>

        <div
          style={{
            display: "flex",
            gap: "15px",
            marginTop: "30px",
          }}
        >
          <button style={dangerButton}>
            Block IP
          </button>

          <button style={warningButton}>
            Investigate
          </button>

          <button style={primaryButton}>
            Generate Report
          </button>
        </div>
      </div>
    </div>
  );
}

type RowProps = {
  label: string;
  value: string | number;
};

function TableRow({ label, value }: RowProps) {
  return (
    <tr>
      <td style={labelStyle}>{label}</td>
      <td style={valueStyle}>{value}</td>
    </tr>
  );
}

const labelStyle = {
  padding: "15px",
  width: "220px",
  color: "#94a3b8",
  borderBottom: "1px solid #334155",
};

const valueStyle = {
  padding: "15px",
  borderBottom: "1px solid #334155",
};

const primaryButton = {
  background: "#3b82f6",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};

const warningButton = {
  background: "#f59e0b",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};

const dangerButton = {
  background: "#ef4444",
  color: "white",
  border: "none",
  padding: "10px 18px",
  borderRadius: "8px",
  cursor: "pointer",
};