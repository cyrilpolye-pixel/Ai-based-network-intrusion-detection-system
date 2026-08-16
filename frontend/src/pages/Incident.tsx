import { useState } from "react";
import "./Incident.css";

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

  return (
    <div className="incident-page">
      <h1 className="incident-title">Incident Details</h1>

      <div className="incident-card">
        <table className="incident-table">
          <tbody>
            <TableRow label="Attack Type" value={incident.attack} />
            <TableRow label="Source IP" value={incident.sourceIP} />
            <TableRow label="Destination IP" value={incident.destinationIP} />
            <TableRow label="Protocol" value={incident.protocol} />

            <tr>
              <td className="incident-label">Severity</td>
              <td className={`incident-value incident-severity-${incident.severity.toLowerCase()}`}>
                {incident.severity}
              </td>
            </tr>

            <tr>
              <td className="incident-label">Status</td>
              <td className={`incident-value incident-status-${incident.status.toLowerCase()}`}>
                {incident.status}
              </td>
            </tr>

            <TableRow
              label="Packet Count"
              value={incident.packetCount.toLocaleString()}
            />
            <TableRow label="Detected At" value={incident.time} />

            <tr>
              <td className="incident-label">Recommendation</td>
              <td className="incident-value">{incident.recommendation}</td>
            </tr>
          </tbody>
        </table>

        <div className="incident-actions">
          <button className="incident-button incident-button-danger">Block IP</button>
          <button className="incident-button incident-button-warning">Investigate</button>
          <button className="incident-button incident-button-primary">Generate Report</button>
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
      <td className="incident-label">{label}</td>
      <td className="incident-value">{value}</td>
    </tr>
  );
}
