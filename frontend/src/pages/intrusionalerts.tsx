import { useState } from "react";

type Alert = {
  id: number;
  time: string;
  type: string;
  source: string;
  severity: "High" | "Medium" | "Low";
};

const IntrusionAlerts = () => {
  const [alerts] = useState<Alert[]>([
    {
      id: 1,
      time: "10:30 AM",
      type: "DDoS Attack",
      source: "192.168.1.5",
      severity: "High",
    },
    {
      id: 2,
      time: "11:10 AM",
      type: "Port Scan",
      source: "192.168.1.8",
      severity: "Medium",
    },
    {
      id: 3,
      time: "11:45 AM",
      type: "Brute Force",
      source: "192.168.1.12",
      severity: "Low",
    },
  ]);

  return (
    <div style={{ padding: "20px", color: "white" }}>
      <h2>Intrusion Alerts</h2>

      <table width="100%" border={1} cellPadding={10}>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Source</th>
            <th>Severity</th>
          </tr>
        </thead>

        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td>{alert.time}</td>
              <td>{alert.type}</td>
              <td>{alert.source}</td>

              <td
                style={{
                  color:
                    alert.severity === "High"
                      ? "red"
                      : alert.severity === "Medium"
                      ? "orange"
                      : "lightgreen",
                  fontWeight: "bold",
                }}
              >
                {alert.severity}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default IntrusionAlerts;