import { useEffect, useState } from "react";

type TrafficLog = {
  id: number;
  source: string;
  destination: string;
  protocol: string;
  status: "Normal" | "Suspicious";
  time: string;
};

const LiveMonitoring = () => {
  const [logs, setLogs] = useState<TrafficLog[]>([]);

  // fake live data generator
  useEffect(() => {
    const interval = setInterval(() => {
      const newLog: TrafficLog = {
        id: Date.now(),
        source: `192.168.1.${Math.floor(Math.random() * 255)}`,
        destination: `10.0.0.${Math.floor(Math.random() * 255)}`,
        protocol: ["HTTP", "TCP", "UDP"][Math.floor(Math.random() * 3)],
        status: Math.random() > 0.8 ? "Suspicious" : "Normal",
        time: new Date().toLocaleTimeString(),
      };

      setLogs((prev) => [newLog, ...prev.slice(0, 9)]);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: "20px" }}>
      <h1>Live Monitoring</h1>

      {/* Status Cards */}
      <div style={{ display: "flex", gap: "20px", marginBottom: "20px" }}>
        <div style={cardStyle}>
          <h3>Active Connections</h3>
          <p>{Math.floor(Math.random() * 500)}</p>
        </div>

        <div style={cardStyle}>
          <h3>Threat Level</h3>
          <p style={{ color: "red" }}>Medium</p>
        </div>

        <div style={cardStyle}>
          <h3>Packets/sec</h3>
          <p>{Math.floor(Math.random() * 1000)}</p>
        </div>
      </div>

      {/* Live Logs Table */}
      <div style={{ background: "#111", padding: "15px", borderRadius: "10px" }}>
        <h2 style={{ color: "#fff" }}>Live Traffic</h2>

        <table style={{ width: "100%", color: "#fff", marginTop: "10px" }}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td>{log.time}</td>
                <td>{log.source}</td>
                <td>{log.destination}</td>
                <td>{log.protocol}</td>
                <td
                  style={{
                    color: log.status === "Suspicious" ? "red" : "lightgreen",
                    fontWeight: "bold",
                  }}
                >
                  {log.status}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const cardStyle = {
  flex: 1,
  background: "#222",
  color: "#fff",
  padding: "15px",
  borderRadius: "10px",
  textAlign: "center" as const,
};

export default LiveMonitoring;