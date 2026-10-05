import { useEffect, useState } from "react";
import socket from "../services/socket";
import "./LiveMonitoring.css";

type TrafficLog = {
  id: string;
  source: string;
  destination: string;
  protocol: string;
  status: "Normal" | "Suspicious";
  attackType: string;
  time: string;
};

const LiveMonitoring = () => {
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const handleConnect = () => {
      console.log("🔌 Connected to Live Monitoring");
      setConnected(true);
    };

    const handleDisconnect = () => {
      console.log("🔌 Disconnected from Live Monitoring");
      setConnected(false);
    };

    const handleTrafficUpdate = (data: any) => {
      const prediction = String(
        data.prediction || data.label || ""
      ).toLowerCase();

      const isSuspicious =
        data.is_attack === true ||
        (
          prediction !== "" &&
          prediction !== "normal" &&
          prediction !== "benign" &&
          prediction !== "unknown" &&
          prediction !== "pending"
        );

      const newLog: TrafficLog = {
        id:
          data._id ||
          `${Date.now()}-${Math.random()}`,

        source:
          data.source_ip ||
          data.srcIP ||
          data.src_ip ||
          "-",

        destination:
          data.target_ip ||
          data.dstIP ||
          data.dst_ip ||
          "-",

        protocol:
          data.protocol ||
          "-",

        status: isSuspicious
          ? "Suspicious"
          : "Normal",

        attackType: isSuspicious
          ? data.prediction ||
            data.label ||
            data.attack_type ||
            "Unknown"
          : "BENIGN",

        time: data.timestamp
          ? new Date(data.timestamp).toLocaleTimeString()
          : new Date().toLocaleTimeString(),
      };

      setLogs((previous) => [
        newLog,
        ...previous.slice(0, 9),
      ]);
    };

    socket.on("connect", handleConnect);
    socket.on("disconnect", handleDisconnect);

    // Dedicated live-monitoring event.
    socket.on(
      "live-traffic",
      handleTrafficUpdate
    );

    // If Socket.IO was already connected before
    // this page mounted, update the UI immediately.
    if (socket.connected) {
      setConnected(true);
    }

    return () => {
      socket.off("connect", handleConnect);
      socket.off("disconnect", handleDisconnect);
      socket.off(
        "live-traffic",
        handleTrafficUpdate
      );
    };
  }, []);

  const suspiciousCount = logs.filter(
    (log) => log.status === "Suspicious"
  ).length;

  const threatLevel =
    suspiciousCount >= 5
      ? "High"
      : suspiciousCount >= 2
      ? "Medium"
      : "Low";

  return (
    <div className="live-page">
      <div className="live-header">
        <div>
          <h1>Live Monitoring</h1>
          <p>Real-time network traffic monitoring</p>
        </div>

        <div
          className={`connection-status ${
            connected ? "online" : "offline"
          }`}
        >
          <span className="status-dot" />
          {connected ? "Connected" : "Disconnected"}
        </div>
      </div>

      <div className="live-cards">
        <div className="live-card">
          <h3>Live Connections</h3>
          <strong>
            {connected ? logs.length : 0}
          </strong>
        </div>

        <div className="live-card">
          <h3>Threat Level</h3>

          <strong
            className={`threat-${threatLevel.toLowerCase()}`}
          >
            {threatLevel}
          </strong>
        </div>

        <div className="live-card">
          <h3>Suspicious Events</h3>
          <strong>{suspiciousCount}</strong>
        </div>
      </div>

      <div className="live-section">
        <h2>Live Traffic</h2>

        {!connected ? (
          <div className="live-empty">
            Waiting for Socket.IO connection...
          </div>
        ) : logs.length === 0 ? (
          <div className="live-empty">
            Connected. Waiting for traffic events...
          </div>
        ) : (
          <div className="live-table-wrapper">
            <table className="live-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Attack Type</th>
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
                    <td>{log.attackType}</td>

                    <td>
                      <span
                        className={`traffic-status ${
                          log.status === "Suspicious"
                            ? "suspicious"
                            : "normal"
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default LiveMonitoring;
