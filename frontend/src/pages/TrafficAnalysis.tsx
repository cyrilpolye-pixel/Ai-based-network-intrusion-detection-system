import { useEffect, useState } from "react";

type ProtocolData = {
  name: string;
  value: number;
};

type TopIP = {
  ip: string;
  requests: number;
};

const TrafficAnalysis = () => {
  const [protocols, setProtocols] = useState<ProtocolData[]>([]);
  const [topIPs, setTopIPs] = useState<TopIP[]>([]);

  useEffect(() => {
    // fake protocol distribution
    setProtocols([
      { name: "HTTP", value: Math.floor(Math.random() * 100) },
      { name: "TCP", value: Math.floor(Math.random() * 100) },
      { name: "UDP", value: Math.floor(Math.random() * 100) },
      { name: "ICMP", value: Math.floor(Math.random() * 100) },
    ]);

    // fake top IPs
    const ips = Array.from({ length: 5 }).map(() => ({
      ip: `192.168.0.${Math.floor(Math.random() * 255)}`,
      requests: Math.floor(Math.random() * 500),
    }));

    setTopIPs(ips);
  }, []);

  return (
    <div style={{ padding: "20px" }}>
      <h1>Traffic Analysis</h1>

      {/* Summary Cards */}
      <div style={{ display: "flex", gap: "20px", marginBottom: "20px" }}>
        <Card title="Total Packets" value={Math.floor(Math.random() * 5000)} />
        <Card title="Bandwidth Usage" value={`${Math.floor(Math.random() * 100)} Mbps`} />
        <Card title="Anomalies Detected" value={Math.floor(Math.random() * 20)} />
      </div>

      {/* Protocol Distribution */}
      <div style={sectionStyle}>
        <h2>Protocol Distribution</h2>

        {protocols.map((p) => (
          <div key={p.name} style={{ marginBottom: "10px" }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>{p.name}</span>
              <span>{p.value}%</span>
            </div>

            <div style={barContainer}>
              <div style={{ ...barFill, width: `${p.value}%` }} />
            </div>
          </div>
        ))}
      </div>

      {/* Top IPs */}
      <div style={sectionStyle}>
        <h2>Top Source IPs</h2>

        <table style={{ width: "100%" }}>
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Requests</th>
            </tr>
          </thead>

          <tbody>
            {topIPs.map((ip, index) => (
              <tr key={index}>
                <td>{ip.ip}</td>
                <td>{ip.requests}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const Card = ({ title, value }: { title: string; value: string | number }) => (
  <div
    style={{
      flex: 1,
      background: "#222",
      color: "#fff",
      padding: "15px",
      borderRadius: "10px",
      textAlign: "center",
    }}
  >
    <h3>{title}</h3>
    <p style={{ fontSize: "20px", fontWeight: "bold" }}>{value}</p>
  </div>
);

const sectionStyle = {
  background: "#111",
  color: "#fff",
  padding: "15px",
  borderRadius: "10px",
  marginBottom: "20px",
};

const barContainer = {
  width: "100%",
  height: "10px",
  background: "#333",
  borderRadius: "5px",
};

const barFill = {
  height: "100%",
  background: "cyan",
  borderRadius: "5px",
};

export default TrafficAnalysis;