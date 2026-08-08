import { useEffect, useMemo, useState } from "react";
import api from "../services/api";
import "./TrafficAnalysis.css";

type TrafficLog = {
  _id: string;
  timestamp?: string;
  srcIP: string;
  dstIP: string;
  protocol: string;
  srcPort?: number;
  dstPort?: number;
  duration?: number;
  bytes?: number;
  packets?: number;
  label?: string;
  prediction?: string;
  confidence?: number;
};

export default function TrafficAnalysis() {
  const [traffic, setTraffic] = useState<TrafficLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchTraffic = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get("/traffic");

      setTraffic(response.data.traffic || []);
    } catch (err: any) {
      console.error("Failed to load traffic:", err);

      setError(
        err.response?.data?.message ||
          "Unable to load traffic data."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTraffic();
  }, []);

  /*
   * Protocol distribution
   */
  const protocols = useMemo(() => {
    const counts: Record<string, number> = {};

    traffic.forEach((item) => {
      const protocol = item.protocol?.toUpperCase() || "UNKNOWN";

      counts[protocol] = (counts[protocol] || 0) + 1;
    });

    const total = traffic.length;

    return Object.entries(counts)
      .map(([name, count]) => ({
        name,
        value: total > 0 ? Math.round((count / total) * 100) : 0,
      }))
      .sort((a, b) => b.value - a.value);
  }, [traffic]);

  /*
   * Top source IPs
   */
  const topIPs = useMemo(() => {
    const counts: Record<string, number> = {};

    traffic.forEach((item) => {
      counts[item.srcIP] = (counts[item.srcIP] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([ip, requests]) => ({
        ip,
        requests,
      }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 5);
  }, [traffic]);

  /*
   * Summary statistics
   */
  const totalPackets = useMemo(() => {
    return traffic.reduce(
      (total, item) => total + (item.packets || 0),
      0
    );
  }, [traffic]);

  const totalBytes = useMemo(() => {
    return traffic.reduce(
      (total, item) => total + (item.bytes || 0),
      0
    );
  }, [traffic]);

  const anomalies = useMemo(() => {
    return traffic.filter(
      (item) =>
        item.prediction?.toLowerCase() === "attack" ||
        item.label?.toLowerCase() === "attack" ||
        item.label?.toLowerCase() === "anomaly"
    ).length;
  }, [traffic]);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";

    const units = ["B", "KB", "MB", "GB"];
    const index = Math.floor(
      Math.log(bytes) / Math.log(1024)
    );

    return `${(bytes / Math.pow(1024, index)).toFixed(2)} ${
      units[index] || "GB"
    }`;
  };

  return (
    <div className="traffic-page">
      <div className="traffic-header">
        <h1>Traffic Analysis</h1>

        <button
          className="traffic-refresh-button"
          onClick={fetchTraffic}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="traffic-error">
          {error}
        </div>
      )}

      {/* Summary Cards */}
      <div className="traffic-summary">
        <div className="traffic-card">
          <h3>Total Packets</h3>
          <strong>
            {loading ? "..." : totalPackets.toLocaleString()}
          </strong>
        </div>

        <div className="traffic-card">
          <h3>Total Data</h3>
          <strong>
            {loading ? "..." : formatBytes(totalBytes)}
          </strong>
        </div>

        <div className="traffic-card">
          <h3>Traffic Records</h3>
          <strong>
            {loading ? "..." : traffic.length.toLocaleString()}
          </strong>
        </div>

        <div className="traffic-card">
          <h3>Anomalies Detected</h3>
          <strong>
            {loading ? "..." : anomalies.toLocaleString()}
          </strong>
        </div>
      </div>

      {/* Protocol Distribution */}
      <section className="traffic-section">
        <h2>Protocol Distribution</h2>

        {loading ? (
          <p className="traffic-empty">
            Loading protocol data...
          </p>
        ) : protocols.length === 0 ? (
          <p className="traffic-empty">
            No traffic data available.
          </p>
        ) : (
          protocols.map((protocol) => (
            <div
              className="protocol-row"
              key={protocol.name}
            >
              <div className="protocol-label">
                <span>{protocol.name}</span>
                <span>{protocol.value}%</span>
              </div>

              <div className="protocol-bar">
                <div
                  className="protocol-fill"
                  style={{
                    width: `${protocol.value}%`,
                  }}
                />
              </div>
            </div>
          ))
        )}
      </section>

      {/* Top Source IPs */}
      <section className="traffic-section">
        <h2>Top Source IPs</h2>

        {loading ? (
          <p className="traffic-empty">
            Loading source IP data...
          </p>
        ) : topIPs.length === 0 ? (
          <p className="traffic-empty">
            No source IP data available.
          </p>
        ) : (
          <table className="traffic-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Traffic Records</th>
              </tr>
            </thead>

            <tbody>
              {topIPs.map((item) => (
                <tr key={item.ip}>
                  <td>{item.ip}</td>
                  <td>{item.requests}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Recent Traffic */}
      <section className="traffic-section">
        <h2>Recent Traffic</h2>

        {loading ? (
          <p className="traffic-empty">
            Loading traffic...
          </p>
        ) : traffic.length === 0 ? (
          <p className="traffic-empty">
            No traffic records found.
          </p>
        ) : (
          <div className="traffic-table-wrapper">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Prediction</th>
                </tr>
              </thead>

              <tbody>
                {traffic.slice(0, 10).map((item) => (
                  <tr key={item._id}>
                    <td>
                      {item.timestamp
                        ? new Date(
                            item.timestamp
                          ).toLocaleTimeString()
                        : "-"}
                    </td>

                    <td>{item.srcIP}</td>

                    <td>{item.dstIP}</td>

                    <td>{item.protocol}</td>

                    <td>
                      {(item.packets || 0).toLocaleString()}
                    </td>

                    <td>
                      {formatBytes(item.bytes || 0)}
                    </td>

                    <td>{item.prediction || "Pending"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
