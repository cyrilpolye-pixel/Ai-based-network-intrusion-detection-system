import { useEffect, useMemo, useState } from "react";
import api from "../services/api";
import "./TrafficAnalysis.css";

type TrafficLog = {
  _id: string;
  timestamp?: string;
  createdAt?: string;
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

type TrafficResponse = {
  success?: boolean;
  count?: number;
  traffic?: TrafficLog[];
  message?: string;
};

type ApiError = {
  response?: {
    data?: {
      message?: string;
    };
  };
  message?: string;
};

const NORMAL_PREDICTIONS = new Set(["BENIGN", "NORMAL"]);

const formatValue = (value?: string | number) => {
  if (value === undefined || value === null || value === "") {
    return "-";
  }

  return value;
};

const formatNumber = (value?: number) => {
  if (value === undefined || value === null || Number.isNaN(value)) {
    return "-";
  }

  return value.toLocaleString();
};

const getTrafficDate = (item: TrafficLog) => item.timestamp || item.createdAt;

const getPrediction = (item: TrafficLog) => item.prediction || item.label || "Pending";

const isNormalTraffic = (prediction?: string) => {
  if (!prediction) {
    return false;
  }

  return NORMAL_PREDICTIONS.has(prediction.trim().toUpperCase());
};

export default function TrafficAnalysis() {
  const [traffic, setTraffic] = useState<TrafficLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchTraffic = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get<TrafficResponse>("/traffic");
      const records = response.data.traffic;

      if (!Array.isArray(records)) {
        throw new Error("Traffic API returned an unexpected response.");
      }

      setTraffic(records);
    } catch (err: unknown) {
      console.error("Failed to load traffic:", err);

      const apiError = err as ApiError;
      const message =
        apiError.response?.data?.message ||
        apiError.message ||
        "Unable to load traffic data.";

      setError(message);
      setTraffic([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTraffic();
  }, []);

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
        count,
        value: total > 0 ? Math.round((count / total) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count);
  }, [traffic]);

  const topIPs = useMemo(() => {
    const counts: Record<string, number> = {};

    traffic.forEach((item) => {
      const ip = item.srcIP || "Unknown";
      counts[ip] = (counts[ip] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([ip, requests]) => ({ ip, requests }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 5);
  }, [traffic]);

  const totalPackets = useMemo(() => {
    return traffic.reduce((total, item) => total + (item.packets || 0), 0);
  }, [traffic]);

  const totalBytes = useMemo(() => {
    return traffic.reduce((total, item) => total + (item.bytes || 0), 0);
  }, [traffic]);

  const attacks = useMemo(() => {
    return traffic.filter((item) => {
      const prediction = getPrediction(item);
      return prediction !== "Pending" && !isNormalTraffic(prediction);
    }).length;
  }, [traffic]);

  const normalTraffic = useMemo(() => {
    return traffic.filter((item) => isNormalTraffic(getPrediction(item))).length;
  }, [traffic]);

  const formatBytes = (bytes?: number) => {
    if (!bytes || bytes <= 0) {
      return "0 B";
    }

    const units = ["B", "KB", "MB", "GB"];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);

    return `${(bytes / Math.pow(1024, index)).toFixed(2)} ${units[index]}`;
  };

  const formatDuration = (duration?: number) => {
    if (duration === undefined || duration === null || Number.isNaN(duration)) {
      return "-";
    }

    if (duration >= 1000) {
      return `${(duration / 1000).toFixed(2)}s`;
    }

    return `${duration}ms`;
  };

  const formatConfidence = (confidence?: number) => {
    if (confidence === undefined || confidence === null || Number.isNaN(confidence)) {
      return "-";
    }

    const percentage = confidence <= 1 ? confidence * 100 : confidence;
    return `${percentage.toFixed(2)}%`;
  };

  const getPredictionClass = (prediction?: string) => {
    if (!prediction || prediction === "Pending") {
      return "traffic-pending";
    }

    return isNormalTraffic(prediction) ? "traffic-benign" : "traffic-attack";
  };

  return (
    <div className="traffic-page">
      <div className="traffic-header">
        <div>
          <h1>Traffic Analysis</h1>
          <p>Monitor real backend traffic records and detected anomalies.</p>
        </div>

        <button className="traffic-refresh-button" onClick={fetchTraffic} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && <div className="traffic-error">{error}</div>}

      <div className="traffic-summary">
        <div className="traffic-card">
          <h3>Total Packets</h3>
          <strong>{loading ? "..." : totalPackets.toLocaleString()}</strong>
        </div>

        <div className="traffic-card">
          <h3>Total Data</h3>
          <strong>{loading ? "..." : formatBytes(totalBytes)}</strong>
        </div>

        <div className="traffic-card">
          <h3>Traffic Records</h3>
          <strong>{loading ? "..." : traffic.length.toLocaleString()}</strong>
        </div>

        <div className="traffic-card">
          <h3>Normal / Attacks</h3>
          <strong>{loading ? "..." : `${normalTraffic.toLocaleString()} / ${attacks.toLocaleString()}`}</strong>
        </div>
      </div>

      <section className="traffic-section">
        <div className="traffic-section-header">
          <div>
            <h2>Protocol Distribution</h2>
            <p>Distribution of protocols in recorded traffic.</p>
          </div>
        </div>

        {loading ? (
          <p className="traffic-empty">Loading protocol data...</p>
        ) : protocols.length === 0 ? (
          <p className="traffic-empty">No traffic data available.</p>
        ) : (
          <div className="protocol-list">
            {protocols.map((protocol) => (
              <div className="protocol-row" key={protocol.name}>
                <div className="protocol-label">
                  <span>{protocol.name}</span>
                  <span>
                    {protocol.count.toLocaleString()} records ({protocol.value}%)
                  </span>
                </div>

                <div className="protocol-bar">
                  <div className="protocol-fill" style={{ width: `${protocol.value}%` }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="traffic-section">
        <div className="traffic-section-header">
          <div>
            <h2>Top Source IPs</h2>
            <p>Sources with the highest number of traffic records.</p>
          </div>
        </div>

        {loading ? (
          <p className="traffic-empty">Loading source IP data...</p>
        ) : topIPs.length === 0 ? (
          <p className="traffic-empty">No source IP data available.</p>
        ) : (
          <div className="traffic-table-wrapper">
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
                    <td>{item.requests.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="traffic-section">
        <div className="traffic-section-header">
          <div>
            <h2>Recent Traffic</h2>
            <p>Latest TrafficLog records returned by the backend.</p>
          </div>
        </div>

        {loading ? (
          <p className="traffic-empty">Loading traffic...</p>
        ) : traffic.length === 0 ? (
          <p className="traffic-empty">No traffic records found.</p>
        ) : (
          <div className="traffic-table-wrapper">
            <table className="traffic-table traffic-table-wide">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Source Port</th>
                  <th>Destination IP</th>
                  <th>Destination Port</th>
                  <th>Protocol</th>
                  <th>Duration</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Label</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                </tr>
              </thead>

              <tbody>
                {traffic.slice(0, 10).map((item) => {
                  const prediction = getPrediction(item);
                  const date = getTrafficDate(item);

                  return (
                    <tr key={item._id}>
                      <td>{date ? new Date(date).toLocaleString() : "-"}</td>
                      <td>{formatValue(item.srcIP)}</td>
                      <td>{formatNumber(item.srcPort)}</td>
                      <td>{formatValue(item.dstIP)}</td>
                      <td>{formatNumber(item.dstPort)}</td>
                      <td>{formatValue(item.protocol)}</td>
                      <td>{formatDuration(item.duration)}</td>
                      <td>{formatNumber(item.packets)}</td>
                      <td>{formatBytes(item.bytes)}</td>
                      <td>{formatValue(item.label)}</td>
                      <td>
                        <span className={`traffic-prediction ${getPredictionClass(prediction)}`}>
                          {isNormalTraffic(prediction) ? "BENIGN / Normal" : prediction}
                        </span>
                      </td>
                      <td>{formatConfidence(item.confidence)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
