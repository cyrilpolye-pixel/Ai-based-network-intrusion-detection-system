import { useEffect, useMemo, useState } from "react";
import api from "../services/api";
import "./Reports.css";

type AlertStatus = "Unread" | "Read" | "Resolved";
type AlertSeverity = "Low" | "Medium" | "High" | "Critical";

type TrafficLog = {
  _id: string;
  timestamp?: string;
  createdAt?: string;
  srcIP?: string;
  dstIP?: string;
  protocol?: string;
  label?: string;
  prediction?: string;
  confidence?: number;
};

type Alert = {
  _id: string;
  trafficLogId?: string | TrafficLog;
  attackType?: string;
  severity?: AlertSeverity;
  status?: AlertStatus;
  time?: string;
  createdAt?: string;
};

type AlertsResponse = {
  alerts?: Alert[];
  message?: string;
};

type TrafficResponse = {
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

type ProtocolSummary = {
  name: string;
  count: number;
  percentage: number;
};

const NORMAL_PREDICTIONS = new Set(["BENIGN", "NORMAL"]);
const RECENT_RECORD_LIMIT = 5;

const getPrediction = (item: TrafficLog) => item.prediction || item.label || "Pending";

const isNormalTraffic = (prediction?: string) => {
  if (!prediction) {
    return false;
  }

  return NORMAL_PREDICTIONS.has(prediction.trim().toUpperCase());
};

const isAttackTraffic = (item: TrafficLog) => {
  const prediction = getPrediction(item);

  return prediction !== "Pending" && !isNormalTraffic(prediction);
};

const getTrafficDate = (item: TrafficLog) => item.timestamp || item.createdAt;
const getAlertDate = (alert: Alert) => alert.time || alert.createdAt;

const formatDate = (date?: string) => {
  if (!date) {
    return "-";
  }

  const parsedDate = new Date(date);

  if (Number.isNaN(parsedDate.getTime())) {
    return "-";
  }

  return parsedDate.toLocaleString();
};

const formatConfidence = (confidence?: number) => {
  if (confidence === undefined || confidence === null || Number.isNaN(confidence)) {
    return "-";
  }

  const percentage = confidence <= 1 ? confidence * 100 : confidence;
  return `${percentage.toFixed(2)}%`;
};

export default function Reports() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [traffic, setTraffic] = useState<TrafficLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadReports = async () => {
    try {
      setLoading(true);
      setError("");

      const [alertsResponse, trafficResponse] = await Promise.all([
        api.get<AlertsResponse>("/alerts"),
        api.get<TrafficResponse>("/traffic"),
      ]);

      const alertRecords = alertsResponse.data.alerts;
      const trafficRecords = trafficResponse.data.traffic;

      if (!Array.isArray(alertRecords) || !Array.isArray(trafficRecords)) {
        throw new Error("Reports APIs returned an unexpected response.");
      }

      setAlerts(alertRecords);
      setTraffic(trafficRecords);
    } catch (err: unknown) {
      console.error("Reports loading error:", err);

      const apiError = err as ApiError;
      setError(apiError.response?.data?.message || apiError.message || "Unable to load report data.");
      setAlerts([]);
      setTraffic([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const attackTraffic = useMemo(() => traffic.filter(isAttackTraffic).length, [traffic]);

  const normalTraffic = useMemo(() => {
    return traffic.filter((item) => isNormalTraffic(getPrediction(item))).length;
  }, [traffic]);

  const totalAlerts = alerts.length;

  const criticalAlerts = useMemo(() => {
    return alerts.filter((alert) => alert.severity === "Critical").length;
  }, [alerts]);

  const protocolDistribution = useMemo<ProtocolSummary[]>(() => {
    const counts: Record<string, number> = {};

    traffic.forEach((item) => {
      const protocol = item.protocol?.trim().toUpperCase() || "UNKNOWN";
      counts[protocol] = (counts[protocol] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([name, count]) => ({
        name,
        count,
        percentage: traffic.length > 0 ? Math.round((count / traffic.length) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count);
  }, [traffic]);

  const recentAlerts = useMemo(() => alerts.slice(0, RECENT_RECORD_LIMIT), [alerts]);
  const recentTraffic = useMemo(() => traffic.slice(0, RECENT_RECORD_LIMIT), [traffic]);

  const hasReportData = traffic.length > 0 || alerts.length > 0;

  return (
    <div className="reports-page">
      <div className="reports-header">
        <div>
          <h1>Reports</h1>
          <p>Network security and intrusion detection reports from backend records.</p>
        </div>

        <button className="reports-refresh-button" onClick={loadReports} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && <div className="reports-error">{error}</div>}

      <div className="reports-summary">
        <div className="reports-card">
          <span>Traffic Records</span>
          <strong>{loading ? "..." : traffic.length.toLocaleString()}</strong>
        </div>

        <div className="reports-card">
          <span>Total Alerts</span>
          <strong>{loading ? "..." : totalAlerts.toLocaleString()}</strong>
        </div>

        <div className="reports-card">
          <span>Normal Traffic</span>
          <strong>{loading ? "..." : normalTraffic.toLocaleString()}</strong>
        </div>

        <div className="reports-card">
          <span>Detected Attacks</span>
          <strong>{loading ? "..." : attackTraffic.toLocaleString()}</strong>
        </div>
      </div>

      <div className="reports-panel">
        <div className="reports-panel-header">
          <div>
            <h2>Security Analysis Report</h2>
            <p>Current system analysis based on recorded traffic and alerts.</p>
          </div>

          <span className="reports-generated">{hasReportData ? "Available" : "No Data"}</span>
        </div>

        {loading ? (
          <div className="reports-empty">Loading report data...</div>
        ) : !hasReportData ? (
          <div className="reports-empty">No traffic or alert data is available to generate a report.</div>
        ) : (
          <div className="report-analysis">
            <div className="analysis-row">
              <span>Total Traffic</span>
              <strong>{traffic.length.toLocaleString()}</strong>
            </div>

            <div className="analysis-row">
              <span>Normal / Benign Traffic</span>
              <strong>{normalTraffic.toLocaleString()}</strong>
            </div>

            <div className="analysis-row">
              <span>Detected Attacks / Anomalies</span>
              <strong className="analysis-danger">{attackTraffic.toLocaleString()}</strong>
            </div>

            <div className="analysis-row">
              <span>Total Alerts</span>
              <strong>{totalAlerts.toLocaleString()}</strong>
            </div>

            <div className="analysis-row">
              <span>Critical Alerts</span>
              <strong className="analysis-danger">{criticalAlerts.toLocaleString()}</strong>
            </div>
          </div>
        )}
      </div>

      <div className="reports-panel">
        <div className="reports-panel-header">
          <div>
            <h2>Protocol Distribution</h2>
            <p>Protocol breakdown from TrafficLog records.</p>
          </div>
        </div>

        {loading ? (
          <div className="reports-empty">Loading protocol data...</div>
        ) : protocolDistribution.length === 0 ? (
          <div className="reports-empty">No protocol data available.</div>
        ) : (
          <div className="reports-protocol-list">
            {protocolDistribution.map((protocol) => (
              <div className="reports-protocol-row" key={protocol.name}>
                <div className="reports-protocol-label">
                  <span>{protocol.name}</span>
                  <span>
                    {protocol.count.toLocaleString()} records ({protocol.percentage}%)
                  </span>
                </div>

                <div className="reports-protocol-bar">
                  <div className="reports-protocol-fill" style={{ width: `${protocol.percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="reports-panel">
        <div className="reports-panel-header">
          <div>
            <h2>Recent Traffic Records</h2>
            <p>Latest backend traffic entries and AI-NIDS predictions.</p>
          </div>
        </div>

        {loading ? (
          <div className="reports-empty">Loading recent traffic...</div>
        ) : recentTraffic.length === 0 ? (
          <div className="reports-empty">No recent traffic found.</div>
        ) : (
          <div className="reports-table-wrapper">
            <table className="reports-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                </tr>
              </thead>

              <tbody>
                {recentTraffic.map((item) => {
                  const prediction = getPrediction(item);

                  return (
                    <tr key={item._id}>
                      <td>{formatDate(getTrafficDate(item))}</td>
                      <td>{item.srcIP || "-"}</td>
                      <td>{item.dstIP || "-"}</td>
                      <td>{item.protocol || "-"}</td>
                      <td className={isNormalTraffic(prediction) ? "report-normal" : "report-attack"}>{prediction}</td>
                      <td>{formatConfidence(item.confidence)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="reports-panel">
        <div className="reports-panel-header">
          <div>
            <h2>Recent Alert Records</h2>
            <p>Alerts generated from detected attack traffic.</p>
          </div>
        </div>

        {loading ? (
          <div className="reports-empty">Loading alert records...</div>
        ) : recentAlerts.length === 0 ? (
          <div className="reports-empty">No alert records found.</div>
        ) : (
          <div className="reports-table-wrapper">
            <table className="reports-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {recentAlerts.map((alert) => (
                  <tr key={alert._id}>
                    <td>{formatDate(getAlertDate(alert))}</td>
                    <td className="report-attack">{alert.attackType || "Unknown"}</td>
                    <td>
                      <span className={`report-badge report-severity-${(alert.severity || "Low").toLowerCase()}`}>
                        {alert.severity || "Low"}
                      </span>
                    </td>
                    <td>
                      <span className={`report-badge report-status-${(alert.status || "Unread").toLowerCase()}`}>
                        {alert.status || "Unread"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="reports-actions">
        <button className="reports-primary-button" onClick={loadReports} disabled={loading}>
          Generate Current Report
        </button>

        <button className="reports-secondary-button" onClick={() => window.print()}>
          Export / Print
        </button>
      </div>
    </div>
  );
}
