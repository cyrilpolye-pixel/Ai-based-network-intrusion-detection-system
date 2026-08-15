import { useEffect, useState } from "react";
import api from "../services/api";
import "./Reports.css";

type Alert = {
  _id: string;
  attackType?: string;
  severity?: string;
  status?: string;
  createdAt?: string;
};

type Traffic = {
  _id: string;
  prediction?: string;
  confidence?: number;
  createdAt?: string;
};

export default function Reports() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [traffic, setTraffic] = useState<Traffic[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadReports = async () => {
    try {
      setLoading(true);
      setError("");

      const [alertsResponse, trafficResponse] =
        await Promise.all([
          api.get("/alerts"),
          api.get("/traffic"),
        ]);

      setAlerts(alertsResponse.data.alerts || []);
      setTraffic(trafficResponse.data.traffic || []);
    } catch (err: any) {
      console.error("Reports loading error:", err);

      setError(
        err.response?.data?.message ||
          "Unable to load report data."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const generatedReports = alerts.length > 0 ? 1 : 0;

  const attackTraffic = traffic.filter(
    (item) =>
      item.prediction &&
      item.prediction.toUpperCase() !== "BENIGN"
  ).length;

  const normalTraffic = traffic.filter(
    (item) =>
      item.prediction?.toUpperCase() === "BENIGN"
  ).length;

  const criticalAlerts = alerts.filter(
    (alert) =>
      alert.severity === "Critical"
  ).length;

  const formatDate = (date?: string) => {
    if (!date) {
      return "-";
    }

    return new Date(date).toLocaleString();
  };

  return (
    <div className="reports-page">

      {/* Header */}
      <div className="reports-header">

        <div>
          <h1>Reports</h1>

          <p>
            Network security and intrusion detection
            reports.
          </p>
        </div>

        <button
          className="reports-refresh-button"
          onClick={loadReports}
          disabled={loading}
        >
          {loading
            ? "Refreshing..."
            : "Refresh"}
        </button>

      </div>

      {error && (
        <div className="reports-error">
          {error}
        </div>
      )}

      {/* Summary */}
      <div className="reports-summary">

        <div className="reports-card">
          <span>Traffic Records</span>

          <strong>
            {loading
              ? "..."
              : traffic.length}
          </strong>
        </div>

        <div className="reports-card">
          <span>Attacks Detected</span>

          <strong>
            {loading
              ? "..."
              : attackTraffic}
          </strong>
        </div>

        <div className="reports-card">
          <span>Normal Traffic</span>

          <strong>
            {loading
              ? "..."
              : normalTraffic}
          </strong>
        </div>

        <div className="reports-card">
          <span>Critical Alerts</span>

          <strong>
            {loading
              ? "..."
              : criticalAlerts}
          </strong>
        </div>

      </div>

      {/* Security Report */}
      <div className="reports-panel">

        <div className="reports-panel-header">

          <div>
            <h2>
              Security Analysis Report
            </h2>

            <p>
              Current system analysis based on
              recorded network traffic.
            </p>
          </div>

          <span className="reports-generated">
            {generatedReports > 0
              ? "Available"
              : "No Data"}
          </span>

        </div>

        {loading ? (
          <div className="reports-empty">
            Loading report data...
          </div>
        ) : traffic.length === 0 ? (
          <div className="reports-empty">
            No traffic data is available to
            generate a report.
          </div>
        ) : (
          <div className="report-analysis">

            <div className="analysis-row">
              <span>Total Traffic</span>
              <strong>
                {traffic.length}
              </strong>
            </div>

            <div className="analysis-row">
              <span>Normal Traffic</span>
              <strong>
                {normalTraffic}
              </strong>
            </div>

            <div className="analysis-row">
              <span>Attacks Detected</span>
              <strong className="analysis-danger">
                {attackTraffic}
              </strong>
            </div>

            <div className="analysis-row">
              <span>Critical Alerts</span>
              <strong className="analysis-danger">
                {criticalAlerts}
              </strong>
            </div>

            <div className="analysis-row">
              <span>Total Alerts</span>
              <strong>
                {alerts.length}
              </strong>
            </div>

          </div>
        )}

      </div>

      {/* Verified Attacks */}
      <div className="reports-panel">

        <div className="reports-panel-header">

          <div>
            <h2>
              Verified Attack Records
            </h2>

            <p>
              Attacks detected by the AI-NIDS
              prediction pipeline.
            </p>
          </div>

        </div>

        {loading ? (
          <div className="reports-empty">
            Loading attack records...
          </div>
        ) : alerts.length === 0 ? (
          <div className="reports-empty">
            No verified attacks found.
          </div>
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

                {alerts.map((alert) => (
                  <tr key={alert._id}>

                    <td>
                      {formatDate(
                        alert.createdAt
                      )}
                    </td>

                    <td className="report-attack">
                      {alert.attackType ||
                        "Unknown"}
                    </td>

                    <td>
                      <span
                        className={`report-badge report-severity-${(
                          alert.severity ||
                          "Low"
                        ).toLowerCase()}`}
                      >
                        {alert.severity ||
                          "Low"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`report-badge report-status-${(
                          alert.status ||
                          "Unread"
                        ).toLowerCase()}`}
                      >
                        {alert.status ||
                          "Unread"}
                      </span>
                    </td>

                  </tr>
                ))}

              </tbody>

            </table>

          </div>
        )}

      </div>

      {/* Actions */}
      <div className="reports-actions">

        <button
          className="reports-primary-button"
          onClick={loadReports}
        >
          Generate Current Report
        </button>

        <button
          className="reports-secondary-button"
          onClick={() =>
            window.print()
          }
        >
          Export / Print
        </button>

      </div>

    </div>
  );
}