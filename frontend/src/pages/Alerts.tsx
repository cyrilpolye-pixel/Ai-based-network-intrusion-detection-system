import { useEffect, useState } from "react";
import api from "../services/api";
import "./Alerts.css";

type Alert = {
  _id: string;
  timestamp?: string;
  attackType?: string;
  srcIP?: string;
  severity?: "Critical" | "High" | "Medium" | "Low";
  status?: "Blocked" | "Investigating" | "Detected";
};

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get("/alerts");

      setAlerts(response.data.alerts || []);
    } catch (err: any) {
      console.error("Failed to load alerts:", err);

      setError(
        err.response?.data?.message ||
          "Unable to load intrusion alerts."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
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

  const getStatusColor = (status?: string) => {
    switch (status) {
      case "Blocked":
        return "#22c55e";
      case "Investigating":
        return "#f59e0b";
      default:
        return "#60a5fa";
    }
  };

  const formatTime = (timestamp?: string) => {
    if (!timestamp) return "-";

    return new Date(timestamp).toLocaleTimeString();
  };

  return (
    <div className="alerts-page">
      <h1 className="alerts-title">
        Intrusion Alerts
      </h1>

      {error && (
        <div className="alerts-error">
          {error}
        </div>
      )}

      <div className="alerts-table-container">
        {loading ? (
          <div className="alerts-message">
            Loading intrusion alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div className="alerts-message">
            No intrusion alerts found.
          </div>
        ) : (
          <table className="alerts-table">
            <thead>
              <tr>
                <th className="alerts-header">Time</th>
                <th className="alerts-header">Attack Type</th>
                <th className="alerts-header">Source IP</th>
                <th className="alerts-header">Severity</th>
                <th className="alerts-header">Status</th>
              </tr>
            </thead>

            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert._id}
                  className="alerts-row"
                >
                  <td className="alerts-cell">
                    {formatTime(alert.timestamp)}
                  </td>

                  <td className="alerts-cell">
                    {alert.attackType || "-"}
                  </td>

                  <td className="alerts-cell">
                    {alert.srcIP || "-"}
                  </td>

                  <td
                    className="alerts-cell alert-severity"
                    style={{
                      color: getSeverityColor(
                        alert.severity
                      ),
                    }}
                  >
                    {alert.severity || "-"}
                  </td>

                  <td
                    className="alerts-cell alert-status"
                    style={{
                      color: getStatusColor(
                        alert.status
                      ),
                    }}
                  >
                    {alert.status || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="alerts-actions">
        <button
          className="primary-button"
          onClick={fetchAlerts}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh Alerts"}
        </button>

        <button
          className="secondary-button"
          onClick={() => {
            console.log("Export Alerts will be implemented next.");
          }}
        >
          Export Alerts
        </button>
      </div>
    </div>
  );
}