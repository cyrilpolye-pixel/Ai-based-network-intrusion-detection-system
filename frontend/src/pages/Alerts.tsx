import { useEffect, useState } from "react";
import api from "../services/api";
import socket from "../services/socket";
import "./Alerts.css";

type Alert = {
  _id: string;
  trafficLogId?: string | object;
  attackType: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: "Unread" | "Read" | "Resolved";
  time?: string;
  createdAt?: string;
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

    const handleNewAlert = (newAlert: Alert) => {
      setAlerts((previous) => {
        const alreadyExists = previous.some(
          (alert) => alert._id === newAlert._id
        );

        if (alreadyExists) {
          return previous;
        }

        return [newAlert, ...previous];
      });
    };

    socket.on("alert-created", handleNewAlert);

    return () => {
      socket.off("alert-created", handleNewAlert);
    };
  }, []);

  const updateStatus = async (
    id: string,
    status: "Unread" | "Read" | "Resolved"
  ) => {
    try {
      await api.put(`/alerts/${id}`, { status });

      setAlerts((previous) =>
        previous.map((alert) =>
          alert._id === id
            ? { ...alert, status }
            : alert
        )
      );
    } catch (err: any) {
      console.error("Failed to update alert:", err);

      setError(
        err.response?.data?.message ||
          "Unable to update alert status."
      );
    }
  };

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "severity-critical";

      case "High":
        return "severity-high";

      case "Medium":
        return "severity-medium";

      default:
        return "severity-low";
    }
  };

  const getStatusClass = (status: string) => {
    switch (status) {
      case "Resolved":
        return "status-resolved";

      case "Read":
        return "status-read";

      default:
        return "status-unread";
    }
  };

  return (
    <div className="alerts-page">
      <div className="alerts-header">
        <div>
          <h1>Intrusion Alerts</h1>

          <p>
            Monitor and manage detected security threats.
          </p>
        </div>

        <button
          className="alerts-refresh-button"
          onClick={fetchAlerts}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh Alerts"}
        </button>
      </div>

      {error && (
        <div className="alerts-error">
          {error}
        </div>
      )}

      <div className="alerts-container">
        {loading ? (
          <div className="alerts-empty">
            Loading intrusion alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div className="alerts-empty">
            No intrusion alerts found.
          </div>
        ) : (
          <div className="alerts-table-wrapper">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert._id}>
                    <td>
                      {alert.time
                        ? new Date(
                            alert.time
                          ).toLocaleString()
                        : alert.createdAt
                        ? new Date(
                            alert.createdAt
                          ).toLocaleString()
                        : "-"}
                    </td>

                    <td className="attack-type">
                      {alert.attackType}
                    </td>

                    <td>
                      <span
                        className={`alert-badge ${getSeverityClass(
                          alert.severity
                        )}`}
                      >
                        {alert.severity}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`alert-badge ${getStatusClass(
                          alert.status
                        )}`}
                      >
                        {alert.status}
                      </span>
                    </td>

                    <td>
                      {alert.status === "Unread" && (
                        <button
                          className="alert-action-button"
                          onClick={() =>
                            updateStatus(
                              alert._id,
                              "Read"
                            )
                          }
                        >
                          Mark Read
                        </button>
                      )}

                      {alert.status === "Read" && (
                        <button
                          className="alert-action-button"
                          onClick={() =>
                            updateStatus(
                              alert._id,
                              "Resolved"
                            )
                          }
                        >
                          Resolve
                        </button>
                      )}

                      {alert.status === "Resolved" && (
                        <span className="resolved-text">
                          Completed
                        </span>
                      )}
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
}