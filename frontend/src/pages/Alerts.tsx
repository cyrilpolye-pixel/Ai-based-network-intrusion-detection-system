import { useEffect, useState, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import socket from "../services/socket";
import "./Alerts.css";

type TrafficLogRef = {
  _id: string;
  srcIP?: string;
  dstIP?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: string;
};

type Alert = {
  _id: string;
  trafficLogId?: string | TrafficLogRef;
  attackType: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: "Unread" | "Read" | "Resolved";
  time?: string;
  createdAt?: string;
};

export default function Alerts() {
  const navigate = useNavigate();

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "Unread" | "Read" | "Resolved">("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get("/alerts");
      setAlerts(response.data.alerts || []);
    } catch (err: any) {
      console.error("Failed to load alerts:", err);
      setError(
        err.response?.data?.message || "Unable to load intrusion alerts."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();

    // Real-time socket events
    const handleNewAlert = (newAlert: Alert) => {
      setAlerts((prev) => {
        const exists = prev.some((a) => a._id === newAlert._id);
        if (exists) return prev;
        return [newAlert, ...prev];
      });
    };

    const handleUpdateAlert = (updatedAlert: Alert) => {
      setAlerts((prev) =>
        prev.map((a) => (a._id === updatedAlert._id ? updatedAlert : a))
      );
    };

    const handleDeleteAlert = ({ id }: { id: string }) => {
      setAlerts((prev) => prev.filter((a) => a._id !== id));
    };

    socket.on("alert-created", handleNewAlert);
    socket.on("alert-updated", handleUpdateAlert);
    socket.on("alert-deleted", handleDeleteAlert);

    return () => {
      socket.off("alert-created", handleNewAlert);
      socket.off("alert-updated", handleUpdateAlert);
      socket.off("alert-deleted", handleDeleteAlert);
    };
  }, [fetchAlerts]);

  const updateStatus = async (
    id: string,
    status: "Unread" | "Read" | "Resolved"
  ) => {
    try {
      await api.put(`/alerts/${id}`, { status });
      setAlerts((prev) =>
        prev.map((a) => (a._id === id ? { ...a, status } : a))
      );
    } catch (err: any) {
      console.error("Failed to update alert:", err);
      setError(
        err.response?.data?.message || "Unable to update alert status."
      );
    }
  };

  const deleteAlert = async (id: string) => {
    if (!window.confirm("Are you sure you want to dismiss this alert?")) return;
    try {
      await api.delete(`/alerts/${id}`);
      setAlerts((prev) => prev.filter((a) => a._id !== id));
    } catch (err: any) {
      console.error("Failed to delete alert:", err);
      setError(
        err.response?.data?.message || "Unable to delete alert."
      );
    }
  };

  // KPI Metrics
  const unreadCount = useMemo(
    () => alerts.filter((a) => a.status === "Unread").length,
    [alerts]
  );
  const criticalCount = useMemo(
    () =>
      alerts.filter(
        (a) => a.severity === "Critical" || a.severity === "High"
      ).length,
    [alerts]
  );
  const resolvedCount = useMemo(
    () => alerts.filter((a) => a.status === "Resolved").length,
    [alerts]
  );

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      // 1. Search filter
      if (searchTerm.trim() !== "") {
        const q = searchTerm.toLowerCase();
        const trafficRef =
          typeof alert.trafficLogId === "object" ? alert.trafficLogId : null;
        const srcIP = trafficRef?.srcIP || "";
        const dstIP = trafficRef?.dstIP || "";
        const attack = alert.attackType.toLowerCase();
        const sev = alert.severity.toLowerCase();

        if (
          !attack.includes(q) &&
          !sev.includes(q) &&
          !srcIP.toLowerCase().includes(q) &&
          !dstIP.toLowerCase().includes(q)
        ) {
          return false;
        }
      }

      // 2. Status filter
      if (statusFilter !== "all" && alert.status !== statusFilter) {
        return false;
      }

      // 3. Severity filter
      if (
        severityFilter !== "all" &&
        alert.severity.toLowerCase() !== severityFilter.toLowerCase()
      ) {
        return false;
      }

      return true;
    });
  }, [alerts, searchTerm, statusFilter, severityFilter]);

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
      {/* Header */}
      <div className="alerts-header">
        <div className="alerts-title-area">
          <div className="alerts-title-row">
            <h1>Intrusion Alerts</h1>
            {unreadCount > 0 && (
              <span className="unread-pulse-badge">
                <span className="unread-dot" />
                {unreadCount} Unread Threats
              </span>
            )}
          </div>
          <p>Real-time detection alerts, severity classifications, and incident response</p>
        </div>

        <button
          className="alerts-refresh-button"
          onClick={fetchAlerts}
          disabled={loading}
        >
          <span className={loading ? "spin" : ""}>↻</span>
          <span>{loading ? "Refreshing..." : "Refresh Alerts"}</span>
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="alerts-error">
          <span>⚠️</span>
          <span>{error}</span>
          <button onClick={() => setError("")} className="close-banner-btn">✕</button>
        </div>
      )}

      {/* KPI Stat Cards */}
      <div className="alerts-kpi-grid">
        <div className="alerts-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">Total Alerts</span>
            <span className="kpi-icon">🚨</span>
          </div>
          <strong className="kpi-value">{loading ? "..." : alerts.length.toLocaleString()}</strong>
          <span className="kpi-sub">All-time detected events</span>
        </div>

        <div className={`alerts-kpi-card ${unreadCount > 0 ? "kpi-card-danger" : ""}`}>
          <div className="kpi-top">
            <span className="kpi-title">Active / Unread</span>
            <span className="kpi-icon">⚠️</span>
          </div>
          <strong className={`kpi-value ${unreadCount > 0 ? "val-danger" : ""}`}>
            {loading ? "..." : unreadCount.toLocaleString()}
          </strong>
          <span className="kpi-sub">Awaiting security inspection</span>
        </div>

        <div className="alerts-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">High & Critical</span>
            <span className="kpi-icon">🔥</span>
          </div>
          <strong className="kpi-value val-orange">
            {loading ? "..." : criticalCount.toLocaleString()}
          </strong>
          <span className="kpi-sub">DDoS, Hulk, PortScan attacks</span>
        </div>

        <div className="alerts-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">Resolved</span>
            <span className="kpi-icon">✅</span>
          </div>
          <strong className="kpi-value val-green">
            {loading ? "..." : resolvedCount.toLocaleString()}
          </strong>
          <span className="kpi-sub">Mitigated security events</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="alerts-filter-bar">
        <div className="alerts-search-box">
          <span className="search-icon">🔍</span>
          <input
            type="text"
            placeholder="Search attack type, IP, severity..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="alerts-search-input"
          />
          {searchTerm && (
            <button
              className="clear-search-btn"
              onClick={() => setSearchTerm("")}
            >
              ✕
            </button>
          )}
        </div>

        {/* Status Filter Pills */}
        <div className="alerts-status-filters">
          <button
            className={`status-pill ${statusFilter === "all" ? "active" : ""}`}
            onClick={() => setStatusFilter("all")}
          >
            All ({alerts.length})
          </button>
          <button
            className={`status-pill red ${statusFilter === "Unread" ? "active" : ""}`}
            onClick={() => setStatusFilter("Unread")}
          >
            Unread ({unreadCount})
          </button>
          <button
            className={`status-pill blue ${statusFilter === "Read" ? "active" : ""}`}
            onClick={() => setStatusFilter("Read")}
          >
            Read ({alerts.filter((a) => a.status === "Read").length})
          </button>
          <button
            className={`status-pill green ${statusFilter === "Resolved" ? "active" : ""}`}
            onClick={() => setStatusFilter("Resolved")}
          >
            Resolved ({resolvedCount})
          </button>
        </div>

        {/* Severity Selector */}
        <select
          className="alerts-severity-select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        {/* Reset Filter */}
        {(searchTerm || statusFilter !== "all" || severityFilter !== "all") && (
          <button
            className="alerts-reset-btn"
            onClick={() => {
              setSearchTerm("");
              setStatusFilter("all");
              setSeverityFilter("all");
            }}
          >
            Reset
          </button>
        )}
      </div>

      {/* Alerts Table Container */}
      <div className="alerts-container">
        {loading ? (
          <div className="alerts-empty">
            <span className="empty-icon">⏳</span>
            <p>Loading intrusion alerts from MongoDB...</p>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="alerts-empty">
            <span className="empty-icon">🛡️</span>
            <p>
              {alerts.length === 0
                ? "No intrusion alerts found. System is safe."
                : "No alerts match the selected filter criteria."}
            </p>
            {alerts.length > 0 && (
              <button
                className="alerts-reset-btn"
                onClick={() => {
                  setSearchTerm("");
                  setStatusFilter("all");
                  setSeverityFilter("all");
                }}
              >
                Clear Filters
              </button>
            )}
          </div>
        ) : (
          <div className="alerts-table-wrapper">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Attack Type</th>
                  <th>Targeted Endpoint</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {filteredAlerts.map((alert) => {
                  const trafficRef =
                    typeof alert.trafficLogId === "object"
                      ? alert.trafficLogId
                      : null;
                  const endpointStr =
                    trafficRef && trafficRef.srcIP
                      ? `${trafficRef.srcIP} → ${trafficRef.dstIP || ""}:${trafficRef.dstPort || ""}`
                      : "-";

                  return (
                    <tr
                      key={alert._id}
                      className={`alerts-row ${
                        alert.status === "Unread" ? "row-unread" : ""
                      }`}
                      onClick={() => navigate(`/incident/${alert._id}`)}
                      style={{ cursor: "pointer" }}
                      title="Click to inspect complete incident details"
                    >
                      <td className="timestamp-cell">
                        {alert.time
                          ? new Date(alert.time).toLocaleString()
                          : alert.createdAt
                          ? new Date(alert.createdAt).toLocaleString()
                          : "-"}
                      </td>

                      <td className="attack-type-cell">
                        <span className="attack-dot-indicator" />
                        <strong>{alert.attackType}</strong>
                      </td>

                      <td className="endpoint-cell">
                        <code>{endpointStr}</code>
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
                        <div className="alert-actions-cell">
                          <button
                            className="alert-action-btn primary"
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/incident/${alert._id}`);
                            }}
                            title="Inspect full packet telemetry & features"
                          >
                            Inspect
                          </button>

                          {alert.status === "Unread" && (
                            <button
                              className="alert-action-btn blue"
                              onClick={(e) => {
                                e.stopPropagation();
                                updateStatus(alert._id, "Read");
                              }}
                              title="Mark alert as acknowledged"
                            >
                              Mark Read
                            </button>
                          )}

                          {alert.status !== "Resolved" && (
                            <button
                              className="alert-action-btn green"
                              onClick={(e) => {
                                e.stopPropagation();
                                updateStatus(alert._id, "Resolved");
                              }}
                              title="Mark threat as mitigated"
                            >
                              Resolve
                            </button>
                          )}

                          <button
                            className="alert-action-btn delete"
                            onClick={(e) => {
                              e.stopPropagation();
                              deleteAlert(alert._id);
                            }}
                            title="Dismiss alert"
                          >
                            ✕
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}