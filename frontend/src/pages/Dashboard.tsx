import { useEffect, useState, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import api from "../services/api";
import socket from "../services/socket";
import "./Dashboard.css";

type DashboardStats = {
  totalTraffic: number;
  totalAlerts: number;
  criticalAlerts: number;
  normalTraffic: number;
  attackTraffic: number;
};

type Alert = {
  _id: string;
  attackType?: string;
  severity?: string;
  status?: string;
  createdAt?: string;
};

const PIE_COLORS: Record<string, string> = {
  Normal: "#10b981",
  Attack: "#ef4444",
};

const BAR_COLORS: Record<string, string> = {
  Detected: "#3b82f6",
  Critical: "#f43f5e",
};

export default function Dashboard() {
  const navigate = useNavigate();

  const [stats, setStats] = useState<DashboardStats>({
    totalTraffic: 0,
    totalAlerts: 0,
    criticalAlerts: 0,
    normalTraffic: 0,
    attackTraffic: 0,
  });

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<string>("");
  const [isLiveConnected, setIsLiveConnected] = useState(socket.connected);

  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadDashboard = useCallback(async (silent = false) => {
    try {
      if (!silent) {
        setIsRefreshing(true);
      }
      setError("");

      const response = await api.get("/dashboard/stats");

      if (response.data?.stats) {
        setStats(response.data.stats);
      }

      if (Array.isArray(response.data?.recentAlerts)) {
        setAlerts(response.data.recentAlerts.slice(0, 5));
      }

      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err: any) {
      console.error("Dashboard loading error:", err);
      if (!silent) {
        setError(
          err.response?.data?.message ||
            "Unable to connect to security backend service."
        );
      }
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  // Debounced refresh for real-time socket events
  const debouncedRefresh = useCallback(() => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }
    debounceTimerRef.current = setTimeout(() => {
      loadDashboard(true);
    }, 800);
  }, [loadDashboard]);

  useEffect(() => {
    // Initial fetch
    loadDashboard(false);

    // Socket status handlers
    const handleConnect = () => setIsLiveConnected(true);
    const handleDisconnect = () => setIsLiveConnected(false);

    socket.on("connect", handleConnect);
    socket.on("disconnect", handleDisconnect);

    // Real-time socket events that should update Dashboard
    socket.on("live-traffic", debouncedRefresh);
    socket.on("traffic-update", debouncedRefresh);
    socket.on("alert-created", debouncedRefresh);
    socket.on("dashboard-update", debouncedRefresh);

    if (socket.connected) {
      setIsLiveConnected(true);
    }

    // Auto-polling backup every 12 seconds
    const intervalId = setInterval(() => {
      loadDashboard(true);
    }, 12000);

    return () => {
      socket.off("connect", handleConnect);
      socket.off("disconnect", handleDisconnect);
      socket.off("live-traffic", debouncedRefresh);
      socket.off("traffic-update", debouncedRefresh);
      socket.off("alert-created", debouncedRefresh);
      socket.off("dashboard-update", debouncedRefresh);

      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
      clearInterval(intervalId);
    };
  }, [loadDashboard, debouncedRefresh]);

  /*
   * Traffic distribution data for Donut Pie Chart
   */
  const trafficData = [
    {
      name: "Normal",
      value: stats.normalTraffic,
    },
    {
      name: "Attack",
      value: stats.attackTraffic,
    },
  ];

  /*
   * Threat data for Bar Chart
   */
  const threatData = [
    {
      name: "Detected",
      value: stats.totalAlerts,
    },
    {
      name: "Critical",
      value: stats.criticalAlerts,
    },
  ];

  const statCards = [
    {
      title: "Total Traffic",
      value: stats.totalTraffic,
      subtext: "Total monitored packets/flows",
      className: "dashboard-card-blue",
      badge: "Network",
    },
    {
      title: "Threats Detected",
      value: stats.totalAlerts,
      subtext: "Identified security anomalies",
      className: "dashboard-card-red",
      badge: "Alerts",
    },
    {
      title: "Critical Threats",
      value: stats.criticalAlerts,
      subtext: "High severity attack vectors",
      className: "dashboard-card-orange",
      badge: "High Risk",
    },
    {
      title: "Normal Traffic",
      value: stats.normalTraffic,
      subtext: "Verified benign communication",
      className: "dashboard-card-green",
      badge: "Healthy",
    },
  ];

  return (
    <div className="dashboard-page">
      {/* Header */}
      <div className="dashboard-header">
        <div className="dashboard-title-area">
          <div className="dashboard-title-row">
            <h1>Security Dashboard</h1>
            <div
              className={`dashboard-live-pill ${
                isLiveConnected ? "connected" : "disconnected"
              }`}
            >
              <span className="live-dot" />
              <span>{isLiveConnected ? "Live Sync Active" : "Disconnected"}</span>
            </div>
          </div>
          <p>
            AI-powered intrusion detection & network telemetry overview
            {lastUpdated && (
              <span className="dashboard-last-updated">
                {" "}• Updated at {lastUpdated}
              </span>
            )}
          </p>
        </div>

        <button
          className="dashboard-refresh-btn"
          onClick={() => loadDashboard(false)}
          disabled={isRefreshing}
          aria-label="Refresh dashboard metrics"
        >
          <span className={`refresh-icon ${isRefreshing ? "spin" : ""}`}>↻</span>
          <span>{isRefreshing ? "Refreshing..." : "Refresh"}</span>
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="dashboard-error-banner">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {/* Key Metric Stat Cards */}
      <div className="dashboard-stat-grid">
        {statCards.map((card) => (
          <div
            key={card.title}
            className={`dashboard-stat-card ${card.className}`}
          >
            <div className="dashboard-stat-top">
              <span className="dashboard-stat-title">{card.title}</span>
              <span className="dashboard-stat-badge">{card.badge}</span>
            </div>

            <div className="dashboard-stat-value">
              {loading ? "..." : card.value.toLocaleString()}
            </div>

            <div className="dashboard-stat-subtext">{card.subtext}</div>
          </div>
        ))}
      </div>

      {/* Interactive Telemetry Charts */}
      <div className="dashboard-chart-grid">
        {/* Traffic Distribution Donut */}
        <div className="dashboard-panel">
          <div className="dashboard-panel-header">
            <div>
              <h2>Traffic Distribution</h2>
              <span>Normal vs detected attack volume</span>
            </div>
            <div className="panel-tag">Flow Telemetry</div>
          </div>

          <div className="dashboard-chart">
            {stats.totalTraffic === 0 ? (
              <div className="dashboard-no-data">
                <div className="no-data-icon">📊</div>
                <p>No traffic telemetry recorded yet.</p>
                <span>Live network flows will populate here automatically.</span>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={trafficData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={95}
                    paddingAngle={3}
                    stroke="#0f172a"
                    strokeWidth={2}
                  >
                    {trafficData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={PIE_COLORS[entry.name] || "#3b82f6"}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)",
                      color: "#f8fafc",
                    }}
                    itemStyle={{ color: "#f8fafc" }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    iconType="circle"
                    wrapperStyle={{ paddingTop: "12px" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Threat Overview Bar Chart */}
        <div className="dashboard-panel">
          <div className="dashboard-panel-header">
            <div>
              <h2>Threat Overview</h2>
              <span>Verified security incidents by severity</span>
            </div>
            <div className="panel-tag danger-tag">Threat Feed</div>
          </div>

          <div className="dashboard-chart">
            {stats.totalAlerts === 0 ? (
              <div className="dashboard-no-data">
                <div className="no-data-icon">🛡️</div>
                <p>No intrusion threats detected.</p>
                <span>System is operating safely within normal parameters.</span>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart
                  data={threatData}
                  margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#334155"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="name"
                    stroke="#94a3b8"
                    tick={{ fill: "#94a3b8", fontSize: 12 }}
                  />
                  <YAxis
                    allowDecimals={false}
                    stroke="#94a3b8"
                    tick={{ fill: "#94a3b8", fontSize: 12 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)",
                      color: "#f8fafc",
                    }}
                    cursor={{ fill: "rgba(51, 65, 85, 0.3)" }}
                  />
                  <Bar dataKey="value" name="Threats" radius={[6, 6, 0, 0]}>
                    {threatData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={BAR_COLORS[entry.name] || "#3b82f6"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Verified Intrusion Incidents Table */}
      <div className="dashboard-panel dashboard-alert-panel">
        <div className="dashboard-panel-header">
          <div>
            <h2>Verified Intrusion Alerts</h2>
            <span>Latest detected threats and security anomalies</span>
          </div>

          <div className="panel-header-actions">
            <span className="alerts-count-badge">
              {stats.totalAlerts} total detected
            </span>
            {alerts.length > 0 && (
              <button
                className="view-all-alerts-link"
                onClick={() => navigate("/alerts")}
              >
                View all alerts →
              </button>
            )}
          </div>
        </div>

        {loading ? (
          <div className="dashboard-no-data">
            <div className="no-data-icon">⏳</div>
            <p>Loading security incidents...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="dashboard-no-data">
            <div className="no-data-icon">✅</div>
            <p>No verified security incidents found.</p>
            <span>Network intrusion monitors have not logged any threats.</span>
          </div>
        ) : (
          <div className="dashboard-table-wrapper">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert._id}
                    onClick={() => navigate(`/incident/${alert._id}`)}
                    className="dashboard-clickable-row"
                    title="Click to view full incident details"
                  >
                    <td className="timestamp-cell">
                      {alert.createdAt
                        ? new Date(alert.createdAt).toLocaleString()
                        : "-"}
                    </td>

                    <td className="dashboard-attack">
                      <span className="attack-dot" />
                      {alert.attackType || "Unclassified Threat"}
                    </td>

                    <td>
                      <span
                        className={`dashboard-badge dashboard-severity-${(
                          alert.severity || "Low"
                        ).toLowerCase()}`}
                      >
                        {alert.severity || "Low"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`dashboard-badge dashboard-status-${(
                          alert.status || "Unread"
                        ).toLowerCase()}`}
                      >
                        {alert.status || "Unread"}
                      </span>
                    </td>

                    <td>
                      <button
                        className="incident-inspect-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/incident/${alert._id}`);
                        }}
                      >
                        Inspect
                      </button>
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