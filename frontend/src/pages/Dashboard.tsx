import { useEffect, useState } from "react";
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

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>({
    totalTraffic: 0,
    totalAlerts: 0,
    criticalAlerts: 0,
    normalTraffic: 0,
    attackTraffic: 0,
  });

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get("/dashboard/stats");

      setStats(response.data.stats);

      setAlerts(
        response.data.recentAlerts?.slice(0, 5) || []
      );
    } catch (err: any) {
      console.error("Dashboard loading error:", err);

      setError(
        err.response?.data?.message ||
          "Unable to load dashboard data."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  /*
   * Pie chart:
   * Normal traffic vs attack traffic
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
   * Bar chart:
   * Total detected threats vs critical threats
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
      className: "dashboard-card-blue",
    },
    {
      title: "Threats Detected",
      value: stats.totalAlerts,
      className: "dashboard-card-red",
    },
    {
      title: "Critical Threats",
      value: stats.criticalAlerts,
      className: "dashboard-card-orange",
    },
    {
      title: "Normal Traffic",
      value: stats.normalTraffic,
      className: "dashboard-card-green",
    },
  ];

  return (
    <div className="dashboard-page">

      {/* Header */}
      <div className="dashboard-header">
        <div>
          <h1>Dashboard</h1>

          <p>
            AI-NIDS network security overview
          </p>
        </div>

        <button
          className="dashboard-refresh"
          onClick={loadDashboard}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="dashboard-error">
          {error}
        </div>
      )}

      {/* Statistics */}
      <div className="dashboard-stat-grid">

        {statCards.map((card) => (
          <div
            key={card.title}
            className={`dashboard-stat-card ${card.className}`}
          >
            <div className="dashboard-stat-title">
              {card.title}
            </div>

            <div className="dashboard-stat-value">
              {loading
                ? "..."
                : card.value.toLocaleString()}
            </div>
          </div>
        ))}

      </div>

      {/* Charts */}
      <div className="dashboard-chart-grid">

        {/* Traffic Pie Chart */}
        <div className="dashboard-panel">

          <div className="dashboard-panel-header">
            <div>
              <h2>Traffic Distribution</h2>

              <span>
                Normal vs detected attacks
              </span>
            </div>
          </div>

          <div className="dashboard-chart">

            {stats.totalTraffic === 0 ? (
              <div className="dashboard-no-data">
                No traffic data available.
              </div>
            ) : (
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <PieChart>

                  <Pie
                    data={trafficData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={95}
                    label
                  >
                    {trafficData.map((entry) => (
                      <Cell key={entry.name} />
                    ))}
                  </Pie>

                  <Tooltip />

                  <Legend />

                </PieChart>
              </ResponsiveContainer>
            )}

          </div>
        </div>

        {/* Threat Bar Chart */}
        <div className="dashboard-panel">

          <div className="dashboard-panel-header">
            <div>
              <h2>Threat Overview</h2>

              <span>
                Verified security threats
              </span>
            </div>
          </div>

          <div className="dashboard-chart">

            {stats.totalAlerts === 0 ? (
              <div className="dashboard-no-data">
                No threats detected.
              </div>
            ) : (
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <BarChart data={threatData}>

                  <CartesianGrid />

                  <XAxis
                    dataKey="name"
                  />

                  <YAxis
                    allowDecimals={false}
                  />

                  <Tooltip />

                  <Bar
                    dataKey="value"
                    name="Count"
                  />

                </BarChart>
              </ResponsiveContainer>
            )}

          </div>
        </div>

      </div>

      {/* Verified Attacks */}
      <div className="dashboard-panel dashboard-alert-panel">

        <div className="dashboard-panel-header">

          <div>
            <h2>
              Verified Intrusion Alerts
            </h2>

            <span>
              Latest detected security threats
            </span>
          </div>

          <span>
            {stats.totalAlerts} detected
          </span>

        </div>

        {loading ? (
          <div className="dashboard-no-data">
            Loading verified attacks...
          </div>
        ) : alerts.length === 0 ? (
          <div className="dashboard-no-data">
            No verified attacks found.
          </div>
        ) : (
          <div className="dashboard-table-wrapper">

            <table className="dashboard-table">

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
                      {alert.createdAt
                        ? new Date(
                            alert.createdAt
                          ).toLocaleString()
                        : "-"}
                    </td>

                    <td className="dashboard-attack">
                      {alert.attackType ||
                        "Unknown"}
                    </td>

                    <td>
                      <span
                        className={`dashboard-badge dashboard-severity-${(
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
                        className={`dashboard-badge dashboard-status-${(
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

    </div>
  );
}