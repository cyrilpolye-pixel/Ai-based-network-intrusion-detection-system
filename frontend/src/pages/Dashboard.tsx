import { useEffect, useState } from "react";
import api from "../services/api";

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

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        setLoading(true);
        setError("");

        const statsResponse = await api.get("/dashboard/stats");

        setStats(statsResponse.data.stats);

        setAlerts(
          statsResponse.data.recentAlerts?.slice(0, 5) || []
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

    loadDashboard();
  }, []);

  const statCards = [
    {
      title: "Total Traffic",
      value: stats.totalTraffic.toLocaleString(),
    },
    {
      title: "Threats Detected",
      value: stats.totalAlerts.toLocaleString(),
    },
    {
      title: "Critical Threats",
      value: stats.criticalAlerts.toLocaleString(),
    },
    {
      title: "Normal Traffic",
      value: stats.normalTraffic.toLocaleString(),
    },
  ];

  return (
    <div>
      <h1
        style={{
          color: "white",
          marginBottom: "25px",
        }}
      >
        Dashboard
      </h1>

      {/* Error */}
      {error && (
        <div
          style={{
            background: "rgba(239,68,68,0.12)",
            border: "1px solid #ef4444",
            color: "#fca5a5",
            padding: "12px 16px",
            borderRadius: "8px",
            marginBottom: "20px",
          }}
        >
          {error}
        </div>
      )}

      {/* Statistics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "20px",
        }}
      >
        {statCards.map((card) => (
          <div
            key={card.title}
            style={{
              background: "#1e293b",
              padding: "20px",
              borderRadius: "10px",
              color: "white",
              border: "1px solid #334155",
            }}
          >
            <h3
              style={{
                color: "#94a3b8",
                marginBottom: "10px",
              }}
            >
              {card.title}
            </h3>

            <h1 style={{ margin: 0 }}>
              {loading ? "..." : card.value}
            </h1>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "2fr 1fr",
          gap: "20px",
          marginTop: "30px",
        }}
      >
        {/* Network Traffic */}
        <div
          style={{
            background: "#1e293b",
            height: "320px",
            borderRadius: "10px",
            padding: "20px",
            color: "white",
            border: "1px solid #334155",
          }}
        >
          <h2>Network Traffic</h2>

          <div
            style={{
              height: "230px",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              color: "#94a3b8",
            }}
          >
            Network traffic chart will be connected next.
          </div>
        </div>

        {/* Threat Distribution */}
        <div
          style={{
            background: "#1e293b",
            height: "320px",
            borderRadius: "10px",
            padding: "20px",
            color: "white",
            border: "1px solid #334155",
          }}
        >
          <h2>Threat Distribution</h2>

          <div
            style={{
              height: "230px",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              color: "#94a3b8",
            }}
          >
            Threat distribution chart will be connected next.
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div
        style={{
          marginTop: "30px",
          background: "#1e293b",
          borderRadius: "10px",
          padding: "20px",
          color: "white",
          border: "1px solid #334155",
        }}
      >
        <h2>Recent Intrusion Alerts</h2>

        {loading ? (
          <p style={{ color: "#94a3b8" }}>
            Loading alerts...
          </p>
        ) : alerts.length === 0 ? (
          <p style={{ color: "#94a3b8" }}>
            No intrusion alerts found.
          </p>
        ) : (
          <table
            style={{
              width: "100%",
              marginTop: "20px",
              borderCollapse: "collapse",
            }}
          >
            <thead>
              <tr>
                <th align="left">Time</th>
                <th align="left">Attack</th>
                <th align="left">Severity</th>
                <th align="left">Status</th>
              </tr>
            </thead>

            <tbody>
              {alerts.map((alert) => (
                <tr key={alert._id}>
                  <td style={cellStyle}>
                    {alert.createdAt
                      ? new Date(
                          alert.createdAt
                        ).toLocaleTimeString()
                      : "-"}
                  </td>

                  <td style={cellStyle}>
                    {alert.attackType || "Unknown"}
                  </td>

                  <td style={cellStyle}>
                    {alert.severity || "-"}
                  </td>

                  <td style={cellStyle}>
                    {alert.status || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const cellStyle = {
  padding: "12px 8px",
  borderTop: "1px solid #334155",
  color: "#cbd5e1",
};

