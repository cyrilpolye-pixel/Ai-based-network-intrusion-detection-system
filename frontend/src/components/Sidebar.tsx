import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const menuItems = [
  { name: "Dashboard", path: "/dashboard" },
  { name: "Live Monitoring", path: "/live-monitoring" },
  { name: "Traffic Analysis", path: "/traffic-analysis" },
  { name: "Intrusion Alerts", path: "/alerts" },
  { name: "Reports", path: "/reports" },
  { name: "Settings", path: "/settings" },
  { name: "Profile", path: "/profile" },
];

export default function Sidebar() {
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/", { replace: true });
  };

  return (
    <div
      style={{
        width: "260px",
        background: "#111827",
        color: "white",
        display: "flex",
        flexDirection: "column",
        padding: "20px",
      }}
    >
      <h2 style={{ marginBottom: "40px" }}>AI-NIDS</h2>

      {menuItems.map((item) => (
        <NavLink
          key={item.path}
          to={item.path}
          style={({ isActive }) => ({
            textDecoration: "none",
            color: isActive ? "#60a5fa" : "#ffffff",
            padding: "12px",
            borderRadius: "8px",
            marginBottom: "10px",
            background: isActive ? "#1e293b" : "transparent",
            transition: "0.2s",
          })}
        >
          {item.name}
        </NavLink>
      ))}

      <div style={{ flex: 1 }} />

      <button
        onClick={handleLogout}
        style={{
          padding: "12px",
          background: "#ef4444",
          color: "white",
          border: "none",
          borderRadius: "8px",
          cursor: "pointer",
        }}
      >
        Logout
      </button>
    </div>
  );
}