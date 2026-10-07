import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "./Sidebar.css";

const menuItems = [
  { name: "Dashboard", path: "/dashboard", icon: "📊" },
  { name: "Live Monitoring", path: "/live-monitoring", icon: "📡" },
  { name: "Traffic Analysis", path: "/traffic-analysis", icon: "📈" },
  { name: "Intrusion Alerts", path: "/alerts", icon: "🚨" },
  { name: "Reports", path: "/reports", icon: "📑" },
  { name: "Settings", path: "/settings", icon: "⚙️" },
  { name: "Profile", path: "/profile", icon: "👤" },
];

type SidebarProps = {
  isOpen?: boolean;
  onClose?: () => void;
};

export default function Sidebar({ isOpen = false, onClose }: SidebarProps) {
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    if (onClose) onClose();
    logout();
    navigate("/", { replace: true });
  };

  const handleLinkClick = () => {
    if (onClose) onClose();
  };

  return (
    <aside className={`app-sidebar ${isOpen ? "sidebar-open" : ""}`}>
      {/* Header / Brand */}
      <div className="sidebar-header">
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">🛡️</div>
          <h2>AI-NIDS</h2>
        </div>

        <button
          className="sidebar-close-btn"
          onClick={onClose}
          aria-label="Close navigation sidebar"
        >
          ✕
        </button>
      </div>

      {/* Navigation Links */}
      <nav className="sidebar-nav">
        {menuItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            onClick={handleLinkClick}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? "active" : ""}`
            }
          >
            <span>{item.icon}</span>
            <span>{item.name}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer / Logout */}
      <div className="sidebar-footer">
        <button
          onClick={handleLogout}
          className="sidebar-logout-btn"
          aria-label="Logout"
        >
          <span>🚪</span>
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
}