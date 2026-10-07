import { useAuth } from "../context/AuthContext";
import "./Topbar.css";

type TopbarProps = {
  onToggleSidebar?: () => void;
};

export default function Topbar({ onToggleSidebar }: TopbarProps) {
  const { user } = useAuth();

  const displayName = user?.name || "Security Admin";
  const displayRole = user?.role || "Administrator";
  const initial = displayName.charAt(0).toUpperCase() || "A";

  return (
    <header className="app-topbar">
      <div className="topbar-left">
        {/* Mobile Hamburger Toggle Button */}
        <button
          className="topbar-menu-btn"
          onClick={onToggleSidebar}
          aria-label="Toggle navigation menu"
        >
          ☰
        </button>

        {/* Global Search Bar */}
        <div className="topbar-search-wrapper">
          <span className="topbar-search-icon">🔍</span>
          <input
            type="text"
            placeholder="Search IP, alerts, protocols..."
            className="topbar-search-input"
          />
        </div>
      </div>

      <div className="topbar-right">
        {/* Notifications */}
        <button
          className="topbar-notification-btn"
          aria-label="Security notifications"
          title="Intrusion notifications"
        >
          🔔
          <span className="notification-badge" />
        </button>

        {/* User Profile */}
        <div className="topbar-profile">
          <div className="profile-avatar">{initial}</div>
          <div className="profile-info">
            <span className="profile-name">{displayName}</span>
            <span className="profile-role">{displayRole}</span>
          </div>
        </div>
      </div>
    </header>
  );
}