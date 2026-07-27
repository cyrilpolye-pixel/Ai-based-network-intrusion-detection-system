import { useState } from "react";

const Settings = () => {
  const [settings, setSettings] = useState({
    username: "admin",
    email: "admin@example.com",
    notifications: true,
    darkMode: true,
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;

    setSettings((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSave = () => {
    console.log("Saved settings:", settings);
    alert("Settings saved successfully!");
  };

  return (
    <div style={{ padding: "20px", color: "white" }}>
      <h2>Settings</h2>

      <div style={{ maxWidth: "400px" }}>
        {/* Username */}
        <div style={{ marginBottom: "15px" }}>
          <label>Username</label>
          <input
            type="text"
            name="username"
            value={settings.username}
            onChange={handleChange}
            style={{
              width: "100%",
              padding: "8px",
              marginTop: "5px",
              background: "#1e293b",
              border: "1px solid #334155",
              color: "white",
            }}
          />
        </div>

        {/* Email */}
        <div style={{ marginBottom: "15px" }}>
          <label>Email</label>
          <input
            type="email"
            name="email"
            value={settings.email}
            onChange={handleChange}
            style={{
              width: "100%",
              padding: "8px",
              marginTop: "5px",
              background: "#1e293b",
              border: "1px solid #334155",
              color: "white",
            }}
          />
        </div>

        {/* Notifications */}
        <div style={{ marginBottom: "15px" }}>
          <label>
            <input
              type="checkbox"
              name="notifications"
              checked={settings.notifications}
              onChange={handleChange}
              style={{ marginRight: "10px" }}
            />
            Enable Notifications
          </label>
        </div>

        {/* Dark Mode */}
        <div style={{ marginBottom: "15px" }}>
          <label>
            <input
              type="checkbox"
              name="darkMode"
              checked={settings.darkMode}
              onChange={handleChange}
              style={{ marginRight: "10px" }}
            />
            Dark Mode
          </label>
        </div>

        {/* Save Button */}
        <button
          onClick={handleSave}
          style={{
            padding: "10px",
            background: "#3b82f6",
            border: "none",
            color: "white",
            cursor: "pointer",
            width: "100%",
          }}
        >
          Save Settings
        </button>
      </div>
    </div>
  );
};

export default Settings;