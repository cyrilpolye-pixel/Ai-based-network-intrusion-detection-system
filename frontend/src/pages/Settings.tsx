import { useState } from "react";

export default function Settings() {
  const [settings, setSettings] = useState({
    autoBlock: true,
    emailAlerts: true,
    desktopAlerts: false,
    packetCapture: true,
    aiThreshold: 85,
    logRetention: 30,
  });

  const handleCheckbox = (name: string) => {
    setSettings((prev) => ({
      ...prev,
      [name]: !prev[name as keyof typeof prev],
    }));
  };

  const handleNumberChange = (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const { name, value } = e.target;

    setSettings((prev) => ({
      ...prev,
      [name]: Number(value),
    }));
  };

  const handleSave = () => {
    console.log(settings);
    alert("Settings saved successfully!");
  };

  return (
    <div style={{ color: "white" }}>
      <h1 style={{ marginBottom: "25px" }}>System Settings</h1>

      <div
        style={{
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "12px",
          padding: "25px",
          maxWidth: "700px",
        }}
      >
        <Checkbox
          label="Enable Automatic IP Blocking"
          checked={settings.autoBlock}
          onChange={() => handleCheckbox("autoBlock")}
        />

        <Checkbox
          label="Enable Email Alerts"
          checked={settings.emailAlerts}
          onChange={() => handleCheckbox("emailAlerts")}
        />

        <Checkbox
          label="Enable Desktop Notifications"
          checked={settings.desktopAlerts}
          onChange={() => handleCheckbox("desktopAlerts")}
        />

        <Checkbox
          label="Enable Packet Capture"
          checked={settings.packetCapture}
          onChange={() => handleCheckbox("packetCapture")}
        />

        <div style={{ marginTop: "25px" }}>
          <label style={labelStyle}>
            AI Detection Threshold (%)
          </label>

          <input
            type="number"
            name="aiThreshold"
            value={settings.aiThreshold}
            min={50}
            max={100}
            onChange={handleNumberChange}
            style={inputStyle}
          />
        </div>

        <div style={{ marginTop: "20px" }}>
          <label style={labelStyle}>
            Log Retention (Days)
          </label>

          <input
            type="number"
            name="logRetention"
            value={settings.logRetention}
            min={1}
            max={365}
            onChange={handleNumberChange}
            style={inputStyle}
          />
        </div>

        <button
          onClick={handleSave}
          style={{
            marginTop: "30px",
            background: "#3b82f6",
            color: "white",
            border: "none",
            padding: "12px 22px",
            borderRadius: "8px",
            cursor: "pointer",
            fontSize: "15px",
            fontWeight: "bold",
          }}
        >
          Save Settings
        </button>
      </div>
    </div>
  );
}

type CheckboxProps = {
  label: string;
  checked: boolean;
  onChange: () => void;
};

function Checkbox({
  label,
  checked,
  onChange,
}: CheckboxProps) {
  return (
    <div
      style={{
        marginBottom: "18px",
      }}
    >
      <label
        style={{
          cursor: "pointer",
          color: "#cbd5e1",
        }}
      >
        <input
          type="checkbox"
          checked={checked}
          onChange={onChange}
          style={{ marginRight: "10px" }}
        />

        {label}
      </label>
    </div>
  );
}

const labelStyle = {
  display: "block" as const,
  marginBottom: "8px",
  color: "#cbd5e1",
};

const inputStyle = {
  width: "100%",
  padding: "10px",
  background: "#0f172a",
  border: "1px solid #334155",
  borderRadius: "8px",
  color: "white",
  fontSize: "15px",
};