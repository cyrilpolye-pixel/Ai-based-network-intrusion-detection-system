import { useState } from "react";
import "./Settings.css";

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
    <div className="settings-page">
      <h1 className="settings-title">System Settings</h1>

      <div className="settings-card">
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

        <div className="settings-field settings-field-large-gap">
          <label className="settings-label">
            AI Detection Threshold (%)
          </label>

          <input
            type="number"
            name="aiThreshold"
            value={settings.aiThreshold}
            min={50}
            max={100}
            onChange={handleNumberChange}
            className="settings-input"
          />
        </div>

        <div className="settings-field">
          <label className="settings-label">
            Log Retention (Days)
          </label>

          <input
            type="number"
            name="logRetention"
            value={settings.logRetention}
            min={1}
            max={365}
            onChange={handleNumberChange}
            className="settings-input"
          />
        </div>

        <button onClick={handleSave} className="settings-save-button">
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
    <div className="settings-checkbox-row">
      <label className="settings-checkbox-label">
        <input
          type="checkbox"
          checked={checked}
          onChange={onChange}
          className="settings-checkbox"
        />

        {label}
      </label>
    </div>
  );
}
