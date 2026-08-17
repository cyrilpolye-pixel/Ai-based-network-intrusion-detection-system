import { useState } from "react";
import "./Settings.css";

type SettingsState = {
  autoBlock: boolean;
  emailAlerts: boolean;
  desktopAlerts: boolean;
  packetCapture: boolean;
  aiThreshold: number;
  logRetention: number;
};

const DEFAULT_SETTINGS: SettingsState = {
  autoBlock: true,
  emailAlerts: true,
  desktopAlerts: false,
  packetCapture: true,
  aiThreshold: 85,
  logRetention: 30,
};

export default function Settings() {
  const [settings, setSettings] =
    useState<SettingsState>(DEFAULT_SETTINGS);

  const [message, setMessage] = useState("");

  const handleCheckbox = (
    name: keyof Pick<
      SettingsState,
      "autoBlock" |
        "emailAlerts" |
        "desktopAlerts" |
        "packetCapture"
    >
  ) => {
    setSettings((prev) => ({
      ...prev,
      [name]: !prev[name],
    }));

    setMessage("");
  };

  const handleNumberChange = (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const { name, value } = e.target;

    setSettings((prev) => ({
      ...prev,
      [name]: Number(value),
    }));

    setMessage("");
  };

  const handleSave = () => {
    /*
     * These settings are currently frontend-only.
     * Do not claim that they were persisted to MongoDB
     * until a real backend settings API exists.
     */
    console.log("Current settings:", settings);

    setMessage(
      "Settings updated for this session. Backend persistence is not currently configured."
    );
  };

  const handleReset = () => {
    setSettings(DEFAULT_SETTINGS);
    setMessage("Settings reset to default values.");
  };

  return (
    <div className="settings-page">
      <div className="settings-header">
        <div>
          <h1 className="settings-title">System Settings</h1>
          <p className="settings-description">
            Configure detection and notification preferences.
          </p>
        </div>
      </div>

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
          <label className="settings-label" htmlFor="aiThreshold">
            AI Detection Threshold (%)
          </label>

          <input
            id="aiThreshold"
            type="number"
            name="aiThreshold"
            value={settings.aiThreshold}
            min={50}
            max={100}
            onChange={handleNumberChange}
            className="settings-input"
          />

          <small className="settings-help">
            Currently applies only to the frontend setting value.
          </small>
        </div>

        <div className="settings-field">
          <label className="settings-label" htmlFor="logRetention">
            Log Retention (Days)
          </label>

          <input
            id="logRetention"
            type="number"
            name="logRetention"
            value={settings.logRetention}
            min={1}
            max={365}
            onChange={handleNumberChange}
            className="settings-input"
          />

          <small className="settings-help">
            Database retention is not currently configured through this page.
          </small>
        </div>

        {message && (
          <div className="settings-message">
            {message}
          </div>
        )}

        <div className="settings-actions">
          <button
            type="button"
            onClick={handleSave}
            className="settings-save-button"
          >
            Save Settings
          </button>

          <button
            type="button"
            onClick={handleReset}
            className="settings-reset-button"
          >
            Reset
          </button>
        </div>
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