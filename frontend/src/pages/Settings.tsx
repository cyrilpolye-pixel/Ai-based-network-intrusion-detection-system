import { useEffect, useState, useCallback } from "react";
import api from "../services/api";
import "./Settings.css";

type BlockedIP = {
  ip: string;
  reason?: string;
  blockedAt?: string;
};

type SettingsState = {
  autoBlock: boolean;
  emailAlerts: boolean;
  desktopAlerts: boolean;
  packetCapture: boolean;
  aiThreshold: number;
  logRetention: number;
  blockedIPs: BlockedIP[];
};

const DEFAULT_SETTINGS: SettingsState = {
  autoBlock: true,
  emailAlerts: true,
  desktopAlerts: false,
  packetCapture: true,
  aiThreshold: 85,
  logRetention: 30,
  blockedIPs: [],
};

const STORAGE_KEY = "ainids_system_settings";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsState>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? { ...DEFAULT_SETTINGS, ...JSON.parse(saved) } : DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [messageTone, setMessageTone] = useState<"success" | "error" | "info">("info");

  // New IP to block
  const [newBlockIP, setNewBlockIP] = useState("");
  const [newBlockReason, setNewBlockReason] = useState("");

  const showFeedback = (msg: string, tone: "success" | "error" | "info" = "success") => {
    setMessage(msg);
    setMessageTone(tone);
    setTimeout(() => {
      setMessage("");
    }, 4000);
  };

  const loadSettings = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get("/settings");
      if (res.data?.settings) {
        const loaded: SettingsState = {
          autoBlock: res.data.settings.autoBlock ?? DEFAULT_SETTINGS.autoBlock,
          emailAlerts: res.data.settings.emailAlerts ?? DEFAULT_SETTINGS.emailAlerts,
          desktopAlerts: res.data.settings.desktopAlerts ?? DEFAULT_SETTINGS.desktopAlerts,
          packetCapture: res.data.settings.packetCapture ?? DEFAULT_SETTINGS.packetCapture,
          aiThreshold: res.data.settings.aiThreshold ?? DEFAULT_SETTINGS.aiThreshold,
          logRetention: res.data.settings.logRetention ?? DEFAULT_SETTINGS.logRetention,
          blockedIPs: res.data.settings.blockedIPs ?? [],
        };
        setSettings(loaded);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(loaded));
      }
    } catch (err: any) {
      console.warn("Using local settings fallback:", err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleCheckbox = (
    name: "autoBlock" | "emailAlerts" | "desktopAlerts" | "packetCapture"
  ) => {
    setSettings((prev) => {
      const updated = { ...prev, [name]: !prev[name] };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      return updated;
    });
  };

  const handleNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setSettings((prev) => {
      const updated = { ...prev, [name]: Number(value) };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      return updated;
    });
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));

      const res = await api.put("/settings", settings);
      showFeedback(
        res.data?.message || "Settings successfully synchronized with MongoDB.",
        "success"
      );
    } catch (err: any) {
      // Local fallback saved
      showFeedback(
        "Settings saved locally. Backend will synchronize when connection resumes.",
        "info"
      );
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setSettings(DEFAULT_SETTINGS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_SETTINGS));
    try {
      await api.put("/settings", DEFAULT_SETTINGS);
      showFeedback("Settings reset to system factory defaults.", "info");
    } catch {
      showFeedback("Settings reset locally to factory defaults.", "info");
    }
  };

  // Manual IP Block
  const handleAddBlockIP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBlockIP.trim()) return;

    try {
      const res = await api.post("/settings/block-ip", {
        ip: newBlockIP.trim(),
        reason: newBlockReason.trim() || "Manual security administrator ban",
      });

      if (res.data?.blockedIPs) {
        setSettings((prev) => ({
          ...prev,
          blockedIPs: res.data.blockedIPs,
        }));
      } else {
        setSettings((prev) => ({
          ...prev,
          blockedIPs: [
            ...prev.blockedIPs,
            {
              ip: newBlockIP.trim(),
              reason: newBlockReason.trim() || "Manual admin ban",
              blockedAt: new Date().toISOString(),
            },
          ],
        }));
      }

      setNewBlockIP("");
      setNewBlockReason("");
      showFeedback(`IP address ${newBlockIP.trim()} added to firewall blocklist.`, "success");
    } catch (err: any) {
      showFeedback(err.response?.data?.message || "Failed to block IP.", "error");
    }
  };

  // Remove IP from blocklist
  const handleUnblockIP = async (ip: string) => {
    try {
      await api.post("/settings/unblock-ip", { ip });
      setSettings((prev) => ({
        ...prev,
        blockedIPs: prev.blockedIPs.filter((b) => b.ip !== ip),
      }));
      showFeedback(`IP ${ip} removed from blocklist.`, "success");
    } catch (err: any) {
      showFeedback(err.response?.data?.message || "Failed to unblock IP.", "error");
    }
  };

  return (
    <div className="settings-page">
      <div className="settings-header">
        <div>
          <h1 className="settings-title">System Settings</h1>
          <p className="settings-description">
            Configure automated intrusion mitigation, detection thresholds, and firewall blocklists.
          </p>
        </div>

        <button
          className="settings-save-top-btn"
          onClick={handleSave}
          disabled={loading || saving}
        >
          {saving ? "Saving..." : loading ? "Loading..." : "Save Settings"}
        </button>
      </div>

      {message && (
        <div className={`settings-alert-banner banner-${messageTone}`}>
          <span>{messageTone === "success" ? "✓" : "ℹ"}</span>
          <span>{message}</span>
        </div>
      )}

      <div className="settings-layout-grid">
        {/* Left Column: Detection & Automation Rules */}
        <div className="settings-column">
          <div className="settings-card">
            <h2 className="settings-section-title">Automated Defense & Telemetry</h2>

            <div className="settings-toggle-list">
              <label className="settings-toggle-row">
                <div className="toggle-info">
                  <strong>Automatic IP Blocking (Firewall Drop)</strong>
                  <span>
                    Instantly add hostile source IPs to perimeter firewall drop rules upon Critical or High severity detection.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.autoBlock}
                  onChange={() => handleCheckbox("autoBlock")}
                  className="settings-switch"
                />
              </label>

              <label className="settings-toggle-row">
                <div className="toggle-info">
                  <strong>Deep Packet Telemetry Logging</strong>
                  <span>
                    Capture full packet duration, byte volumes, and flow flags alongside intrusion alerts.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.packetCapture}
                  onChange={() => handleCheckbox("packetCapture")}
                  className="settings-switch"
                />
              </label>

              <label className="settings-toggle-row">
                <div className="toggle-info">
                  <strong>Email Security Notifications</strong>
                  <span>
                    Dispatch urgent alert notifications when DDoS or DoS Hulk anomalies are classified.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.emailAlerts}
                  onChange={() => handleCheckbox("emailAlerts")}
                  className="settings-switch"
                />
              </label>

              <label className="settings-toggle-row">
                <div className="toggle-info">
                  <strong>Desktop & Audio Notifications</strong>
                  <span>
                    Play acoustic chimes and trigger browser notification popups for real-time intrusion alerts.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.desktopAlerts}
                  onChange={() => handleCheckbox("desktopAlerts")}
                  className="settings-switch"
                />
              </label>
            </div>
          </div>

          <div className="settings-card">
            <h2 className="settings-section-title">AI Inference & Storage Optimization</h2>

            <div className="settings-input-group">
              <div className="input-header-row">
                <label htmlFor="aiThreshold">
                  AI Classification Confidence Threshold
                </label>
                <span className="threshold-pill">{settings.aiThreshold}%</span>
              </div>
              <input
                id="aiThreshold"
                type="range"
                name="aiThreshold"
                min={50}
                max={99}
                value={settings.aiThreshold}
                onChange={handleNumberChange}
                className="settings-range-slider"
              />
              <span className="input-hint">
                Traffic predictions with confidence above {settings.aiThreshold}% will trigger verified intrusion alerts.
              </span>
            </div>

            <div className="settings-input-group">
              <div className="input-header-row">
                <label htmlFor="logRetention">Log Retention Window (Days)</label>
                <span className="threshold-pill">{settings.logRetention} Days</span>
              </div>
              <input
                id="logRetention"
                type="number"
                name="logRetention"
                min={1}
                max={365}
                value={settings.logRetention}
                onChange={handleNumberChange}
                className="settings-number-input"
              />
              <span className="input-hint">
                MongoDB Atlas Free Tier Guard: Automatically prunes benign traffic logs older than {settings.logRetention} days.
              </span>
            </div>

            <div className="settings-actions-row">
              <button
                type="button"
                onClick={handleSave}
                disabled={loading || saving}
                className="settings-save-button"
              >
                {saving
                  ? "Saving to Database..."
                  : loading
                  ? "Loading Settings..."
                  : "Save System Settings"}
              </button>

              <button
                type="button"
                onClick={handleReset}
                className="settings-reset-button"
              >
                Reset to Defaults
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Firewall Blocklist Management */}
        <div className="settings-column">
          <div className="settings-card firewall-card">
            <div className="firewall-header">
              <div>
                <h2 className="settings-section-title">Firewall Blocklist Manager</h2>
                <span className="firewall-sub">
                  Active host ban list enforced across edge ingress routes
                </span>
              </div>
              <span className="block-count-badge">
                {settings.blockedIPs.length} Blocked
              </span>
            </div>

            {/* Manual Ban Form */}
            <form onSubmit={handleAddBlockIP} className="manual-ban-form">
              <input
                type="text"
                placeholder="IP Address (e.g., 192.168.1.50)"
                value={newBlockIP}
                onChange={(e) => setNewBlockIP(e.target.value)}
                className="ban-input"
                required
              />
              <input
                type="text"
                placeholder="Reason (e.g., Suspicious port scanning)"
                value={newBlockReason}
                onChange={(e) => setNewBlockReason(e.target.value)}
                className="ban-input ban-reason"
              />
              <button type="submit" className="ban-submit-btn">
                + Ban IP
              </button>
            </form>

            {/* Blocked IP List */}
            <div className="blocked-list-container">
              {settings.blockedIPs.length === 0 ? (
                <div className="empty-blocklist">
                  <span>🛡️ No IP addresses currently banned.</span>
                  <p>
                    Hostile IPs can be added manually or automatically when viewing incident details.
                  </p>
                </div>
              ) : (
                <div className="blocked-ip-table-wrapper">
                  <table className="blocked-ip-table">
                    <thead>
                      <tr>
                        <th>Banned Host IP</th>
                        <th>Reason</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {settings.blockedIPs.map((item) => (
                        <tr key={item.ip}>
                          <td className="ip-cell">
                            <code>{item.ip}</code>
                          </td>
                          <td className="reason-cell">
                            {item.reason || "Intrusion detected"}
                          </td>
                          <td>
                            <button
                              className="unblock-btn"
                              onClick={() => handleUnblockIP(item.ip)}
                              title="Remove firewall ban"
                            >
                              Unblock
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
        </div>
      </div>
    </div>
  );
}