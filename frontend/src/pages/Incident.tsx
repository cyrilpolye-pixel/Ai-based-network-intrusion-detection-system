import { useEffect, useState, useCallback } from "react";
import { useNavigate, useParams } from "react-router-dom";
import api from "../services/api";
import socket from "../services/socket";
import "./Incident.css";

type Alert = {
  _id: string;
  trafficLogId?: string | {
    _id?: string;
    srcIP?: string;
    dstIP?: string;
    protocol?: string;
    srcPort?: number;
    dstPort?: number;
    duration?: number;
    packets?: number;
    bytes?: number;
    label?: string;
    prediction?: string;
    confidence?: number;
    timestamp?: string;
    createdAt?: string;
  };
  attackType: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  status: "Unread" | "Read" | "Resolved";
  time?: string;
  createdAt?: string;
};

type TrafficLog = {
  _id: string;
  timestamp?: string;
  createdAt?: string;
  srcIP?: string;
  dstIP?: string;
  protocol?: string;
  srcPort?: number;
  dstPort?: number;
  duration?: number;
  packets?: number;
  bytes?: number;
  label?: string;
  prediction?: string;
  confidence?: number;
};

const ATTACK_INFO: Record<
  string,
  {
    category: string;
    description: string;
    mitigation: string;
  }
> = {
  "dos hulk": {
    category: "Application-Layer Denial of Service",
    description:
      "DoS Hulk (Http Unbearable Load King) floods the target HTTP/HTTPS service with obfuscated requests and randomized User-Agent headers, exhausting server thread pools and RAM.",
    mitigation:
      "Deploy WAF rate limiting, enforce HTTP Keep-Alive request limits, and blacklist hostile source IP at the edge firewall.",
  },
  ddos: {
    category: "Distributed Denial of Service",
    description:
      "High-throughput packet flooding attack intended to saturate network bandwidth and server connection tables, making the target unreachable for legitimate users.",
    mitigation:
      "Activate upstream DDoS scrubbing, enable TCP SYN cookies, and rate-limit ingress packets at the border router.",
  },
  portscan: {
    category: "Network Reconnaissance & Probing",
    description:
      "Systematic probing of destination ports to identify active listening daemons, open services, and vulnerable versions prior to targeted exploitation.",
    mitigation:
      "Close unused listening ports, deploy Port Knocking or IDS auto-block rules, and restrict access via strict firewall white-lists.",
  },
  infiltration: {
    category: "Privilege Escalation & Lateral Movement",
    description:
      "Unauthorized breach inside internal network boundaries, attempting lateral movement to access sensitive database and control nodes.",
    mitigation:
      "Isolate host VLAN immediately, inspect active user sessions, rotate SSH/API credentials, and perform memory malware analysis.",
  },
  botnet: {
    category: "Command & Control Communication",
    description:
      "Outbound or inbound beaconing to recognized Command & Control (C2) botnet controllers for coordinating distributed attacks or data exfiltration.",
    mitigation:
      "Block destination C2 IP at DNS resolver and perimeter firewall; quarantine the infected client endpoint for forensic imaging.",
  },
};

export default function Incident() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();

  const [alert, setAlert] = useState<Alert | null>(null);
  const [traffic, setTraffic] = useState<TrafficLog | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState("");
  const [toastMessage, setToastMessage] = useState("");
  const [isBlocked, setIsBlocked] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage("");
    }, 3500);
  };

  const loadIncident = useCallback(async () => {
    if (!alertId) {
      setError("No incident ID was provided.");
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError("");

      let selectedAlert: Alert | null = null;
      let selectedTraffic: TrafficLog | null = null;

      try {
        const directRes = await api.get(`/alerts/${alertId}`);
        if (directRes.data?.alert) {
          selectedAlert = directRes.data.alert;
          if (
            selectedAlert?.trafficLogId &&
            typeof selectedAlert.trafficLogId === "object"
          ) {
            selectedTraffic = selectedAlert.trafficLogId as TrafficLog;
          }
        }
      } catch {
        // Fallback to alerts list if single lookup fails
      }

      if (!selectedAlert) {
        const alertsResponse = await api.get("/alerts");
        const alerts: Alert[] = alertsResponse.data.alerts || [];
        selectedAlert = alerts.find((item) => item._id === alertId) || null;
      }

      if (!selectedAlert) {
        setError("Incident alert record was not found.");
        return;
      }

      setAlert(selectedAlert);

      // If trafficLog was only an ID string, fetch full record
      if (!selectedTraffic) {
        const trafficId =
          typeof selectedAlert.trafficLogId === "string"
            ? selectedAlert.trafficLogId
            : (selectedAlert.trafficLogId as any)?._id;

        if (trafficId) {
          try {
            const tRes = await api.get(`/traffic/${trafficId}`);
            selectedTraffic = tRes.data?.traffic || null;
          } catch {
            selectedTraffic = null;
          }
        }
      }

      setTraffic(selectedTraffic);

      // Check if IP is in firewall blocklist
      const srcIP = selectedTraffic?.srcIP;
      if (srcIP) {
        try {
          const settingsRes = await api.get("/settings");
          const blockedList: Array<{ ip: string }> =
            settingsRes.data?.settings?.blockedIPs || [];
          setIsBlocked(blockedList.some((b) => b.ip === srcIP));
        } catch {
          // Non-critical check
        }
      }
    } catch (err: any) {
      console.error("Failed to load incident details:", err);
      setError(
        err.response?.data?.message || "Unable to load incident details."
      );
    } finally {
      setLoading(false);
    }
  }, [alertId]);

  useEffect(() => {
    loadIncident();

    // Listen for live socket updates to this alert
    const handleUpdate = (updatedAlert: Alert) => {
      if (updatedAlert._id === alertId) {
        setAlert((prev) => (prev ? { ...prev, ...updatedAlert } : updatedAlert));
        showToast("Incident status updated by system.");
      }
    };

    const handleDelete = ({ id }: { id: string }) => {
      if (id === alertId) {
        showToast("Incident has been dismissed.");
        setTimeout(() => navigate("/alerts"), 1500);
      }
    };

    socket.on("alert-updated", handleUpdate);
    socket.on("alert-deleted", handleDelete);

    return () => {
      socket.off("alert-updated", handleUpdate);
      socket.off("alert-deleted", handleDelete);
    };
  }, [alertId, loadIncident, navigate]);

  // Update Alert Status
  const handleUpdateStatus = async (
    newStatus: "Unread" | "Read" | "Resolved"
  ) => {
    if (!alert) return;
    try {
      setActionLoading(true);
      await api.put(`/alerts/${alert._id}`, { status: newStatus });
      setAlert((prev) => (prev ? { ...prev, status: newStatus } : null));
      showToast(`Incident marked as ${newStatus}.`);
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to update status.");
    } finally {
      setActionLoading(false);
    }
  };

  // Block Source IP
  const handleBlockIP = async () => {
    const ip = traffic?.srcIP;
    if (!ip) return;

    if (!window.confirm(`Are you sure you want to block IP address ${ip}?`)) {
      return;
    }

    try {
      setActionLoading(true);
      await api.post("/settings/block-ip", {
        ip,
        reason: `Auto-mitigation for ${alert?.attackType || "Intrusion"} incident`,
      });
      setIsBlocked(true);
      showToast(`Firewall block rule active for ${ip}`);
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to block IP.");
    } finally {
      setActionLoading(false);
    }
  };

  // Unblock IP
  const handleUnblockIP = async () => {
    const ip = traffic?.srcIP;
    if (!ip) return;

    try {
      setActionLoading(true);
      await api.post("/settings/unblock-ip", { ip });
      setIsBlocked(false);
      showToast(`IP ${ip} removed from firewall blocklist.`);
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to unblock IP.");
    } finally {
      setActionLoading(false);
    }
  };

  // Delete / Dismiss
  const handleDelete = async () => {
    if (!alert) return;
    if (
      !window.confirm(
        "Are you sure you want to dismiss this incident? This action cannot be undone."
      )
    ) {
      return;
    }

    try {
      setActionLoading(true);
      await api.delete(`/alerts/${alert._id}`);
      showToast("Incident dismissed.");
      setTimeout(() => navigate("/alerts"), 1000);
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to dismiss incident.");
      setActionLoading(false);
    }
  };

  // Export JSON
  const handleExportJson = () => {
    const payload = {
      incidentAlert: alert,
      packetTelemetry: traffic,
      exportedAt: new Date().toISOString(),
    };
    const dataStr =
      "data:text/json;charset=utf-8," +
      encodeURIComponent(JSON.stringify(payload, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `incident-${alert?._id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast("Incident report downloaded.");
  };

  const formatDate = (value?: string) => {
    if (!value) return "-";
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
  };

  const formatBytes = (value?: number) => {
    if (value === undefined || value === null || Number.isNaN(value)) return "-";
    if (value === 0) return "0 Bytes";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(
      Math.floor(Math.log(value) / Math.log(1024)),
      units.length - 1
    );
    return `${(value / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  };

  const formatDuration = (value?: number) => {
    if (value === undefined || value === null || Number.isNaN(value)) return "-";
    return value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value} ms`;
  };

  const formatConfidence = (value?: number) => {
    if (value === undefined || value === null || Number.isNaN(value)) return "-";
    const pct = value <= 1 ? value * 100 : value;
    return `${pct.toFixed(1)}%`;
  };

  // Helper for port service names
  const getPortService = (port?: number) => {
    if (!port) return "";
    const map: Record<number, string> = {
      21: "FTP",
      22: "SSH",
      23: "Telnet",
      25: "SMTP",
      53: "DNS",
      80: "HTTP",
      110: "POP3",
      143: "IMAP",
      443: "HTTPS",
      3306: "MySQL",
      3389: "RDP",
      5432: "PostgreSQL",
      8080: "HTTP-Proxy",
      27017: "MongoDB",
    };
    return map[port] ? `(${map[port]})` : "";
  };

  if (loading) {
    return (
      <div className="incident-page">
        <div className="incident-loading-card">
          <div className="incident-spinner" />
          <p>Querying MongoDB for complete packet telemetry and incident dossier...</p>
        </div>
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="incident-page">
        <div className="incident-error-card">
          <div className="incident-error-icon">⚠️</div>
          <h2>Incident Record Not Found</h2>
          <p>{error || "The requested alert ID does not exist in the database."}</p>
          <button
            className="incident-btn incident-btn-primary"
            onClick={() => navigate("/alerts")}
          >
            ← Return to Intrusion Alerts
          </button>
        </div>
      </div>
    );
  }

  const attackKey = alert.attackType.toLowerCase().trim();
  const attackIntel =
    ATTACK_INFO[attackKey] || {
      category: "Network Intrusion & Anomaly",
      description:
        "Anomalous traffic signature flagged by the AI intrusion detection engine based on extracted flow features.",
      mitigation:
        "Inspect connection duration, verify destination port credentials, and block persistent hostile source IPs.",
    };

  return (
    <div className="incident-page">
      {/* Toast Notification */}
      {toastMessage && <div className="incident-toast">{toastMessage}</div>}

      {/* Header Bar */}
      <div className="incident-header">
        <div className="incident-header-left">
          <button
            className="incident-back-btn"
            onClick={() => navigate("/alerts")}
            title="Return to alerts dashboard"
          >
            ← Back to Alerts
          </button>

          <div className="incident-title-block">
            <div className="incident-title-row">
              <h1 className="incident-title">{alert.attackType}</h1>
              <span
                className={`incident-pill-sev severity-${alert.severity.toLowerCase()}`}
              >
                {alert.severity} Severity
              </span>
              <span
                className={`incident-pill-status status-${alert.status.toLowerCase()}`}
              >
                {alert.status}
              </span>
              {isBlocked && (
                <span className="incident-pill-blocked">
                  🛡️ IP Blocked
                </span>
              )}
            </div>

            <p className="incident-meta-subtitle">
              Incident ID: <code>{alert._id}</code> &bull; Detected:{" "}
              <strong>{formatDate(alert.time || alert.createdAt)}</strong>
            </p>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="incident-action-toolbar">
          {alert.status === "Unread" && (
            <button
              className="incident-btn incident-btn-blue"
              onClick={() => handleUpdateStatus("Read")}
              disabled={actionLoading}
            >
              ✓ Acknowledge (Read)
            </button>
          )}

          {alert.status !== "Resolved" ? (
            <button
              className="incident-btn incident-btn-green"
              onClick={() => handleUpdateStatus("Resolved")}
              disabled={actionLoading}
            >
              🛡️ Mark as Resolved
            </button>
          ) : (
            <button
              className="incident-btn incident-btn-amber"
              onClick={() => handleUpdateStatus("Unread")}
              disabled={actionLoading}
            >
              ↺ Re-open Incident
            </button>
          )}

          {traffic?.srcIP && (
            <>
              {isBlocked ? (
                <button
                  className="incident-btn incident-btn-ghost"
                  onClick={handleUnblockIP}
                  disabled={actionLoading}
                >
                  Unblock Source IP
                </button>
              ) : (
                <button
                  className="incident-btn incident-btn-red"
                  onClick={handleBlockIP}
                  disabled={actionLoading}
                  title="Block this source IP at system firewall"
                >
                  ⛔ Block Attacker IP
                </button>
              )}

              <button
                className="incident-btn incident-btn-purple"
                onClick={() =>
                  navigate(`/traffic-analysis?search=${traffic.srcIP}`)
                }
                title="View all traffic logs involving this IP"
              >
                🔍 Filter in Traffic
              </button>
            </>
          )}

          <button
            className="incident-btn incident-btn-secondary"
            onClick={handleExportJson}
            title="Download telemetry JSON file"
          >
            📥 Export Report
          </button>

          <button
            className="incident-btn incident-btn-delete"
            onClick={handleDelete}
            disabled={actionLoading}
            title="Dismiss incident"
          >
            🗑️
          </button>
        </div>
      </div>

      {/* Main Grid: Telemetry & Threat Intelligence */}
      <div className="incident-grid">
        {/* Left Column: Visual Flow & Deep Telemetry */}
        <div className="incident-left-col">
          {/* Visual Packet Flow Banner */}
          <div className="incident-card flow-banner-card">
            <h3 className="section-title">Network Communication Flow</h3>
            <div className="visual-flow">
              <div className="flow-node source-node">
                <span className="node-type">SOURCE HOST</span>
                <strong className="node-ip">{traffic?.srcIP || "Unknown IP"}</strong>
                <span className="node-port">
                  Port {traffic?.srcPort ?? "N/A"}{" "}
                  {getPortService(traffic?.srcPort)}
                </span>
              </div>

              <div className="flow-connector">
                <span className="flow-protocol">
                  {traffic?.protocol || "TCP/IP"}
                </span>
                <div className="flow-arrow-line">
                  <span className="flow-animated-pulse" />
                </div>
                <span className="flow-attack-tag">{alert.attackType}</span>
              </div>

              <div className="flow-node target-node">
                <span className="node-type">TARGET ENDPOINT</span>
                <strong className="node-ip">{traffic?.dstIP || "Protected Host"}</strong>
                <span className="node-port">
                  Port {traffic?.dstPort ?? "N/A"}{" "}
                  {getPortService(traffic?.dstPort)}
                </span>
              </div>
            </div>
          </div>

          {/* Complete Packet Telemetry Table */}
          <div className="incident-card">
            <h3 className="section-title">Complete Packet Telemetry & Flow Metrics</h3>
            <table className="telemetry-table">
              <tbody>
                <tr>
                  <td className="tel-label">Source IP Address</td>
                  <td className="tel-val tel-mono">
                    <strong>{traffic?.srcIP || "-"}</strong>
                  </td>
                  <td className="tel-label">Destination IP Address</td>
                  <td className="tel-val tel-mono">
                    <strong>{traffic?.dstIP || "-"}</strong>
                  </td>
                </tr>

                <tr>
                  <td className="tel-label">Source Port</td>
                  <td className="tel-val tel-mono">
                    {traffic?.srcPort ?? "-"} {getPortService(traffic?.srcPort)}
                  </td>
                  <td className="tel-label">Destination Port</td>
                  <td className="tel-val tel-mono">
                    {traffic?.dstPort ?? "-"} {getPortService(traffic?.dstPort)}
                  </td>
                </tr>

                <tr>
                  <td className="tel-label">Transport Protocol</td>
                  <td className="tel-val">
                    <span className="protocol-badge">
                      {traffic?.protocol || "TCP"}
                    </span>
                  </td>
                  <td className="tel-label">Flow Duration</td>
                  <td className="tel-val">{formatDuration(traffic?.duration)}</td>
                </tr>

                <tr>
                  <td className="tel-label">Packet Count</td>
                  <td className="tel-val">
                    {traffic?.packets !== undefined
                      ? traffic.packets.toLocaleString()
                      : "-"}
                  </td>
                  <td className="tel-label">Total Data Transferred</td>
                  <td className="tel-val">{formatBytes(traffic?.bytes)}</td>
                </tr>

                <tr>
                  <td className="tel-label">Ground Truth Label</td>
                  <td className="tel-val tel-mono">{traffic?.label || "Unknown"}</td>
                  <td className="tel-label">AI Model Prediction</td>
                  <td className="tel-val">
                    <strong className="prediction-tag">
                      {traffic?.prediction || alert.attackType}
                    </strong>
                  </td>
                </tr>

                <tr>
                  <td className="tel-label">Prediction Confidence</td>
                  <td className="tel-val">
                    <div className="confidence-meter-row">
                      <div className="confidence-meter-bg">
                        <div
                          className="confidence-meter-fill"
                          style={{
                            width: `${
                              (traffic?.confidence
                                ? traffic.confidence <= 1
                                  ? traffic.confidence * 100
                                  : traffic.confidence
                                : 95)
                            }%`,
                          }}
                        />
                      </div>
                      <span className="confidence-pct">
                        {formatConfidence(traffic?.confidence || 0.95)}
                      </span>
                    </div>
                  </td>
                  <td className="tel-label">Telemetry Log Ref</td>
                  <td className="tel-val tel-mono">
                    <code>{traffic?._id || "In-Memory Stream"}</code>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: AI Threat Assessment & Mitigation Guidance */}
        <div className="incident-right-col">
          {/* Threat Assessment Card */}
          <div className="incident-card threat-intel-card">
            <div className="intel-header">
              <span className="intel-icon">🛡️</span>
              <div>
                <h3>Threat Intelligence Assessment</h3>
                <span className="intel-category">{attackIntel.category}</span>
              </div>
            </div>

            <div className="intel-section">
              <h4>Attack Profile</h4>
              <p>{attackIntel.description}</p>
            </div>

            <div className="intel-section">
              <h4>Recommended Defense Strategy</h4>
              <p className="mitigation-text">{attackIntel.mitigation}</p>
            </div>

            <div className="intel-actions-box">
              <h4>Automated Response</h4>
              <p className="intel-subtext">
                Quickly execute defensive actions against this host.
              </p>
              <div className="intel-buttons">
                {traffic?.srcIP && (
                  <button
                    className={`intel-btn ${
                      isBlocked ? "intel-btn-unblock" : "intel-btn-block"
                    }`}
                    onClick={isBlocked ? handleUnblockIP : handleBlockIP}
                  >
                    {isBlocked
                      ? "✓ Attacker IP Blocked (Click to Unblock)"
                      : "⛔ Immediate Firewall Drop (Block IP)"}
                  </button>
                )}
                <button
                  className="intel-btn intel-btn-search"
                  onClick={() =>
                    navigate(
                      `/traffic-analysis?search=${traffic?.srcIP || alert.attackType}`
                    )
                  }
                >
                  Inspect Associated Traffic Flows →
                </button>
              </div>
            </div>
          </div>

          {/* Quick Stats Summary Card */}
          <div className="incident-card audit-card">
            <h3 className="section-title">Audit Information</h3>
            <div className="audit-item">
              <span className="audit-lbl">Incident First Detected</span>
              <strong className="audit-val">
                {formatDate(alert.createdAt || alert.time)}
              </strong>
            </div>
            <div className="audit-item">
              <span className="audit-lbl">Investigation Status</span>
              <span
                className={`incident-pill-status status-${alert.status.toLowerCase()}`}
              >
                {alert.status}
              </span>
            </div>
            <div className="audit-item">
              <span className="audit-lbl">Classification Pipeline</span>
              <span className="audit-val">AI-NIDS Random Forest Classifier</span>
            </div>

            <button
              className="toggle-raw-json-btn"
              onClick={() => setShowRawJson(!showRawJson)}
            >
              {showRawJson ? "Hide Raw JSON Telemetry" : "View Raw JSON Telemetry"}
            </button>
          </div>
        </div>
      </div>

      {/* Collapsible Raw JSON Telemetry */}
      {showRawJson && (
        <div className="incident-card raw-json-card">
          <div className="raw-json-header">
            <h3>Raw Network Telemetry Schema</h3>
            <button
              className="incident-btn incident-btn-secondary"
              onClick={() => {
                navigator.clipboard.writeText(
                  JSON.stringify({ alert, traffic }, null, 2)
                );
                showToast("Telemetry JSON copied to clipboard!");
              }}
            >
              📋 Copy JSON
            </button>
          </div>
          <pre className="raw-json-code">
            {JSON.stringify({ alert, traffic }, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}