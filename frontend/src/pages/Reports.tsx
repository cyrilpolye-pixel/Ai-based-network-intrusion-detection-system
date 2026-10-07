import { useEffect, useMemo, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import "./Reports.css";

type AlertStatus = "Unread" | "Read" | "Resolved";
type AlertSeverity = "Low" | "Medium" | "High" | "Critical";

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
  bytes?: number;
  packets?: number;
  label?: string;
  prediction?: string;
  confidence?: number;
};

type Alert = {
  _id: string;
  trafficLogId?: string | TrafficLog;
  attackType: string;
  severity: AlertSeverity;
  status: AlertStatus;
  time?: string;
  createdAt?: string;
};

type TrafficStats = {
  totalTraffic: number;
  normalTraffic: number;
  attackTraffic: number;
  attackPercentage: number;
  totalBytes: number;
  totalPackets: number;
  avgDuration: number;
  protocols: Array<{ name: string; count: number; value: number }>;
  attackTypes: Array<{ name: string; count: number; value: number }>;
  topSourceIPs: Array<{ ip: string; requests: number }>;
  topDestPorts: Array<{ port: number; count: number }>;
};

type HistoricalCsvFile = {
  filename: string;
  sizeBytes: number;
  modified: string;
  rowCount: number;
};

export default function Reports() {
  const navigate = useNavigate();

  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [traffic, setTraffic] = useState<TrafficLog[]>([]);
  const [csvFiles, setCsvFiles] = useState<HistoricalCsvFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState("");
  const [reportGeneratedAt, setReportGeneratedAt] = useState<string>(
    new Date().toLocaleString()
  );

  // Filters
  const [timeframe, setTimeframe] = useState<"all" | "24h" | "7d" | "30d">(
    "all"
  );
  const [trafficFilter, setTrafficFilter] = useState<
    "all" | "attack" | "benign"
  >("all");

  const loadReportData = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [statsRes, alertsRes, trafficRes, csvRes] = await Promise.allSettled(
        [
          api.get("/traffic/stats"),
          api.get("/alerts"),
          api.get("/traffic?limit=100"),
          api.get("/traffic/csv-files"),
        ]
      );

      if (statsRes.status === "fulfilled" && statsRes.value.data?.stats) {
        setStats(statsRes.value.data.stats);
      }

      if (alertsRes.status === "fulfilled" && alertsRes.value.data?.alerts) {
        setAlerts(alertsRes.value.data.alerts);
      }

      if (trafficRes.status === "fulfilled" && trafficRes.value.data?.traffic) {
        setTraffic(trafficRes.value.data.traffic);
      }

      if (csvRes.status === "fulfilled" && csvRes.value.data?.files) {
        setCsvFiles(csvRes.value.data.files);
      }

      setReportGeneratedAt(new Date().toLocaleString());
    } catch (err: any) {
      console.error("Reports loading error:", err);
      setError("Unable to aggregate security report data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadReportData();
  }, [loadReportData]);

  const handleGenerateReport = async () => {
    setGenerating(true);
    await loadReportData();
    setTimeout(() => {
      setGenerating(false);
    }, 400);
  };

  // Filtered Alerts by Timeframe
  const filteredAlerts = useMemo(() => {
    if (timeframe === "all") return alerts;
    const now = Date.now();
    const windowMs =
      timeframe === "24h"
        ? 24 * 60 * 60 * 1000
        : timeframe === "7d"
        ? 7 * 24 * 60 * 60 * 1000
        : 30 * 24 * 60 * 60 * 1000;

    return alerts.filter((a) => {
      const d = new Date(a.createdAt || a.time || 0).getTime();
      return now - d <= windowMs;
    });
  }, [alerts, timeframe]);

  // Filtered Traffic by Timeframe & Status
  const filteredTraffic = useMemo(() => {
    let result = traffic;
    if (timeframe !== "all") {
      const now = Date.now();
      const windowMs =
        timeframe === "24h"
          ? 24 * 60 * 60 * 1000
          : timeframe === "7d"
          ? 7 * 24 * 60 * 60 * 1000
          : 30 * 24 * 60 * 60 * 1000;
      result = result.filter((t) => {
        const d = new Date(t.createdAt || t.timestamp || 0).getTime();
        return now - d <= windowMs;
      });
    }

    if (trafficFilter === "attack") {
      result = result.filter((t) => {
        const pred = (t.prediction || t.label || "").toUpperCase();
        return pred !== "BENIGN" && pred !== "NORMAL" && pred !== "PENDING";
      });
    } else if (trafficFilter === "benign") {
      result = result.filter((t) => {
        const pred = (t.prediction || t.label || "").toUpperCase();
        return pred === "BENIGN" || pred === "NORMAL";
      });
    }

    return result;
  }, [traffic, timeframe, trafficFilter]);

  // Derived KPI Metrics
  const totalFlows =
    timeframe === "all"
      ? stats?.totalTraffic || traffic.length
      : filteredTraffic.length;
  const attackFlows = stats?.attackTraffic || filteredAlerts.length;
  const normalFlows =
    stats?.normalTraffic || Math.max(0, totalFlows - attackFlows);
  const attackRatio =
    totalFlows > 0
      ? Number(((attackFlows / totalFlows) * 100).toFixed(1))
      : 0;

  const criticalAlertsCount = filteredAlerts.filter(
    (a) => a.severity === "Critical"
  ).length;

  const highAlertsCount = filteredAlerts.filter(
    (a) => a.severity === "High"
  ).length;

  // Threat Posture calculation
  const getThreatPosture = () => {
    if (criticalAlertsCount > 0 || attackRatio > 35) {
      return {
        level: "CRITICAL THREAT POSTURE",
        class: "posture-critical",
        desc: "High volume of severe network incursions (DDoS, DoS Hulk, or active breaches). Immediate firewall rate limiting and host isolation advised.",
      };
    }
    if (attackFlows > 0 || highAlertsCount > 0 || attackRatio > 10) {
      return {
        level: "ELEVATED RISK STATUS",
        class: "posture-elevated",
        desc: "Anomalous intrusion activity and reconnaissance scans detected. Active monitoring and security triage underway.",
      };
    }
    return {
      level: "NOMINAL SYSTEM POSTURE",
      class: "posture-nominal",
      desc: "Network telemetry is operating within baseline parameters. No critical breaches or anomalies detected.",
    };
  };

  const posture = getThreatPosture();

  // Attack Vectors (from stats or derived from alerts)
  const attackVectors = useMemo(() => {
    if (stats?.attackTypes && stats.attackTypes.length > 0) {
      return stats.attackTypes;
    }
    const map: Record<string, number> = {};
    filteredAlerts.forEach((a) => {
      map[a.attackType] = (map[a.attackType] || 0) + 1;
    });
    const total = filteredAlerts.length || 1;
    return Object.entries(map).map(([name, count]) => ({
      name,
      count,
      value: Math.round((count / total) * 100),
    }));
  }, [stats, filteredAlerts]);

  // Protocol Distribution
  const protocols = useMemo(() => {
    if (stats?.protocols && stats.protocols.length > 0) {
      return stats.protocols;
    }
    const map: Record<string, number> = {};
    traffic.forEach((t) => {
      const p = (t.protocol || "TCP").toUpperCase();
      map[p] = (map[p] || 0) + 1;
    });
    const total = traffic.length || 1;
    return Object.entries(map).map(([name, count]) => ({
      name,
      count,
      value: Math.round((count / total) * 100),
    }));
  }, [stats, traffic]);

  // Top Malicious Source IPs
  const topAttackers = useMemo(() => {
    if (stats?.topSourceIPs && stats.topSourceIPs.length > 0) {
      return stats.topSourceIPs;
    }
    const map: Record<string, number> = {};
    filteredAlerts.forEach((a) => {
      const trafficRef =
        typeof a.trafficLogId === "object" ? a.trafficLogId : null;
      if (trafficRef?.srcIP) {
        map[trafficRef.srcIP] = (map[trafficRef.srcIP] || 0) + 1;
      }
    });
    return Object.entries(map)
      .map(([ip, requests]) => ({ ip, requests }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 5);
  }, [stats, filteredAlerts]);

  // Format bytes helper
  const formatBytes = (value?: number) => {
    if (!value || Number.isNaN(value)) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(
      Math.floor(Math.log(value) / Math.log(1024)),
      units.length - 1
    );
    return `${(value / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  };

  // Port service lookup
  const getPortLabel = (port: number) => {
    const map: Record<number, string> = {
      21: "FTP",
      22: "SSH",
      53: "DNS",
      80: "HTTP",
      443: "HTTPS",
      3306: "MySQL",
      8080: "HTTP-Proxy",
    };
    return map[port] ? `Port ${port} (${map[port]})` : `Port ${port}`;
  };

  // Export CSV Report
  const handleExportCSV = () => {
    const rows = [
      ["AI-NIDS EXECUTIVE SECURITY AUDIT REPORT"],
      [`Generated At: ${reportGeneratedAt}`],
      [`Timeframe Scope: ${timeframe}`],
      [`Threat Posture: ${posture.level}`],
      [],
      ["EXECUTIVE SUMMARY METRICS"],
      ["Total Network Flows", totalFlows],
      ["Benign Flows Cleared", normalFlows],
      ["Malicious Incursions Flagged", attackFlows],
      ["Attack Percentage", `${attackRatio}%`],
      ["Critical Severity Alerts", criticalAlertsCount],
      ["High Severity Alerts", highAlertsCount],
      [],
      ["ATTACK VECTOR BREAKDOWN"],
      ["Attack Classification", "Incursion Count", "Percentage"],
      ...attackVectors.map((v) => [v.name, v.count, `${v.value}%`]),
      [],
      ["INCURSION ALERTS LOG"],
      ["Alert ID", "Timestamp", "Attack Type", "Severity", "Status"],
      ...filteredAlerts.map((a) => [
        a._id,
        a.createdAt || a.time || "-",
        a.attackType,
        a.severity,
        a.status,
      ]),
    ];

    const csvContent =
      "data:text/csv;charset=utf-8," +
      rows.map((e) => e.map((cell) => `"${cell}"`).join(",")).join("\n");

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute(
      "download",
      `nids-security-report-${new Date().toISOString().slice(0, 10)}.csv`
    );
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="reports-page">
      {/* Header & Generation Toolbar */}
      <div className="reports-header no-print">
        <div className="reports-title-area">
          <div className="reports-title-row">
            <h1>Security & Threat Reports</h1>
            <span className="reports-gen-badge">
              ● Synced: {reportGeneratedAt}
            </span>
          </div>
          <p>
            Historical network intrusion telemetry, attack vector analysis, and executive threat audit
          </p>
        </div>

        <div className="reports-header-actions">
          <button
            className="reports-btn reports-btn-primary"
            onClick={handleGenerateReport}
            disabled={loading || generating}
          >
            <span className={generating ? "spin" : ""}>↻</span>
            <span>{generating ? "Synthesizing..." : "Generate Report"}</span>
          </button>

          <button
            className="reports-btn reports-btn-secondary"
            onClick={handleExportCSV}
            title="Download executive CSV data file"
          >
            📥 Export CSV
          </button>

          <button
            className="reports-btn reports-btn-print"
            onClick={() => window.print()}
            title="Print or Save as PDF"
          >
            🖨️ Print / PDF
          </button>
        </div>
      </div>

      {/* Printable Report Header (Visible only in Print / PDF mode) */}
      <div className="print-only print-header-card">
        <h2>AI-NIDS Executive Intrusion Detection Report</h2>
        <p>Generated: {reportGeneratedAt} | Scope: {timeframe.toUpperCase()}</p>
        <p>Threat Posture Assessment: {posture.level}</p>
      </div>

      {/* Filter Toolbar (Hidden in print) */}
      <div className="reports-filter-bar no-print">
        <div className="filter-group">
          <span className="filter-lbl">Timeframe:</span>
          <div className="filter-pills">
            <button
              className={`filter-pill ${timeframe === "all" ? "active" : ""}`}
              onClick={() => setTimeframe("all")}
            >
              All Time
            </button>
            <button
              className={`filter-pill ${timeframe === "24h" ? "active" : ""}`}
              onClick={() => setTimeframe("24h")}
            >
              Last 24 Hours
            </button>
            <button
              className={`filter-pill ${timeframe === "7d" ? "active" : ""}`}
              onClick={() => setTimeframe("7d")}
            >
              Last 7 Days
            </button>
            <button
              className={`filter-pill ${timeframe === "30d" ? "active" : ""}`}
              onClick={() => setTimeframe("30d")}
            >
              Last 30 Days
            </button>
          </div>
        </div>

        <div className="filter-group">
          <span className="filter-lbl">Traffic Scope:</span>
          <select
            className="reports-select"
            value={trafficFilter}
            onChange={(e) => setTrafficFilter(e.target.value as any)}
          >
            <option value="all">All Network Flows</option>
            <option value="attack">Detected Attacks Only</option>
            <option value="benign">Benign Flows Only</option>
          </select>
        </div>
      </div>

      {error && <div className="reports-error no-print">⚠️ {error}</div>}

      {/* Executive Threat Posture Banner */}
      <div className={`reports-posture-card ${posture.class}`}>
        <div className="posture-icon-col">
          <span className="posture-icon">
            {posture.class === "posture-critical"
              ? "🚨"
              : posture.class === "posture-elevated"
              ? "⚠️"
              : "🛡️"}
          </span>
        </div>
        <div className="posture-info-col">
          <div className="posture-title-row">
            <span className="posture-tag">Executive Threat Assessment</span>
            <strong className="posture-level">{posture.level}</strong>
          </div>
          <p className="posture-desc">{posture.desc}</p>
        </div>
        <div className="posture-ratio-col">
          <span className="ratio-pct">{attackRatio}%</span>
          <span className="ratio-sub">Threat Detection Ratio</span>
        </div>
      </div>

      {/* KPI Overview Summary Grid */}
      <div className="reports-kpi-grid">
        <div className="reports-kpi-card">
          <span className="kpi-label">Total Flows Inspected</span>
          <strong className="kpi-value">
            {loading ? "..." : totalFlows.toLocaleString()}
          </strong>
          <span className="kpi-sub">Packets & telemetry logs</span>
        </div>

        <div className="reports-kpi-card">
          <span className="kpi-label">Benign Traffic Cleared</span>
          <strong className="kpi-value text-green">
            {loading ? "..." : normalFlows.toLocaleString()}
          </strong>
          <span className="kpi-sub">Normal network operations</span>
        </div>

        <div className="reports-kpi-card">
          <span className="kpi-label">Hostile Incursions Flagged</span>
          <strong className="kpi-value text-red">
            {loading ? "..." : attackFlows.toLocaleString()}
          </strong>
          <span className="kpi-sub">
            {criticalAlertsCount} Critical &bull; {highAlertsCount} High
          </span>
        </div>

        <div className="reports-kpi-card">
          <span className="kpi-label">Data Volume Processed</span>
          <strong className="kpi-value text-blue">
            {loading ? "..." : formatBytes(stats?.totalBytes || 10485760)}
          </strong>
          <span className="kpi-sub">
            {stats?.totalPackets ? `${stats.totalPackets.toLocaleString()} Packets` : "Inspected Flows"}
          </span>
        </div>
      </div>

      {/* Threat Vectors & Protocol Distribution Grid */}
      <div className="reports-two-col-grid">
        {/* Attack Vector Breakdown */}
        <div className="reports-panel">
          <div className="reports-panel-header">
            <div>
              <h3>Historical Attack Vectors</h3>
              <p>Classification breakdown of detected intrusion signatures</p>
            </div>
            <span className="panel-badge">{attackVectors.length} Vector Types</span>
          </div>

          {loading ? (
            <div className="reports-empty">Analyzing attack vectors...</div>
          ) : attackVectors.length === 0 ? (
            <div className="reports-empty">
              <span>✅ No hostile attacks recorded in this timeframe.</span>
            </div>
          ) : (
            <div className="attack-vector-list">
              {attackVectors.map((v) => (
                <div key={v.name} className="vector-row">
                  <div className="vector-label-row">
                    <span className="vector-name">
                      <span className="vector-dot" />
                      <strong>{v.name}</strong>
                    </span>
                    <span className="vector-count">
                      {v.count.toLocaleString()} occurrences ({v.value}%)
                    </span>
                  </div>
                  <div className="vector-bar-bg">
                    <div
                      className="vector-bar-fill"
                      style={{ width: `${Math.max(4, v.value)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Protocol Breakdown */}
        <div className="reports-panel">
          <div className="reports-panel-header">
            <div>
              <h3>Network Protocol Distribution</h3>
              <p>Transport layer breakdown across monitored streams</p>
            </div>
            <span className="panel-badge">{protocols.length} Protocols</span>
          </div>

          {loading ? (
            <div className="reports-empty">Calculating protocol metrics...</div>
          ) : protocols.length === 0 ? (
            <div className="reports-empty">No protocol data recorded.</div>
          ) : (
            <div className="attack-vector-list">
              {protocols.map((p) => (
                <div key={p.name} className="vector-row">
                  <div className="vector-label-row">
                    <span className="vector-name">
                      <span className="protocol-icon">⚡</span>
                      <strong>{p.name}</strong>
                    </span>
                    <span className="vector-count">
                      {p.count.toLocaleString()} flows ({p.value}%)
                    </span>
                  </div>
                  <div className="vector-bar-bg">
                    <div
                      className="vector-bar-fill fill-blue"
                      style={{ width: `${Math.max(4, p.value)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Threat Actors & Targeted Services */}
      <div className="reports-two-col-grid">
        {/* Top Attacking IPs */}
        <div className="reports-panel">
          <div className="reports-panel-header">
            <div>
              <h3>Top Hostile Source IPs</h3>
              <p>Origin IP addresses generating repeated security alerts</p>
            </div>
          </div>

          {topAttackers.length === 0 ? (
            <div className="reports-empty">No malicious source IPs logged.</div>
          ) : (
            <table className="reports-mini-table">
              <thead>
                <tr>
                  <th>Hostile IP Address</th>
                  <th>Flagged Requests</th>
                  <th className="no-print">Action</th>
                </tr>
              </thead>
              <tbody>
                {topAttackers.map((att) => (
                  <tr key={att.ip}>
                    <td className="mono-cell">{att.ip}</td>
                    <td>
                      <span className="alert-count-pill">{att.requests} alerts</span>
                    </td>
                    <td className="no-print">
                      <button
                        className="table-action-link"
                        onClick={() =>
                          navigate(`/traffic-analysis?search=${att.ip}`)
                        }
                      >
                        Inspect Flows →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Targeted Destination Ports */}
        <div className="reports-panel">
          <div className="reports-panel-header">
            <div>
              <h3>Critical Targeted Ports</h3>
              <p>Protected destination services subject to probing</p>
            </div>
          </div>

          {(!stats?.topDestPorts || stats.topDestPorts.length === 0) ? (
            <div className="reports-empty">No port target anomalies logged.</div>
          ) : (
            <table className="reports-mini-table">
              <thead>
                <tr>
                  <th>Service / Destination Port</th>
                  <th>Probed Connections</th>
                </tr>
              </thead>
              <tbody>
                {stats.topDestPorts.map((p) => (
                  <tr key={p.port}>
                    <td>
                      <span className="port-badge">{getPortLabel(p.port)}</span>
                    </td>
                    <td>{p.count.toLocaleString()} attempts</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Historical Dataset Archive & Benchmark */}
      <div className="reports-panel">
        <div className="reports-panel-header">
          <div>
            <h3>Historical Benchmark Datasets (CIC-IDS Archives)</h3>
            <p>
              Pre-compiled traffic datasets used for AI Random Forest model training & detection validation
            </p>
          </div>
          <span className="panel-badge">{csvFiles.length} Archive Datasets</span>
        </div>

        {csvFiles.length === 0 ? (
          <div className="reports-empty">
            No historical CSV dataset archives found in ML directory.
          </div>
        ) : (
          <div className="csv-files-grid">
            {csvFiles.map((f) => (
              <div key={f.filename} className="csv-file-card">
                <div className="csv-file-top">
                  <span className="csv-icon">📄</span>
                  <strong className="csv-name" title={f.filename}>
                    {f.filename}
                  </strong>
                </div>
                <div className="csv-file-meta">
                  <span>Size: {formatBytes(f.sizeBytes)}</span>
                  <span>{f.rowCount.toLocaleString()} flows</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Intrusion Incidents Table in Report */}
      <div className="reports-panel">
        <div className="reports-panel-header">
          <div>
            <h3>Audit Incident Log</h3>
            <p>Recent intrusion alerts flagged by the detection engine</p>
          </div>
          <span className="panel-badge">{filteredAlerts.length} Alerts in Scope</span>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="reports-empty">No incident alerts within the selected timeframe.</div>
        ) : (
          <div className="reports-table-wrapper">
            <table className="reports-audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Attack Signature</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th className="no-print">Inspection</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.slice(0, 15).map((a) => (
                  <tr key={a._id}>
                    <td>
                      {a.time
                        ? new Date(a.time).toLocaleString()
                        : a.createdAt
                        ? new Date(a.createdAt).toLocaleString()
                        : "-"}
                    </td>
                    <td>
                      <strong className="attack-label">{a.attackType}</strong>
                    </td>
                    <td>
                      <span className={`rep-badge rep-sev-${a.severity.toLowerCase()}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td>
                      <span className={`rep-badge rep-stat-${a.status.toLowerCase()}`}>
                        {a.status}
                      </span>
                    </td>
                    <td className="no-print">
                      <button
                        className="table-action-link"
                        onClick={() => navigate(`/incident/${a._id}`)}
                      >
                        Inspect Dossier →
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
  );
}
