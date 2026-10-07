import { useEffect, useMemo, useState, useCallback } from "react";
import api from "../services/api";
import socket from "../services/socket";
import "./TrafficAnalysis.css";

type TrafficLog = {
  _id: string;
  timestamp?: string;
  createdAt?: string;
  srcIP: string;
  dstIP: string;
  protocol: string;
  srcPort?: number;
  dstPort?: number;
  duration?: number;
  bytes?: number;
  packets?: number;
  label?: string;
  prediction?: string;
  confidence?: number;
};

type CsvFile = {
  filename: string;
  sizeBytes: number;
  modified: string;
  rowCount: number;
};

type TrafficStats = {
  totalTraffic: number;
  normalTraffic: number;
  attackTraffic: number;
  attackPercentage: number;
  totalBytes: number;
  totalPackets: number;
  avgDuration: number;
  protocols: { name: string; count: number; value: number }[];
  attackTypes: { name: string; count: number; value: number }[];
  topSourceIPs: { ip: string; requests: number }[];
  topDestPorts: { port: number; count: number }[];
};

const NORMAL_PREDICTIONS = new Set(["BENIGN", "NORMAL"]);

const isNormalTraffic = (prediction?: string) => {
  if (!prediction) return false;
  return NORMAL_PREDICTIONS.has(prediction.trim().toUpperCase());
};


const formatNumber = (value?: number) => {
  if (value === undefined || value === null || Number.isNaN(value)) return "-";
  return value.toLocaleString();
};

const formatBytes = (bytes?: number) => {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  return `${(bytes / Math.pow(1024, index)).toFixed(2)} ${units[index]}`;
};

const formatDuration = (duration?: number) => {
  if (duration === undefined || duration === null || Number.isNaN(duration))
    return "-";
  if (duration >= 1000) return `${(duration / 1000).toFixed(2)}s`;
  return `${duration.toFixed(2)}ms`;
};

const formatConfidence = (confidence?: number) => {
  if (confidence === undefined || confidence === null || Number.isNaN(confidence))
    return "-";
  const percentage = confidence <= 1 ? confidence * 100 : confidence;
  return `${percentage.toFixed(1)}%`;
};

export default function TrafficAnalysis() {
  const [traffic, setTraffic] = useState<TrafficLog[]>([]);
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [csvFiles, setCsvFiles] = useState<CsvFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState("");
  const [error, setError] = useState("");
  const [showCsvModal, setShowCsvModal] = useState(false);

  // Filtering & Search State
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "attack" | "benign">("all");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [attackTypeFilter, setAttackTypeFilter] = useState("all");

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // Fetch all traffic records
  const fetchTraffic = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [trafficRes, statsRes, csvRes] = await Promise.allSettled([
        api.get("/traffic?limit=1000"),
        api.get("/traffic/stats"),
        api.get("/traffic/csv-files"),
      ]);

      if (trafficRes.status === "fulfilled" && trafficRes.value.data?.traffic) {
        setTraffic(trafficRes.value.data.traffic);
      }

      if (statsRes.status === "fulfilled" && statsRes.value.data?.stats) {
        setStats(statsRes.value.data.stats);
      }

      if (csvRes.status === "fulfilled" && csvRes.value.data?.files) {
        setCsvFiles(csvRes.value.data.files);
      }
    } catch (err: any) {
      console.error("Traffic load error:", err);
      setError(
        err.response?.data?.message || "Unable to retrieve traffic analytics data."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  // Sync a CSV file into MongoDB
  const handleSyncCsv = async (filename: string) => {
    try {
      setSyncing(true);
      setSyncMessage("");

      const response = await api.post("/traffic/sync-csv", { filename });

      if (response.data?.success) {
        setSyncMessage(response.data.message);
        // Refresh traffic & stats
        await fetchTraffic();
      }
    } catch (err: any) {
      console.error("Sync error:", err);
      setError(err.response?.data?.message || "Failed to synchronize CSV archive.");
    } finally {
      setSyncing(false);
    }
  };

  // Export current filtered table view as CSV
  const handleExportCsv = () => {
    if (filteredTraffic.length === 0) return;

    const headers = [
      "Timestamp",
      "Source IP",
      "Source Port",
      "Destination IP",
      "Destination Port",
      "Protocol",
      "Duration",
      "Packets",
      "Bytes",
      "Prediction",
      "Confidence",
    ];

    const rows = filteredTraffic.map((item) => [
      item.timestamp || item.createdAt || "",
      item.srcIP || "",
      item.srcPort || 0,
      item.dstIP || "",
      item.dstPort || 0,
      item.protocol || "",
      item.duration || 0,
      item.packets || 0,
      item.bytes || 0,
      item.prediction || item.label || "BENIGN",
      item.confidence || 0,
    ]);

    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute(
      "download",
      `traffic-analysis-export-${new Date().toISOString().slice(0, 10)}.csv`
    );
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  useEffect(() => {
    fetchTraffic();

    // Listen to real-time traffic updates from socket
    const handleTrafficUpdate = (newTraffic: TrafficLog) => {
      setTraffic((prev) => {
        const exists = prev.some((t) => t._id === newTraffic._id);
        if (exists) return prev;
        return [newTraffic, ...prev.slice(0, 999)];
      });
    };

    socket.on("traffic-update", handleTrafficUpdate);

    return () => {
      socket.off("traffic-update", handleTrafficUpdate);
    };
  }, [fetchTraffic]);

  // Extract unique protocols & attack types for dropdowns
  const availableProtocols = useMemo(() => {
    const set = new Set<string>();
    traffic.forEach((t) => {
      if (t.protocol) set.add(t.protocol.toUpperCase());
    });
    return Array.from(set).sort();
  }, [traffic]);

  const availableAttackTypes = useMemo(() => {
    const set = new Set<string>();
    traffic.forEach((t) => {
      const p = t.prediction || t.label;
      if (p && !isNormalTraffic(p) && p !== "Pending") {
        set.add(p);
      }
    });
    return Array.from(set).sort();
  }, [traffic]);

  // Client-side filtering across fields
  const filteredTraffic = useMemo(() => {
    return traffic.filter((item) => {
      // 1. Search term match
      if (searchTerm.trim() !== "") {
        const query = searchTerm.toLowerCase();
        const matchesIP =
          item.srcIP?.toLowerCase().includes(query) ||
          item.dstIP?.toLowerCase().includes(query) ||
          String(item.srcPort || "").includes(query) ||
          String(item.dstPort || "").includes(query);
        const matchesProtocol = item.protocol?.toLowerCase().includes(query);
        const matchesLabel =
          item.label?.toLowerCase().includes(query) ||
          item.prediction?.toLowerCase().includes(query);

        if (!matchesIP && !matchesProtocol && !matchesLabel) {
          return false;
        }
      }

      // 2. Status match (Attack vs Benign)
      const pred = item.prediction || item.label || "BENIGN";
      const isBenign = isNormalTraffic(pred);

      if (statusFilter === "attack" && isBenign) return false;
      if (statusFilter === "benign" && !isBenign) return false;

      // 3. Protocol filter
      if (
        protocolFilter !== "all" &&
        item.protocol?.toUpperCase() !== protocolFilter.toUpperCase()
      ) {
        return false;
      }

      // 4. Attack type filter
      if (attackTypeFilter !== "all") {
        if (pred.toLowerCase() !== attackTypeFilter.toLowerCase()) {
          return false;
        }
      }

      return true;
    });
  }, [traffic, searchTerm, statusFilter, protocolFilter, attackTypeFilter]);

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter, protocolFilter, attackTypeFilter, pageSize]);

  // Paginated records
  const paginatedTraffic = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredTraffic.slice(start, start + pageSize);
  }, [filteredTraffic, currentPage, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filteredTraffic.length / pageSize));

  // Calculated overview stats
  const totalPackets = useMemo(
    () => traffic.reduce((acc, t) => acc + (t.packets || 0), 0),
    [traffic]
  );
  const totalBytes = useMemo(
    () => traffic.reduce((acc, t) => acc + (t.bytes || 0), 0),
    [traffic]
  );
  const attackCount = useMemo(
    () =>
      traffic.filter((t) => !isNormalTraffic(t.prediction || t.label)).length,
    [traffic]
  );
  const benignCount = traffic.length - attackCount;

  return (
    <div className="traffic-page">
      {/* Page Header */}
      <div className="traffic-header">
        <div className="traffic-title-area">
          <h1>Traffic Analysis</h1>
          <p>
            Historical network flow telemetry, deep packet statistics & classification logs
          </p>
        </div>

        {/* Action Controls */}
        <div className="traffic-actions-bar">
          <button
            className="traffic-btn traffic-btn-secondary"
            onClick={() => setShowCsvModal(true)}
            title="Import historical capture CSV archives from ids/Outputs"
          >
            <span>📁</span>
            <span>Historical CSV Archives ({csvFiles.length})</span>
          </button>

          <button
            className="traffic-btn traffic-btn-secondary"
            onClick={handleExportCsv}
            disabled={filteredTraffic.length === 0}
            title="Export filtered records as CSV"
          >
            <span>📥</span>
            <span>Export CSV</span>
          </button>

          <button
            className="traffic-btn traffic-btn-primary"
            onClick={fetchTraffic}
            disabled={loading}
          >
            <span className={loading ? "spin" : ""}>↻</span>
            <span>{loading ? "Refreshing..." : "Refresh"}</span>
          </button>
        </div>
      </div>

      {/* Sync Status Banner */}
      {syncMessage && (
        <div className="traffic-success-banner">
          <span>✅</span>
          <span>{syncMessage}</span>
          <button onClick={() => setSyncMessage("")}>✕</button>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="traffic-error">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="traffic-summary">
        <div className="traffic-card">
          <div className="traffic-card-top">
            <h3>Monitored Flows</h3>
            <span className="traffic-card-badge blue">MongoDB</span>
          </div>
          <strong>{loading ? "..." : traffic.length.toLocaleString()}</strong>
          <span className="traffic-card-sub">Total recorded flow sessions</span>
        </div>

        <div className="traffic-card">
          <div className="traffic-card-top">
            <h3>Total Data Volume</h3>
            <span className="traffic-card-badge">Bandwidth</span>
          </div>
          <strong>{loading ? "..." : formatBytes(totalBytes)}</strong>
          <span className="traffic-card-sub">Combined ingress & egress</span>
        </div>

        <div className="traffic-card">
          <div className="traffic-card-top">
            <h3>Total Packets</h3>
            <span className="traffic-card-badge">Frames</span>
          </div>
          <strong>{loading ? "..." : totalPackets.toLocaleString()}</strong>
          <span className="traffic-card-sub">Network packets evaluated</span>
        </div>

        <div className="traffic-card">
          <div className="traffic-card-top">
            <h3>Threat Classification</h3>
            <span
              className={`traffic-card-badge ${
                attackCount > 0 ? "red" : "green"
              }`}
            >
              {attackCount > 0 ? "Threats Present" : "All Clean"}
            </span>
          </div>
          <strong className={attackCount > 0 ? "threat-alert-text" : "threat-safe-text"}>
            {loading ? "..." : `${benignCount.toLocaleString()} / ${attackCount.toLocaleString()}`}
          </strong>
          <span className="traffic-card-sub">
            Benign vs Detected Malicious Attacks
          </span>
        </div>
      </div>

      {/* Interactive Telemetry & Distribution Grid */}
      <div className="traffic-analytics-grid">
        {/* Protocol Breakdown */}
        <section className="traffic-section">
          <div className="traffic-section-header">
            <div>
              <h2>Protocol Distribution</h2>
              <p>Network transport protocols across recorded flows</p>
            </div>
            <span className="section-pill">Transport Layer</span>
          </div>

          {stats?.protocols && stats.protocols.length > 0 ? (
            <div className="protocol-list">
              {stats.protocols.map((protocol) => (
                <div className="protocol-row" key={protocol.name}>
                  <div className="protocol-label">
                    <span className="protocol-name">{protocol.name}</span>
                    <span className="protocol-val">
                      {protocol.count.toLocaleString()} flows ({protocol.value}%)
                    </span>
                  </div>
                  <div className="protocol-bar">
                    <div
                      className="protocol-fill"
                      style={{ width: `${Math.max(4, protocol.value)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="traffic-empty">No protocol distribution data available.</p>
          )}
        </section>

        {/* Attack Types Distribution */}
        <section className="traffic-section">
          <div className="traffic-section-header">
            <div>
              <h2>Detected Threat Categories</h2>
              <p>Breakdown of AI-classified intrusion patterns</p>
            </div>
            <span className="section-pill red">Intrusions</span>
          </div>

          {stats?.attackTypes && stats.attackTypes.length > 0 ? (
            <div className="attack-type-grid">
              {stats.attackTypes.map((attack) => (
                <div className="attack-type-pill-card" key={attack.name}>
                  <div className="attack-pill-top">
                    <span className="attack-dot red" />
                    <span className="attack-name">{attack.name}</span>
                  </div>
                  <div className="attack-count">
                    {attack.count.toLocaleString()}{" "}
                    <span className="attack-pct">({attack.value}%)</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="clean-system-state">
              <span className="clean-icon">🛡️</span>
              <p>No attack categories detected</p>
              <span>All recorded network sessions are benign.</span>
            </div>
          )}
        </section>
      </div>

      {/* Top Source IPs & Targeted Destination Ports */}
      <div className="traffic-targets-grid">
        {/* Top Source IPs */}
        <section className="traffic-section">
          <div className="traffic-section-header">
            <div>
              <h2>Top Source IPs</h2>
              <p>Host addresses generating the highest traffic</p>
            </div>
          </div>

          {stats?.topSourceIPs && stats.topSourceIPs.length > 0 ? (
            <table className="traffic-table mini-table">
              <thead>
                <tr>
                  <th>Source IP Address</th>
                  <th>Flow Records</th>
                </tr>
              </thead>
              <tbody>
                {stats.topSourceIPs.map((item) => (
                  <tr
                    key={item.ip}
                    className="clickable-ip-row"
                    onClick={() => setSearchTerm(item.ip)}
                    title="Click to filter by this IP"
                  >
                    <td>
                      <span className="ip-badge">{item.ip}</span>
                    </td>
                    <td>{item.requests.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="traffic-empty">No source IP records available.</p>
          )}
        </section>

        {/* Top Targeted Destination Ports */}
        <section className="traffic-section">
          <div className="traffic-section-header">
            <div>
              <h2>Targeted Destination Ports</h2>
              <p>Most frequently accessed service ports</p>
            </div>
          </div>

          {stats?.topDestPorts && stats.topDestPorts.length > 0 ? (
            <table className="traffic-table mini-table">
              <thead>
                <tr>
                  <th>Destination Port</th>
                  <th>Flow Count</th>
                </tr>
              </thead>
              <tbody>
                {stats.topDestPorts.map((item) => (
                  <tr
                    key={item.port}
                    className="clickable-ip-row"
                    onClick={() => setSearchTerm(String(item.port))}
                    title="Click to filter by this port"
                  >
                    <td>
                      <span className="port-badge">Port {item.port}</span>
                    </td>
                    <td>{item.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="traffic-empty">No destination port data available.</p>
          )}
        </section>
      </div>

      {/* Search, Filter & Telemetry Table Section */}
      <section className="traffic-section traffic-table-section">
        <div className="traffic-section-header">
          <div>
            <h2>Traffic Telemetry Records</h2>
            <p>
              Showing {filteredTraffic.length.toLocaleString()} matching records
              out of {traffic.length.toLocaleString()} stored flows
            </p>
          </div>
        </div>

        {/* Filter and Search Toolbar */}
        <div className="traffic-filter-toolbar">
          {/* Search Box */}
          <div className="search-box">
            <span className="search-icon">🔍</span>
            <input
              type="text"
              placeholder="Search by IP, port, protocol, attack type..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
            {searchTerm && (
              <button
                className="clear-search-btn"
                onClick={() => setSearchTerm("")}
              >
                ✕
              </button>
            )}
          </div>

          {/* Status Filter Buttons */}
          <div className="status-filter-group">
            <button
              className={`filter-pill ${statusFilter === "all" ? "active" : ""}`}
              onClick={() => setStatusFilter("all")}
            >
              All Flows
            </button>
            <button
              className={`filter-pill ${
                statusFilter === "attack" ? "active red" : ""
              }`}
              onClick={() => setStatusFilter("attack")}
            >
              Attacks Only ({attackCount})
            </button>
            <button
              className={`filter-pill ${
                statusFilter === "benign" ? "active green" : ""
              }`}
              onClick={() => setStatusFilter("benign")}
            >
              Benign Only ({benignCount})
            </button>
          </div>

          {/* Protocol Dropdown */}
          <select
            className="filter-select"
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
          >
            <option value="all">All Protocols</option>
            {availableProtocols.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>

          {/* Attack Type Dropdown */}
          {availableAttackTypes.length > 0 && (
            <select
              className="filter-select"
              value={attackTypeFilter}
              onChange={(e) => setAttackTypeFilter(e.target.value)}
            >
              <option value="all">All Attack Types</option>
              {availableAttackTypes.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          )}

          {/* Reset Filters */}
          {(searchTerm ||
            statusFilter !== "all" ||
            protocolFilter !== "all" ||
            attackTypeFilter !== "all") && (
            <button
              className="reset-filters-btn"
              onClick={() => {
                setSearchTerm("");
                setStatusFilter("all");
                setProtocolFilter("all");
                setAttackTypeFilter("all");
              }}
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* Table Content */}
        {loading ? (
          <p className="traffic-empty">Loading traffic records...</p>
        ) : filteredTraffic.length === 0 ? (
          <div className="traffic-no-matches">
            <p>No traffic records matching the selected filters.</p>
            <button
              className="traffic-btn traffic-btn-secondary"
              onClick={() => {
                setSearchTerm("");
                setStatusFilter("all");
                setProtocolFilter("all");
                setAttackTypeFilter("all");
              }}
            >
              Clear Filters
            </button>
          </div>
        ) : (
          <>
            <div className="traffic-table-wrapper">
              <table className="traffic-table traffic-table-wide">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Source IP : Port</th>
                    <th>Destination IP : Port</th>
                    <th>Protocol</th>
                    <th>Duration</th>
                    <th>Packets</th>
                    <th>Data</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                  </tr>
                </thead>

                <tbody>
                  {paginatedTraffic.map((item) => {
                    const pred = item.prediction || item.label || "BENIGN";
                    const isNormal = isNormalTraffic(pred);
                    const date = item.timestamp || item.createdAt;

                    return (
                      <tr key={item._id}>
                        <td className="timestamp-col">
                          {date ? new Date(date).toLocaleString() : "-"}
                        </td>

                        <td className="endpoint-col">
                          <span className="ip-text">{item.srcIP}</span>
                          {item.srcPort ? (
                            <span className="port-text">:{item.srcPort}</span>
                          ) : null}
                        </td>

                        <td className="endpoint-col">
                          <span className="ip-text">{item.dstIP}</span>
                          {item.dstPort ? (
                            <span className="port-text">:{item.dstPort}</span>
                          ) : null}
                        </td>

                        <td>
                          <span className="protocol-tag">{item.protocol}</span>
                        </td>

                        <td>{formatDuration(item.duration)}</td>
                        <td>{formatNumber(item.packets)}</td>
                        <td>{formatBytes(item.bytes)}</td>

                        <td>
                          <span
                            className={`traffic-prediction ${
                              isNormal ? "traffic-benign" : "traffic-attack"
                            }`}
                          >
                            {!isNormal && <span className="threat-bullet" />}
                            {isNormal ? "BENIGN / Normal" : pred}
                          </span>
                        </td>

                        <td>{formatConfidence(item.confidence)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination Toolbar */}
            <div className="traffic-pagination-bar">
              <div className="pagination-info">
                Showing{" "}
                <strong>
                  {(currentPage - 1) * pageSize + 1} -{" "}
                  {Math.min(currentPage * pageSize, filteredTraffic.length)}
                </strong>{" "}
                of <strong>{filteredTraffic.length}</strong> flows
              </div>

              <div className="pagination-controls">
                <select
                  className="page-size-select"
                  value={pageSize}
                  onChange={(e) => setPageSize(Number(e.target.value))}
                >
                  <option value={15}>15 rows</option>
                  <option value={25}>25 rows</option>
                  <option value={50}>50 rows</option>
                  <option value={100}>100 rows</option>
                </select>

                <button
                  className="page-nav-btn"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  ◀ Prev
                </button>

                <span className="page-indicator">
                  Page {currentPage} of {totalPages}
                </span>

                <button
                  className="page-nav-btn"
                  onClick={() =>
                    setCurrentPage((p) => Math.min(totalPages, p + 1))
                  }
                  disabled={currentPage === totalPages}
                >
                  Next ▶
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      {/* Historical CSV Archives Modal */}
      {showCsvModal && (
        <div
          className="csv-modal-backdrop"
          onClick={() => setShowCsvModal(false)}
        >
          <div
            className="csv-modal-content"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="csv-modal-header">
              <div>
                <h2>Historical CSV Capture Archives</h2>
                <p>
                  Synchronize raw packet capture CSV files from{" "}
                  <code>ids/Outputs</code> directly into MongoDB
                </p>
              </div>
              <button
                className="close-modal-btn"
                onClick={() => setShowCsvModal(false)}
              >
                ✕
              </button>
            </div>

            <div className="csv-file-list">
              {csvFiles.length === 0 ? (
                <div className="no-csvs-state">
                  <p>No CSV capture archives found in <code>ids/Outputs</code>.</p>
                </div>
              ) : (
                csvFiles.map((file) => (
                  <div className="csv-file-item" key={file.filename}>
                    <div className="csv-file-details">
                      <span className="csv-icon">📄</span>
                      <div>
                        <strong>{file.filename}</strong>
                        <div className="csv-meta">
                          <span>{file.rowCount.toLocaleString()} flows</span>
                          <span>•</span>
                          <span>{formatBytes(file.sizeBytes)}</span>
                          <span>•</span>
                          <span>
                            {new Date(file.modified).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                    </div>

                    <button
                      className="csv-sync-btn"
                      onClick={() => handleSyncCsv(file.filename)}
                      disabled={syncing}
                    >
                      {syncing ? "Syncing..." : "Sync into MongoDB"}
                    </button>
                  </div>
                ))
              )}
            </div>

            <div className="csv-modal-footer">
              <button
                className="traffic-btn traffic-btn-primary"
                onClick={() => handleSyncCsv("all")}
                disabled={syncing || csvFiles.length === 0}
              >
                {syncing ? "Syncing All Files..." : "Sync All Historical CSVs"}
              </button>
              <button
                className="traffic-btn traffic-btn-secondary"
                onClick={() => setShowCsvModal(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
