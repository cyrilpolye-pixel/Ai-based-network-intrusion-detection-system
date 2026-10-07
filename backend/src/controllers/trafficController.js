const fs = require("fs");
const path = require("path");
const TrafficLog = require("../models/TrafficLog");
const Alert = require("../models/Alert");
const { getIO } = require("../socket/socket");

// Helper: Determine severity for detected attacks
const getSeverity = (attackType = "") => {
  const type = String(attackType).toLowerCase();
  if (type.includes("ddos") || type.includes("dos hulk") || type.includes("botnet")) {
    return "Critical";
  }
  if (type.includes("portscan") || type.includes("brute") || type.includes("patator")) {
    return "High";
  }
  if (type.includes("dos") || type.includes("slowloris") || type.includes("goldeneye")) {
    return "High";
  }
  return "Medium";
};

// Helper: Check whether a prediction/label represents an attack
const isAttack = (prediction = "", label = "") => {
  const p = String(prediction || "").trim().toLowerCase();
  const l = String(label || "").trim().toLowerCase();
  const nonAttacks = new Set(["benign", "normal", "unknown", "pending", ""]);
  return !nonAttacks.has(p) || !nonAttacks.has(l);
};

// Locate ids/Outputs directory
const getCsvOutputDir = () => {
  const candidate = path.resolve(__dirname, "../../../ids/Outputs");
  if (fs.existsSync(candidate)) return candidate;
  return null;
};

// ============================================================
// 1. GET ALL TRAFFIC LOGS (With Search, Filtering & Pagination)
// ============================================================
const getTrafficLogs = async (req, res) => {
  try {
    const {
      search,
      status, // 'all', 'attack', 'benign'
      protocol, // 'all', 'TCP', 'UDP', etc.
      attackType, // specific attack type
      page = 1,
      limit = 50,
      sortBy = "timestamp",
      sortOrder = "desc",
    } = req.query;

    const query = {};

    // Text search across IP addresses, protocol, prediction, and label
    if (search && search.trim() !== "") {
      const escaped = search.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const searchRegex = new RegExp(escaped, "i");
      query.$or = [
        { srcIP: searchRegex },
        { dstIP: searchRegex },
        { protocol: searchRegex },
        { prediction: searchRegex },
        { label: searchRegex },
      ];
    }

    // Status filter (Attack vs Benign)
    if (status === "attack") {
      query.prediction = {
        $nin: [/^benign$/i, /^normal$/i, /^pending$/i, /^unknown$/i],
      };
    } else if (status === "benign") {
      query.prediction = {
        $in: [/^benign$/i, /^normal$/i],
      };
    }

    // Protocol filter
    if (protocol && protocol.toLowerCase() !== "all") {
      query.protocol = new RegExp(`^${protocol}$`, "i");
    }

    // Specific attack type filter
    if (attackType && attackType.toLowerCase() !== "all") {
      query.prediction = new RegExp(attackType, "i");
    }

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(0, parseInt(limit, 10) || 50);
    const sortDirection = sortOrder === "asc" ? 1 : -1;
    const sortField = sortBy === "createdAt" ? "createdAt" : "timestamp";

    const total = await TrafficLog.countDocuments(query);

    let trafficQuery = TrafficLog.find(query).sort({
      [sortField]: sortDirection,
      _id: sortDirection,
    });

    if (limitNum > 0) {
      trafficQuery = trafficQuery.skip((pageNum - 1) * limitNum).limit(limitNum);
    }

    const traffic = await trafficQuery.exec();

    return res.status(200).json({
      success: true,
      count: traffic.length,
      total,
      page: pageNum,
      totalPages: limitNum > 0 ? Math.ceil(total / limitNum) : 1,
      traffic,
    });
  } catch (error) {
    console.error("Traffic retrieval error:", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// ============================================================
// 2. GET COMPREHENSIVE TRAFFIC STATISTICS
// ============================================================
const getTrafficStats = async (req, res) => {
  try {
    const totalTraffic = await TrafficLog.countDocuments();

    // Benign count
    const normalTraffic = await TrafficLog.countDocuments({
      $or: [
        { prediction: { $regex: /^(benign|normal)$/i } },
        { label: { $regex: /^(benign|normal)$/i } },
      ],
    });

    const attackTraffic = Math.max(0, totalTraffic - normalTraffic);

    // Protocol breakdown
    const protocolStats = await TrafficLog.aggregate([
      {
        $group: {
          _id: { $toUpper: "$protocol" },
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
    ]);

    // Attack types breakdown
    const attackTypeStats = await TrafficLog.aggregate([
      {
        $match: {
          prediction: {
            $nin: [/^benign$/i, /^normal$/i, /^pending$/i, /^unknown$/i],
          },
        },
      },
      {
        $group: {
          _id: "$prediction",
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
    ]);

    // Top Source IPs
    const topSourceIPs = await TrafficLog.aggregate([
      {
        $group: {
          _id: "$srcIP",
          requests: { $sum: 1 },
        },
      },
      { $sort: { requests: -1 } },
      { $limit: 5 },
    ]);

    // Top Destination Ports
    const topDestPorts = await TrafficLog.aggregate([
      {
        $match: {
          dstPort: { $gt: 0 },
        },
      },
      {
        $group: {
          _id: "$dstPort",
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);

    // Volume sums (Packets and Bytes)
    const metrics = await TrafficLog.aggregate([
      {
        $group: {
          _id: null,
          totalBytes: { $sum: "$bytes" },
          totalPackets: { $sum: "$packets" },
          avgDuration: { $avg: "$duration" },
        },
      },
    ]);

    const totalBytes = metrics[0]?.totalBytes || 0;
    const totalPackets = metrics[0]?.totalPackets || 0;
    const avgDuration = metrics[0]?.avgDuration || 0;

    return res.status(200).json({
      success: true,
      stats: {
        totalTraffic,
        normalTraffic,
        attackTraffic,
        attackPercentage:
          totalTraffic > 0
            ? Number(((attackTraffic / totalTraffic) * 100).toFixed(2))
            : 0,
        totalBytes,
        totalPackets,
        avgDuration: Number(avgDuration.toFixed(2)),
        protocols: protocolStats.map((p) => ({
          name: p._id || "UNKNOWN",
          count: p.count,
          value:
            totalTraffic > 0 ? Math.round((p.count / totalTraffic) * 100) : 0,
        })),
        attackTypes: attackTypeStats.map((a) => ({
          name: a._id || "Unclassified",
          count: a.count,
          value:
            attackTraffic > 0 ? Math.round((a.count / attackTraffic) * 100) : 0,
        })),
        topSourceIPs: topSourceIPs.map((s) => ({
          ip: s._id || "Unknown",
          requests: s.requests,
        })),
        topDestPorts: topDestPorts.map((p) => ({
          port: p._id,
          count: p.count,
        })),
      },
    });
  } catch (error) {
    console.error("Traffic stats calculation error:", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// ============================================================
// 3. LIST AVAILABLE HISTORICAL CSV FILES
// ============================================================
const getHistoricalCsvFiles = async (req, res) => {
  try {
    const outputDir = getCsvOutputDir();

    if (!outputDir) {
      return res.status(200).json({
        success: true,
        files: [],
        message: "No CSV output directory found.",
      });
    }

    const allFiles = fs.readdirSync(outputDir);
    const csvFiles = allFiles
      .filter((file) => file.endsWith(".csv"))
      .map((filename) => {
        const fullPath = path.join(outputDir, filename);
        const stats = fs.statSync(fullPath);

        // Count non-empty lines
        let rowCount = 0;
        try {
          const content = fs.readFileSync(fullPath, "utf8");
          const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
          rowCount = Math.max(0, lines.length - 1);
        } catch {
          rowCount = 0;
        }

        return {
          filename,
          sizeBytes: stats.size,
          modified: stats.mtime,
          rowCount,
        };
      })
      .sort((a, b) => new Date(b.modified) - new Date(a.modified));

    return res.status(200).json({
      success: true,
      count: csvFiles.length,
      files: csvFiles,
    });
  } catch (error) {
    console.error("Failed to read CSV files:", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// ============================================================
// 4. SYNC HISTORICAL CSV TO MONGODB
// ============================================================
const syncCsvToMongo = async (req, res) => {
  try {
    const { filename } = req.body;
    const outputDir = getCsvOutputDir();

    if (!outputDir) {
      return res.status(404).json({
        success: false,
        message: "CSV output directory not found.",
      });
    }

    let filesToProcess = [];
    if (filename && filename !== "all") {
      const targetPath = path.join(outputDir, filename);
      if (!fs.existsSync(targetPath)) {
        return res.status(404).json({
          success: false,
          message: `File ${filename} does not exist.`,
        });
      }
      filesToProcess = [filename];
    } else {
      filesToProcess = fs
        .readdirSync(outputDir)
        .filter((f) => f.endsWith(".csv"));
    }

    let totalImported = 0;
    let totalSkipped = 0;
    let alertsCreated = 0;

    for (const file of filesToProcess) {
      const fullPath = path.join(outputDir, file);
      const content = fs.readFileSync(fullPath, "utf8");
      const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);

      if (lines.length <= 1) continue;

      const headers = lines[0].split(",").map((h) => h.trim().toLowerCase());
      const hMap = {};
      headers.forEach((h, i) => (hMap[h] = i));

      const rowsToInsert = [];
      const alertsToInsert = [];

      for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].split(",");
        if (cols.length < 5) continue;

        const rawTimestamp = cols[hMap["timestamp"]] || "";
        const flowDate = rawTimestamp ? new Date(rawTimestamp) : new Date();
        const srcIP = (cols[hMap["src_ip"]] || cols[hMap["srcip"]] || "0.0.0.0").trim();
        const dstIP = (cols[hMap["dst_ip"]] || cols[hMap["dstip"]] || "0.0.0.0").trim();
        const srcPort = Number(cols[hMap["src_port"]] || 0);
        const dstPort = Number(cols[hMap["dst_port"]] || cols[hMap["destination port"]] || 0);
        const protocol = (cols[hMap["protocol"]] || "TCP").trim().toUpperCase();

        const duration = Number(cols[hMap["flow duration"]] || 0);
        const fwdBytes = Number(cols[hMap["total length of fwd packets"]] || 0);
        const bwdBytes = Number(cols[hMap["total length of bwd packets"]] || 0);
        const bytes = fwdBytes + bwdBytes;

        const fwdPackets = Number(cols[hMap["total fwd packets"]] || 0);
        const bwdPackets = Number(cols[hMap["total backward packets"]] || 0);
        const packets = Math.max(1, fwdPackets + bwdPackets);

        const prediction = (
          cols[hMap["prediction"]] ||
          cols[hMap["attack_type"]] ||
          cols[hMap["label"]] ||
          "BENIGN"
        ).trim();

        const label = (cols[hMap["label"]] || prediction || "BENIGN").trim();
        const confidence = Number(cols[hMap["confidence"]] || 0.95);

        rowsToInsert.push({
          timestamp: flowDate,
          srcIP,
          dstIP,
          srcPort,
          dstPort,
          protocol,
          duration,
          bytes,
          packets,
          label,
          prediction,
          confidence,
        });
      }

      if (rowsToInsert.length === 0) continue;

      // Duplicate prevention: find existing records within this timestamp bounds
      const minDate = new Date(
        Math.min(...rowsToInsert.map((r) => r.timestamp.getTime()))
      );
      const maxDate = new Date(
        Math.max(...rowsToInsert.map((r) => r.timestamp.getTime()))
      );

      const existingRecords = await TrafficLog.find(
        {
          timestamp: { $gte: minDate, $lte: maxDate },
        },
        "timestamp srcIP dstIP srcPort dstPort"
      ).lean();

      const existingMap = new Set();
      existingRecords.forEach((e) => {
        existingMap.add(
          `${new Date(e.timestamp).getTime()}_${e.srcIP}_${e.dstIP}_${e.srcPort}_${e.dstPort}`
        );
      });

      const uniqueRows = [];
      for (const row of rowsToInsert) {
        const key = `${row.timestamp.getTime()}_${row.srcIP}_${row.dstIP}_${row.srcPort}_${row.dstPort}`;
        if (!existingMap.has(key)) {
          uniqueRows.push(row);
          existingMap.add(key); // avoid duplicates inside the same file
        } else {
          totalSkipped++;
        }
      }

      if (uniqueRows.length > 0) {
        const inserted = await TrafficLog.insertMany(uniqueRows, { ordered: false });
        totalImported += inserted.length;

        // Create alert documents for any attack rows in this CSV
        for (const item of inserted) {
          if (isAttack(item.prediction, item.label)) {
            alertsToInsert.push({
              trafficLogId: item._id,
              attackType: item.prediction || item.label || "Threat Detected",
              severity: getSeverity(item.prediction),
              status: "Unread",
              time: item.timestamp,
            });
          }
        }

        if (alertsToInsert.length > 0) {
          const insertedAlerts = await Alert.insertMany(alertsToInsert, {
            ordered: false,
          });
          alertsCreated += insertedAlerts.length;
        }
      }
    }

    // Notify connected frontend clients
    try {
      const io = getIO();
      io.emit("dashboard-update", { type: "sync", totalImported });
    } catch {}

    return res.status(200).json({
      success: true,
      message: `Historical CSV synchronization completed. Imported ${totalImported} new flows (${alertsCreated} alerts created), skipped ${totalSkipped} duplicates.`,
      imported: totalImported,
      skipped: totalSkipped,
      alertsCreated,
    });
  } catch (error) {
    console.error("CSV sync error:", error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// ============================================================
// 5. CREATE TRAFFIC LOG (Existing)
// ============================================================
const createTrafficLog = async (req, res) => {
  try {
    const traffic = await TrafficLog.create(req.body);

    try {
      const io = getIO();
      io.emit("traffic-update", traffic);
    } catch (socketError) {
      console.error("Socket.IO emit failed:", socketError.message);
    }

    res.status(201).json({
      success: true,
      message: "Traffic log created successfully.",
      traffic,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// ============================================================
// 6. GET TRAFFIC LOG BY ID (Existing)
// ============================================================
const getTrafficLogById = async (req, res) => {
  try {
    const traffic = await TrafficLog.findById(req.params.id);

    if (!traffic) {
      return res.status(404).json({
        success: false,
        message: "Traffic log not found.",
      });
    }

    res.status(200).json({
      success: true,
      traffic,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// ============================================================
// 7. DELETE TRAFFIC LOG (Existing)
// ============================================================
const deleteTrafficLog = async (req, res) => {
  try {
    const traffic = await TrafficLog.findById(req.params.id);

    if (!traffic) {
      return res.status(404).json({
        success: false,
        message: "Traffic log not found.",
      });
    }

    await traffic.deleteOne();

    res.status(200).json({
      success: true,
      message: "Traffic log deleted successfully.",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

module.exports = {
  createTrafficLog,
  getTrafficLogs,
  getTrafficStats,
  getHistoricalCsvFiles,
  syncCsvToMongo,
  getTrafficLogById,
  deleteTrafficLog,
};
