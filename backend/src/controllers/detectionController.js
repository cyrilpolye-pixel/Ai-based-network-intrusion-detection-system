const TrafficLog = require("../models/TrafficLog");
const Alert = require("../models/Alert");
const { getIO } = require("../socket/socket");

// Helper to determine severity based on attack type
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

// Helper to check if flow is an attack
const checkIsAttack = (label = "", prediction = "", isAttackFlag = false) => {
  if (Boolean(isAttackFlag)) return true;
  const p = String(prediction || "").trim().toLowerCase();
  const l = String(label || "").trim().toLowerCase();
  const nonAttacks = new Set(["benign", "normal", "unknown", "pending", ""]);
  return !nonAttacks.has(p) || !nonAttacks.has(l);
};

const receivePortScan = async (req, res) => {
  try {
    const {
      source_ip,
      target_ip,
      port_count,
      ports,
      timestamp,
    } = req.body;

    if (!source_ip || !target_ip) {
      return res.status(400).json({
        success: false,
        message: "source_ip and target_ip are required.",
      });
    }

    const flowDate = timestamp ? new Date(timestamp) : new Date();

    // Create traffic record
    const traffic = await TrafficLog.create({
      timestamp: flowDate,
      srcIP: source_ip,
      dstIP: target_ip,
      protocol: "TCP",
      srcPort: 0,
      dstPort: Array.isArray(ports) && ports.length > 0 ? Number(ports[0]) : 0,
      duration: 0,
      bytes: 0,
      packets: Number(port_count || 0),
      label: "PortScan",
      prediction: "PortScan",
      confidence: 1,
    });

    // Create intrusion alert
    const alert = await Alert.create({
      trafficLogId: traffic._id,
      attackType: "PortScan",
      severity: "High",
      status: "Unread",
      time: flowDate,
    });

    // Notify connected frontend clients
    try {
      const io = getIO();
      io.emit("traffic-update", traffic);
      io.emit("alert-created", alert);
      io.emit("dashboard-update", { type: "attack", traffic, alert });
      io.emit("live-traffic", {
        source_ip,
        target_ip,
        source_port: 0,
        target_port: traffic.dstPort,
        protocol: "TCP",
        timestamp: flowDate.toISOString(),
        duration: 0,
        bytes: 0,
        packets: Number(port_count || 0),
        label: "PortScan",
        prediction: "PortScan",
        attack_type: "PortScan",
        is_attack: true,
        confidence: 1,
        detection_method: "PortScan Scanner",
      });
    } catch (socketError) {
      console.error("Socket.IO emit failed:", socketError.message);
    }

    return res.status(201).json({
      success: true,
      message: "PortScan detection stored successfully.",
      traffic,
      alert,
    });
  } catch (error) {
    console.error("PortScan ingestion error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to store PortScan detection.",
      error: error.message,
    });
  }
};

const receiveFlow = async (req, res) => {
  try {
    const {
      source_ip,
      target_ip,
      source_port,
      target_port,
      protocol,
      timestamp,
      duration,
      bytes,
      packets,
      label,
      prediction,
      confidence,
    } = req.body;

    if (!source_ip || !target_ip) {
      return res.status(400).json({
        success: false,
        message: "source_ip and target_ip are required.",
      });
    }

    const flowDate = timestamp ? new Date(timestamp) : new Date();
    const isAttack = checkIsAttack(label, prediction);
    const attackName = isAttack ? (prediction || label || "Suspicious Flow") : "BENIGN";

    const traffic = await TrafficLog.create({
      timestamp: flowDate,
      srcIP: source_ip,
      dstIP: target_ip,
      protocol: protocol || "TCP",
      srcPort: Number(source_port || 0),
      dstPort: Number(target_port || 0),
      duration: Number(duration || 0),
      bytes: Number(bytes || 0),
      packets: Number(packets || 0),
      label: label || (isAttack ? attackName : "BENIGN"),
      prediction: prediction || (isAttack ? attackName : "BENIGN"),
      confidence: Number(confidence || (isAttack ? 0.95 : 0.99)),
    });

    let alert = null;
    if (isAttack) {
      alert = await Alert.create({
        trafficLogId: traffic._id,
        attackType: attackName,
        severity: getSeverity(attackName),
        status: "Unread",
        time: flowDate,
      });
    }

    try {
      const io = getIO();
      io.emit("traffic-update", traffic);
      if (alert) {
        io.emit("alert-created", alert);
      }
      io.emit("dashboard-update", {
        type: isAttack ? "attack" : "normal",
        traffic,
        alert,
      });
    } catch (socketError) {
      console.error("Socket.IO emit failed:", socketError.message);
    }

    return res.status(201).json({
      success: true,
      message: "Traffic flow stored successfully.",
      traffic,
      alert,
    });
  } catch (error) {
    console.error("Traffic ingestion error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to store traffic flow.",
      error: error.message,
    });
  }
};

const receiveLiveFlow = async (req, res) => {
  try {
    const {
      source_ip,
      target_ip,
      source_port,
      target_port,
      protocol,
      timestamp,
      duration,
      bytes,
      packets,
      label,
      prediction,
      attack_type,
      confidence,
      is_attack,
      detection_method,
    } = req.body;

    if (!source_ip || !target_ip) {
      return res.status(400).json({
        success: false,
        message: "source_ip and target_ip are required.",
      });
    }

    const flowDate = timestamp ? new Date(timestamp) : new Date();
    const isAttack = checkIsAttack(label, prediction || attack_type, is_attack);
    const attackName = isAttack
      ? (attack_type || prediction || label || "Threat Detected")
      : "BENIGN";

    const liveTraffic = {
      source_ip,
      target_ip,
      source_port: Number(source_port || 0),
      target_port: Number(target_port || 0),
      protocol: protocol || "TCP",
      timestamp: flowDate.toISOString(),
      duration: Number(duration || 0),
      bytes: Number(bytes || 0),
      packets: Number(packets || 0),
      label: label || (isAttack ? attackName : "BENIGN"),
      prediction: isAttack ? attackName : "BENIGN",
      attack_type: isAttack ? attackName : "BENIGN",
      confidence: Number(confidence || (isAttack ? 0.95 : 0.99)),
      is_attack: isAttack,
      detection_method: detection_method || "ML/CNN",
    };

    let traffic = null;
    let alert = null;

    // Persist to MongoDB so Traffic Analysis, Intrusion Alerts & Dashboard stats have records
    try {
      traffic = await TrafficLog.create({
        timestamp: flowDate,
        srcIP: source_ip,
        dstIP: target_ip,
        protocol: protocol || "TCP",
        srcPort: Number(source_port || 0),
        dstPort: Number(target_port || 0),
        duration: Number(duration || 0),
        bytes: Number(bytes || 0),
        packets: Number(packets || 0),
        label: label || (isAttack ? attackName : "BENIGN"),
        prediction: isAttack ? attackName : "BENIGN",
        confidence: Number(confidence || (isAttack ? 0.95 : 0.99)),
      });

      if (isAttack) {
        alert = await Alert.create({
          trafficLogId: traffic._id,
          attackType: attackName,
          severity: getSeverity(attackName),
          status: "Unread",
          time: flowDate,
        });
      }
    } catch (dbError) {
      console.error("Database save failed in receiveLiveFlow:", dbError.message);
    }

    // Emit live events to frontends
    try {
      const io = getIO();
      // 1. Live stream event for LiveMonitoring
      io.emit("live-traffic", {
        ...liveTraffic,
        _id: traffic?._id,
      });

      // 2. Traffic update for TrafficAnalysis
      if (traffic) {
        io.emit("traffic-update", traffic);
      }

      // 3. Alert created for IntrusionAlerts
      if (alert) {
        io.emit("alert-created", alert);
      }

      // 4. Dashboard update event for Dashboard
      io.emit("dashboard-update", {
        type: isAttack ? "attack" : "normal",
        traffic,
        alert,
      });
    } catch (socketError) {
      console.error("Socket.IO emit failed in receiveLiveFlow:", socketError.message);
    }

    return res.status(200).json({
      success: true,
      message: "Live traffic processed and emitted successfully.",
      traffic,
      alert,
    });
  } catch (error) {
    console.error("Live traffic error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to emit live traffic.",
      error: error.message,
    });
  }
};

module.exports = {
  receivePortScan,
  receiveFlow,
  receiveLiveFlow,
};
