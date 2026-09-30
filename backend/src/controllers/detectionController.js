const TrafficLog = require("../models/TrafficLog");
const Alert = require("../models/Alert");
const { getIO } = require("../socket/socket");

const receivePortScan = async (req, res) => {
  try {
    const {
      source_ip,
      target_ip,
      port_count,
      ports,
      timestamp,
    } = req.body;

    // Validate required information
    if (!source_ip || !target_ip) {
      return res.status(400).json({
        success: false,
        message: "source_ip and target_ip are required.",
      });
    }

    // Create traffic record
    const traffic = await TrafficLog.create({
      timestamp: timestamp ? new Date(timestamp) : new Date(),

      srcIP: source_ip,
      dstIP: target_ip,

      protocol: "TCP",

      srcPort: 0,

      // PortScan may involve multiple destination ports.
      // The first detected port is stored here.
      dstPort:
        Array.isArray(ports) && ports.length > 0
          ? Number(ports[0])
          : 0,

      duration: 0,

      bytes: 0,

      packets: port_count || 0,

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

      time: timestamp ? new Date(timestamp) : new Date(),
    });

    // Notify connected frontend clients
    try {
      const io = getIO();

      io.emit("traffic-update", traffic);

      io.emit("alert-created", alert);
    } catch (socketError) {
      console.error(
        "Socket.IO emit failed:",
        socketError.message
      );
    }

    return res.status(201).json({
      success: true,
      message: "PortScan detection stored successfully.",

      traffic,

      alert,
    });
  } catch (error) {
    console.error(
      "PortScan ingestion error:",
      error
    );

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

    const traffic = await TrafficLog.create({
      timestamp: timestamp ? new Date(timestamp) : new Date(),
      srcIP: source_ip,
      dstIP: target_ip,
      protocol: protocol || "Unknown",
      srcPort: Number(source_port || 0),
      dstPort: Number(target_port || 0),
      duration: Number(duration || 0),
      bytes: Number(bytes || 0),
      packets: Number(packets || 0),
      label: label || "Unknown",
      prediction: prediction || "Pending",
      confidence: Number(confidence || 0),
    });

    try {
      const io = getIO();
      io.emit("traffic-update", traffic);
    } catch (socketError) {
      console.error("Socket.IO emit failed:", socketError.message);
    }

    return res.status(201).json({
      success: true,
      message: "Traffic flow stored successfully.",
      traffic,
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





module.exports = {
  receivePortScan,
  receiveFlow,
};
