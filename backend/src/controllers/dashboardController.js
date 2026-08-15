const TrafficLog = require("../models/TrafficLog");
const Alert = require("../models/Alert");

const getDashboardStats = async (req, res) => {
  try {
    const totalTraffic = await TrafficLog.countDocuments();

    const totalAlerts = await Alert.countDocuments();

    const criticalAlerts = await Alert.countDocuments({
      severity: "Critical",
    });

    // BENIGN traffic is considered normal traffic
    const normalTraffic = await TrafficLog.countDocuments({
      prediction: "BENIGN",
    });

    // Anything other than BENIGN is considered attack traffic
    const attackTraffic = await TrafficLog.countDocuments({
      prediction: { $ne: "BENIGN" },
    });

    const recentAlerts = await Alert.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate("trafficLogId");

    res.status(200).json({
      success: true,
      stats: {
        totalTraffic,
        totalAlerts,
        criticalAlerts,
        normalTraffic,
        attackTraffic,
      },
      recentAlerts,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

module.exports = {
  getDashboardStats,
};