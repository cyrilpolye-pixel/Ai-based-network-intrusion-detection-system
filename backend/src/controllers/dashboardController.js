const TrafficLog = require("../models/TrafficLog");
const Alert = require("../models/Alert");

const getDashboardStats = async (req, res) => {
  try {
    const totalTraffic = await TrafficLog.countDocuments();

    const totalAlerts = await Alert.countDocuments();

    const criticalAlerts = await Alert.countDocuments({
      severity: "Critical",
    });

    // BENIGN or normal traffic (case-insensitive)
    const normalTraffic = await TrafficLog.countDocuments({
      $or: [
        { prediction: { $regex: /^(benign|normal)$/i } },
        { label: { $regex: /^(benign|normal)$/i } },
      ],
    });

    // Anything other than benign/normal is considered attack traffic
    const attackTraffic = Math.max(0, totalTraffic - normalTraffic);

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