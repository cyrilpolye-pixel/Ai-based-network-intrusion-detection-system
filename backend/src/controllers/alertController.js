const Alert = require("../models/Alert");
const { getIO } = require("../socket/socket");

// Create Alert
const createAlert = async (req, res) => {
  try {
    const alert = await Alert.create(req.body);

    try {
      const io = getIO();
      io.emit("alert-created", alert);
    } catch {}

    res.status(201).json({
      success: true,
      message: "Alert created successfully.",
      alert,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Get All Alerts (With optional filtering)
const getAlerts = async (req, res) => {
  try {
    const { status, severity, search } = req.query;
    const query = {};

    if (status && status !== "all") {
      query.status = new RegExp(`^${status}$`, "i");
    }

    if (severity && severity !== "all") {
      query.severity = new RegExp(`^${severity}$`, "i");
    }

    if (search && search.trim() !== "") {
      const searchRegex = new RegExp(search.trim(), "i");
      query.$or = [
        { attackType: searchRegex },
        { severity: searchRegex },
        { status: searchRegex },
      ];
    }

    const alerts = await Alert.find(query)
      .populate("trafficLogId")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: alerts.length,
      alerts,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Get Single Alert By ID
const getAlertById = async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id).populate("trafficLogId");

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Intrusion alert not found.",
      });
    }

    res.status(200).json({
      success: true,
      alert,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Update Alert Status
const updateAlertStatus = async (req, res) => {
  try {
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status },
      { returnDocument: "after" }
    ).populate("trafficLogId");

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found.",
      });
    }

    try {
      const io = getIO();
      io.emit("alert-updated", alert);
      io.emit("dashboard-update", { type: "alert-status", alert });
    } catch {}

    res.status(200).json({
      success: true,
      alert,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Delete Alert
const deleteAlert = async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found.",
      });
    }

    await alert.deleteOne();

    try {
      const io = getIO();
      io.emit("alert-deleted", { id: req.params.id });
      io.emit("dashboard-update", { type: "alert-deleted" });
    } catch {}

    res.status(200).json({
      success: true,
      message: "Alert deleted successfully.",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

module.exports = {
  createAlert,
  getAlerts,
  getAlertById,
  updateAlertStatus,
  deleteAlert,
};