const Alert = require("../models/Alert");

// Create Alert
const createAlert = async (req, res) => {
  try {
    const alert = await Alert.create(req.body);

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

// Get All Alerts
const getAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find()
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

// Update Alert Status
const updateAlertStatus = async (req, res) => {
  try {
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status },
      {  returnDocument: "after" }
    );

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found.",
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
  updateAlertStatus,
  deleteAlert,
};