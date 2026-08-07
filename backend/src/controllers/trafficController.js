const TrafficLog = require("../models/TrafficLog");

// Create Traffic Log
const createTrafficLog = async (req, res) => {
  try {
    const traffic = await TrafficLog.create(req.body);

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

// Get All Traffic Logs
const getTrafficLogs = async (req, res) => {
  try {
    const traffic = await TrafficLog.find().sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: traffic.length,
      traffic,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Get Traffic Log By ID
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

// Delete Traffic Log
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
  getTrafficLogById,
  deleteTrafficLog,
};