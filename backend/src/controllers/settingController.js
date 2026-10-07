const Setting = require("../models/Setting");

// Get current system settings
const getSettings = async (req, res) => {
  try {
    let settings = await Setting.findOne();

    if (!settings) {
      settings = await Setting.create({
        autoBlock: true,
        emailAlerts: true,
        desktopAlerts: false,
        packetCapture: true,
        aiThreshold: 85,
        logRetention: 30,
        blockedIPs: [],
      });
    }

    return res.status(200).json({
      success: true,
      settings,
    });
  } catch (error) {
    console.error("Error fetching settings:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to retrieve settings.",
    });
  }
};

// Update system settings
const updateSettings = async (req, res) => {
  try {
    const {
      autoBlock,
      emailAlerts,
      desktopAlerts,
      packetCapture,
      aiThreshold,
      logRetention,
    } = req.body;

    let settings = await Setting.findOne();

    if (!settings) {
      settings = new Setting();
    }

    if (autoBlock !== undefined) settings.autoBlock = Boolean(autoBlock);
    if (emailAlerts !== undefined) settings.emailAlerts = Boolean(emailAlerts);
    if (desktopAlerts !== undefined) settings.desktopAlerts = Boolean(desktopAlerts);
    if (packetCapture !== undefined) settings.packetCapture = Boolean(packetCapture);
    if (aiThreshold !== undefined) settings.aiThreshold = Number(aiThreshold);
    if (logRetention !== undefined) settings.logRetention = Number(logRetention);

    await settings.save();

    return res.status(200).json({
      success: true,
      message: "Settings saved successfully to MongoDB.",
      settings,
    });
  } catch (error) {
    console.error("Error updating settings:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to update settings.",
    });
  }
};

// Add IP to blocklist
const blockIP = async (req, res) => {
  try {
    const { ip, reason } = req.body;

    if (!ip || typeof ip !== "string") {
      return res.status(400).json({
        success: false,
        message: "Valid IP address is required.",
      });
    }

    let settings = await Setting.findOne();
    if (!settings) {
      settings = await Setting.create({});
    }

    const trimmedIP = ip.trim();
    const alreadyBlocked = settings.blockedIPs.some((b) => b.ip === trimmedIP);

    if (!alreadyBlocked) {
      settings.blockedIPs.push({
        ip: trimmedIP,
        reason: reason || "Identified as hostile intrusion source",
        blockedAt: new Date(),
      });
      await settings.save();
    }

    return res.status(200).json({
      success: true,
      message: `IP address ${trimmedIP} successfully added to firewall blocklist.`,
      blockedIPs: settings.blockedIPs,
    });
  } catch (error) {
    console.error("Error blocking IP:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to block IP.",
    });
  }
};

// Remove IP from blocklist
const unblockIP = async (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip) {
      return res.status(400).json({
        success: false,
        message: "IP address is required to unblock.",
      });
    }

    let settings = await Setting.findOne();
    if (!settings) {
      return res.status(200).json({ success: true, blockedIPs: [] });
    }

    const trimmedIP = ip.trim();
    settings.blockedIPs = settings.blockedIPs.filter((b) => b.ip !== trimmedIP);
    await settings.save();

    return res.status(200).json({
      success: true,
      message: `IP address ${trimmedIP} removed from blocklist.`,
      blockedIPs: settings.blockedIPs,
    });
  } catch (error) {
    console.error("Error unblocking IP:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to unblock IP.",
    });
  }
};

module.exports = {
  getSettings,
  updateSettings,
  blockIP,
  unblockIP,
};
