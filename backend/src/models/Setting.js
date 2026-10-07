const mongoose = require("mongoose");

const settingSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    autoBlock: {
      type: Boolean,
      default: true,
    },
    emailAlerts: {
      type: Boolean,
      default: true,
    },
    desktopAlerts: {
      type: Boolean,
      default: false,
    },
    packetCapture: {
      type: Boolean,
      default: true,
    },
    aiThreshold: {
      type: Number,
      default: 85,
      min: 50,
      max: 100,
    },
    logRetention: {
      type: Number,
      default: 30,
      min: 1,
      max: 365,
    },
    blockedIPs: [
      {
        ip: { type: String, required: true },
        reason: { type: String, default: "Hostile intrusion activity detected" },
        blockedAt: { type: Date, default: Date.now },
      },
    ],
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Setting", settingSchema);
