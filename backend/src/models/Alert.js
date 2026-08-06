const mongoose = require("mongoose");

const alertSchema = new mongoose.Schema(
  {
    trafficLogId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "TrafficLog",
      required: true,
    },

    attackType: {
      type: String,
      required: true,
    },

    severity: {
      type: String,
      enum: ["Low", "Medium", "High", "Critical"],
      default: "Low",
    },

    status: {
      type: String,
      enum: ["Unread", "Read", "Resolved"],
      default: "Unread",
    },

    time: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Alert", alertSchema);