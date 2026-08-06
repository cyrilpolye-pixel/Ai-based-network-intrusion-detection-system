const mongoose = require("mongoose");

const trafficLogSchema = new mongoose.Schema(
  {
    timestamp: {
      type: Date,
      default: Date.now,
    },

    srcIP: {
      type: String,
      required: true,
    },

    dstIP: {
      type: String,
      required: true,
    },

    protocol: {
      type: String,
      required: true,
    },

    srcPort: Number,

    dstPort: Number,

    duration: Number,

    bytes: Number,

    packets: Number,

    label: {
      type: String,
      default: "Unknown",
    },

    prediction: {
      type: String,
      default: "Pending",
    },

    confidence: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("TrafficLog", trafficLogSchema);