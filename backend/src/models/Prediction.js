const mongoose = require("mongoose");

const predictionSchema = new mongoose.Schema(
  {
    trafficId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "TrafficLog",
      required: true,
    },

    predictedLabel: {
      type: String,
      required: true,
    },

    confidence: {
      type: Number,
      required: true,
    },

    model: {
      type: String,
      default: "Random Forest",
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

module.exports = mongoose.model("Prediction", predictionSchema);