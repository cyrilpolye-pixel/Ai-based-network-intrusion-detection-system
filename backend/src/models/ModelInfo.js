const mongoose = require("mongoose");

const modelInfoSchema = new mongoose.Schema(
  {
    modelName: {
      type: String,
      required: true,
    },

    version: {
      type: String,
      default: "1.0",
    },

    accuracy: Number,

    precision: Number,

    recall: Number,

    f1Score: Number,

    trainedOn: {
      type: Date,
      default: Date.now,
    },

    status: {
      type: String,
      enum: ["Active", "Inactive"],
      default: "Active",
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("ModelInfo", modelInfoSchema);