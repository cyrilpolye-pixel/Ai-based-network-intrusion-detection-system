const TrafficLog = require("../models/TrafficLog");
const Prediction = require("../models/Prediction");
const Alert = require("../models/Alert");
const { getIO } = require("../socket/socket");

const predictTraffic = async (req, res) => {
  try {
    const { features } = req.body;

    if (!features || typeof features !== "object") {
      return res.status(400).json({
        success: false,
        message: "Features are required.",
      });
    }

    // Send network features to the pretrained CNN ML service
    const mlResponse = await fetch("http://127.0.0.1:5001/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        features,
      }),
    });

    const result = await mlResponse.json();

    if (!mlResponse.ok) {
      return res.status(mlResponse.status).json({
        success: false,
        message: result.message || "ML service prediction failed.",
      });
    }

    const prediction = result;

    const attackType = prediction.attack_type || "BENIGN";
    const confidence = Number(prediction.confidence || 0);
    const isAttack = Boolean(prediction.is_attack);

    // Extract available traffic information.
    // CICIDS feature data may not contain IP/protocol information,
    // so safe fallback values are used.
    const traffic = await TrafficLog.create({
      srcIP: features["Src IP"] || features["Source IP"] || "Unknown",
      dstIP: features["Dst IP"] || features["Destination IP"] || "Unknown",
      protocol: features["Protocol"] || "Unknown",

      srcPort: Number(
        features["Src Port"] || features["Source Port"] || 0
      ),

      dstPort: Number(
        features["Dst Port"] ||
        features["Destination Port"] ||
        features["Destination Port"] ||
        0
      ),

      duration: Number(features["Flow Duration"] || 0),

      bytes:
        Number(features["Total Length of Fwd Packets"] || 0) +
        Number(features["Total Length of Bwd Packets"] || 0),

      packets:
        Number(features["Total Fwd Packets"] || 0) +
        Number(features["Total Backward Packets"] || 0),

      label: features["Label"] || "Unknown",

      prediction: isAttack ? attackType : "BENIGN",

      confidence,
    });

    // Save the model prediction
    const predictionRecord = await Prediction.create({
      trafficId: traffic._id,
      predictedLabel: attackType,
      confidence,
      model: "CNN1D",
    });

    let alert = null;

    // Create an alert only when the CNN detects an attack
    if (isAttack) {
      let severity = "Low";

      if (confidence >= 0.95) {
        severity = "Critical";
      } else if (confidence >= 0.85) {
        severity = "High";
      } else if (confidence >= 0.70) {
        severity = "Medium";
      }

      alert = await Alert.create({
        trafficLogId: traffic._id,
        attackType,
        severity,
        status: "Unread",
      });

      // Notify connected frontend clients
      try {
        const io = getIO();

        io.emit("traffic-update", traffic);
        io.emit("alert-created", alert);
      } catch (socketError) {
        console.error(
          "Socket.IO emit failed:",
          socketError.message
        );
      }
    } else {
      // Still notify clients about normal traffic
      try {
        const io = getIO();
        io.emit("traffic-update", traffic);
      } catch (socketError) {
        console.error(
          "Socket.IO emit failed:",
          socketError.message
        );
      }
    }

    return res.status(200).json({
      success: true,

      prediction: {
        attack_type: attackType,
        binary_confidence: prediction.binary_confidence,
        confidence,
        is_attack: isAttack,
      },

      traffic,
      predictionRecord,
      alert,
    });
  } catch (error) {
    console.error("AI prediction error:", error);

    return res.status(500).json({
      success: false,
      message: "AI prediction failed.",
      error: error.message,
    });
  }
};

module.exports = {
  predictTraffic,
};