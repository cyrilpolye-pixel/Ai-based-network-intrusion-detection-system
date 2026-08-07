const express = require("express");
const router = express.Router();

const { protect } = require("../middleware/authMiddleware");

const {
  createTrafficLog,
  getTrafficLogs,
  getTrafficLogById,
  deleteTrafficLog,
} = require("../controllers/trafficController");

router.post("/", protect, createTrafficLog);

router.get("/", protect, getTrafficLogs);

router.get("/:id", protect, getTrafficLogById);

router.delete("/:id", protect, deleteTrafficLog);

module.exports = router;