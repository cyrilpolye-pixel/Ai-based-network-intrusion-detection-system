const express = require("express");
const router = express.Router();

const { protect } = require("../middleware/authMiddleware");

const {
  createTrafficLog,
  getTrafficLogs,
  getTrafficStats,
  getHistoricalCsvFiles,
  syncCsvToMongo,
  getTrafficLogById,
  deleteTrafficLog,
} = require("../controllers/trafficController");

// Historical stats & CSV sync endpoints (MUST precede /:id)
router.get("/stats", protect, getTrafficStats);
router.get("/csv-files", protect, getHistoricalCsvFiles);
router.post("/sync-csv", protect, syncCsvToMongo);

// Standard CRUD endpoints
router.post("/", protect, createTrafficLog);
router.get("/", protect, getTrafficLogs);
router.get("/:id", protect, getTrafficLogById);
router.delete("/:id", protect, deleteTrafficLog);

module.exports = router;