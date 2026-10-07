const express = require("express");
const router = express.Router();

const { protect } = require("../middleware/authMiddleware");

const {
  createAlert,
  getAlerts,
  getAlertById,
  updateAlertStatus,
  deleteAlert,
} = require("../controllers/alertController");

router.post("/", protect, createAlert);
router.get("/", protect, getAlerts);
router.get("/:id", protect, getAlertById);
router.put("/:id", protect, updateAlertStatus);
router.delete("/:id", protect, deleteAlert);

module.exports = router;