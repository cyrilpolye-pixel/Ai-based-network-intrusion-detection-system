const express = require("express");
const router = express.Router();

const { protect } = require("../middleware/authMiddleware");
const {
  getSettings,
  updateSettings,
  blockIP,
  unblockIP,
} = require("../controllers/settingController");

router.get("/", protect, getSettings);
router.put("/", protect, updateSettings);
router.post("/block-ip", protect, blockIP);
router.post("/unblock-ip", protect, unblockIP);

module.exports = router;
