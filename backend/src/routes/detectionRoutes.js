const express = require("express");

const {
  receivePortScan,
  receiveFlow,
} = require("../controllers/detectionController");

const router = express.Router();

router.post("/portscan", receivePortScan);
router.post("/flow", receiveFlow);

module.exports = router;