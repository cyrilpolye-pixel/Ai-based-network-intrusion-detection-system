const express = require("express");

const {
  receivePortScan,
  receiveFlow,
  receiveLiveFlow,
} = require("../controllers/detectionController");

const router = express.Router();

router.post("/portscan", receivePortScan);
router.post("/flow", receiveFlow);
router.post("/live-flow", receiveLiveFlow);

module.exports = router;