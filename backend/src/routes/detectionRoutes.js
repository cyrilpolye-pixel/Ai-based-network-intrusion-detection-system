const express = require("express");

const {
  receiveAttack,
  receivePortScan,
  receiveFlow,
  receiveLiveFlow,
} = require("../controllers/detectionController");

const router = express.Router();

router.post("/attack", receiveAttack);
router.post("/portscan", receivePortScan);
router.post("/flow", receiveFlow);
router.post("/live-flow", receiveLiveFlow);

module.exports = router;