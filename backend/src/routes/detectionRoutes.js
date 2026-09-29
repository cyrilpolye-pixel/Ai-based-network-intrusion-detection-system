const express = require("express");

const {
  receivePortScan,
} = require("../controllers/detectionController");

const router = express.Router();

router.post("/portscan", receivePortScan);

module.exports = router;