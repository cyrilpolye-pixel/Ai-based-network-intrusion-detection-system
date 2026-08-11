const express = require("express");
const { predictTraffic } = require("../controllers/aiController");

const router = express.Router();

router.post("/predict", predictTraffic);

module.exports = router;