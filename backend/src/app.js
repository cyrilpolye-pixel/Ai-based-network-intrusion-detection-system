const express = require("express");
const cors = require("cors");
const dashboardRoutes = require("./routes/dashboardRoutes");
require("dotenv").config();
const trafficRoutes = require("./routes/trafficRoutes");
const authRoutes = require("./routes/authRoutes");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Default Route
app.get("/", (req, res) => {
  res.json({
    message: "AI-NIDS Backend is Running 🚀",
  });
});

// API Routes
app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/traffic", trafficRoutes);
module.exports = app;