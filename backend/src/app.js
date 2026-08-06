const express = require("express");
const cors = require("cors");
require("dotenv").config();

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

module.exports = app;