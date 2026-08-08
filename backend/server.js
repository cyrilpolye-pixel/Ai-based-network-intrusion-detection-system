const http = require("http");
const app = require("./src/app");
const connectDB = require("./src/config/db");
const { initializeSocket } = require("./src/socket/socket");

require("dotenv").config();

const PORT = process.env.PORT || 5000;

const server = http.createServer(app);

const startServer = async () => {
  try {
    await connectDB();

    initializeSocket(server);

    server.listen(PORT, () => {
      console.log(
        `🚀 Server running on http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error("❌ Server startup failed:", error.message);
    process.exit(1);
  }
};

startServer();

