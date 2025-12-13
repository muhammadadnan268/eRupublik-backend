require("dotenv").config();
const serverless = require("serverless-http");
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const passport = require("passport");
const path = require("path");

// Import with correct path from netlify/functions
const connectDB = require("../../src/config/db");
const initPassport = require("../../src/config/passport");
const authRoutes = require("../../src/routes/auth");
const auth = require("../../src/middleware/auth");
const swaggerUi = require("swagger-ui-express");
const { getSpec } = require("../../src/swagger");

const app = express();

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());
initPassport();

app.use("/api/auth", authRoutes);
app.get("/api/profile", auth, (req, res) => {
  res.json({ 
    id: req.user.id, 
    email: req.user.email, 
    role: req.user.role, 
    provider: req.user.provider, 
    citizenName: req.user.citizenName, 
    citizenship: req.user.citizenship 
  });
});

const spec = getSpec();
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(spec));

// Health check endpoint
app.get("/", (req, res) => {
  res.json({ message: "eRepublic Backend API is running on Netlify" });
});

// Initialize database connection
let dbConnected = false;
const initializeDB = async () => {
  if (!dbConnected) {
    try {
      await connectDB();
      dbConnected = true;
      console.log("Database connected");
    } catch (error) {
      console.error("Database connection error:", error);
    }
  }
};

// Initialize DB before handling requests
initializeDB();

// Export serverless handler
module.exports.handler = serverless(app);

