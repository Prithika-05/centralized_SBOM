import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import sbomRoutes from "./modules/sbom/routes.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use("/api/sboms", sbomRoutes);

// Root endpoint
app.get("/", (_req, res) => {
  res.json({
    name: "Centralized SBOM Management System",
    status: "running",
  });
});

// Health check
app.get("/api/health", (_req, res) => {
  res.json({
    status: "OK",
    service: "SBOM Backend",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`SBOM backend running on http://localhost:${PORT}`);
});