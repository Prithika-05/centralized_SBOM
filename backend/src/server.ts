import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import sbomRoutes from "./modules/sbom/routes.js";
import { testNeo4jConnection } from "./services/neo4jService.js";

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

app.get("/api/health/neo4j", async (_req, res) => {
  const connected = await testNeo4jConnection();

  if (!connected) {
    return res.status(500).json({
      status: "ERROR",
      service: "Neo4j",
    });
  }

  res.json({
    status: "OK",
    service: "Neo4j",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`SBOM backend running on http://localhost:${PORT}`);
});