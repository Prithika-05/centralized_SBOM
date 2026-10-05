import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import sbomRoutes from "./modules/sbom/routes.js";
import {
  testNeo4jConnection,
  createTestNode,
} from "./services/neo4jService.js";
import {
  getDirectDependencies,
  getTransitiveDependencies,
} from "./services/dependencyService.js";
import { testNVDConnection } from "./services/nvdService.js";
import { findVulnerabilities } from "./services/vulnerabilityService.js";
import { testOSVConnection } from "./services/osvService.js";
import {
  findAllVulnerabilities,
} from "./services/combinedVulnerabilityService.js";
import { correlateComponent } from "./services/vulnerabilityCorrelationService.js";


dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

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

app.post("/api/health/neo4j/test-node", async (_req, res) => {
  try {
    await createTestNode();

    res.json({
      status: "OK",
      message: "Test node created successfully",
    });
  } catch (error) {
    console.error("Failed to create Neo4j test node:", error);

    res.status(500).json({
      status: "ERROR",
      message: "Failed to create Neo4j test node",
    });
  }
});

app.get(
  "/api/components/:componentId/dependencies",
  async (req, res) => {
    try {
      const componentId = req.params.componentId;

      const result = await getDirectDependencies(componentId);

      res.json(result);
    } catch (error) {
      console.error(
        "Failed to retrieve dependencies:",
        error
      );

      res.status(500).json({
        status: "ERROR",
        message: "Failed to retrieve dependencies",
      });
    }
  }
);

app.get(
  "/api/components/:componentId/dependencies/transitive",
  async (req, res) => {
    try {
      const componentId = req.params.componentId;

      const result = await getTransitiveDependencies(componentId);

      res.json(result);
    } catch (error) {
      console.error(
        "Failed to retrieve transitive dependencies:",
        error
      );

      res.status(500).json({
        status: "ERROR",
        message: "Failed to retrieve transitive dependencies",
      });
    }
  }
);

app.get("/api/health/nvd", async (_req, res) => {
  const connected = await testNVDConnection();

  if (!connected) {
    return res.status(500).json({
      status: "ERROR",
      service: "NVD",
    });
  }

  res.json({
    status: "OK",
    service: "NVD",
  });
});

app.get(
  "/api/components/:componentId/vulnerabilities",
  async (req, res) => {
    try {
      const componentId = req.params.componentId;

      const result = await findVulnerabilities(
        componentId,
        req.query.name as string,
        req.query.version as string
      );

      res.json(result);
    } catch (error) {
      console.error(
        "Failed to retrieve vulnerabilities:",
        error
      );

      res.status(500).json({
        status: "ERROR",
        message: "Failed to retrieve vulnerabilities",
      });
    }
  }
);

app.get("/api/health/osv", async (_req, res) => {
  const connected = await testOSVConnection();

  if (!connected) {
    return res.status(500).json({
      status: "ERROR",
      service: "OSV",
    });
  }

  res.json({
    status: "OK",
    service: "OSV",
  });
});

app.get(
  "/api/components/:componentId/vulnerabilities/all",
  async (req, res) => {
    try {
      const componentId = req.params.componentId;
      const name = req.query.name as string;
      const version = req.query.version as string;

      if (!name || !version) {
        return res.status(400).json({
          status: "ERROR",
          message: "Package name and version are required",
        });
      }

      const vulnerabilities = await findAllVulnerabilities(
        name,
        version
      );

      res.json({
        componentId,
        name,
        version,
        vulnerabilities,
      });
    } catch (error) {
      console.error(
        "Failed to retrieve combined vulnerabilities:",
        error
      );

      res.status(500).json({
        status: "ERROR",
        message: "Failed to retrieve vulnerabilities",
      });
    }
  }
);

app.get("/api/components/:componentId/vulnerability-analysis", async (req, res) => {
  try {
    const componentId = req.params.componentId;
    const name = req.query.name as string;
    const version = req.query.version as string;

    if (!name || !version) {
      return res.status(400).json({
        status: "ERROR",
        message: "Package name and version are required",
      });
    }

    const result = await correlateComponent(
      componentId,
      name,
      version
    );

    res.json(result);
  } catch (error) {
    console.error("Failed to correlate vulnerabilities:", error);

    res.status(500).json({
      status: "ERROR",
      message: "Failed to correlate vulnerabilities",
    });
  }
});

app.use("/api/sboms", sbomRoutes);


// Start server
app.listen(PORT, () => {
  console.log(`SBOM backend running on http://localhost:${PORT}`);
});