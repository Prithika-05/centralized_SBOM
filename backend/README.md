# Centralized SBOM Management System — Backend

A TypeScript/Node.js backend for the Centralized Software Bill of Materials (SBOM) Management System. The backend is being developed incrementally, beginning with the HTTP/API foundation and SBOM ingestion and processing pipeline.

The target architecture supports SPDX and CycloneDX SBOM ingestion, validation, parsing, dependency normalization, graph-based dependency analysis, vulnerability intelligence integration, CRA compliance validation, and reporting.

---

# 1. Backend

## Technology Stack

- **Runtime:** Node.js
- **Language:** TypeScript
- **HTTP Framework:** Express
- **CORS:** `cors`
- **Environment Configuration:** `dotenv`
- **File Upload Handling:** `multer`
- **Development Runner:** `tsx`
- **Graph Database Driver:** `neo4j-driver`
- **Type Definitions:** `@types/node`, `@types/express`, `@types/cors`, `@types/multer`

## Current Implementation Scope

The current backend implementation covers the following stages:

1. **Step 1 — Backend Foundation**
   - TypeScript project configuration
   - Express HTTP server
   - CORS and JSON middleware
   - Environment-based port configuration
   - Root and health-check endpoints

2. **Step 2 — SBOM Ingestion**
   - Multipart SBOM file upload
   - File persistence under the SBOM upload directory
   - Upload response metadata
   - Missing-file error handling

3. **Step 3 — SBOM Format Detection**
   - SPDX format detection
   - CycloneDX format detection
   - Unknown format handling

4. **Step 4 — SBOM Validation**
   - Validation of the uploaded SBOM according to the detected format
   - Validation error handling

5. **Step 5 — SBOM Parsing**
   - Conversion of the detected SBOM into the application's parsed SBOM structure
   - Component and dependency extraction

6. **Step 6 — SBOM Normalization**
   - Conversion of parsed components into a common normalized structure
   - Ecosystem identification from package identifiers
   - Normalized dependency, license, and hash information

The `neo4j-driver` package has also been installed in preparation for the graph database stage. Graph database connection and storage are part of a later implementation stage.

Vulnerability intelligence, impact analysis, CRA compliance validation, reporting, and frontend functionality are also planned for later stages.

---

# 2. Prerequisites

Install the following before starting the backend:

- Node.js — LTS version recommended
- npm — installed with Node.js
- A terminal such as PowerShell, Command Prompt, or Bash
- Postman or another HTTP client for API testing
- Neo4j will be required when the graph database implementation is started

Verify the Node.js and npm installation:

```bash
node --version
npm --version
```

---

# 3. Installation

From the repository root:

```bash
cd backend
```

Initialize the project if it has not already been initialized:

```bash
npm init -y
```

Install runtime dependencies:

```bash
npm install express cors dotenv multer neo4j-driver
```

Install development and TypeScript dependencies:

```bash
npm install -D typescript tsx @types/node @types/express @types/cors @types/multer
```

---

# 4. Backend Structure

Current implementation:

```text
backend/
├── src/
│   ├── modules/
│   │   └── sbom/
│   │       ├── routes.ts
│   │       ├── formatDetector.ts
│   │       ├── validator.ts
│   │       ├── parser.ts
│   │       ├── normalizer.ts
│   │       └── uploads/
│   │
│   └── server.ts
│
├── .env
├── .gitignore
├── package.json
├── package-lock.json
└── tsconfig.json
```

## Runtime Processing Flow

The current SBOM processing flow is:

```text
Client
   |
   | POST /api/sboms/upload
   v
Express Server
   |
   v
Multer
   |
   v
Uploaded File
   |
   v
Read File
   |
   v
JSON.parse()
   |
   v
Format Detection
   |
   +------ SPDX
   |
   +------ CycloneDX
   |
   +------ Unknown
   |
   v
Validation
   |
   v
Parsing
   |
   v
Normalization
   |
   v
Normalized SBOM
   |
   v
HTTP Response
```

---

# 5. Starting the Backend

The backend can be started directly with `tsx`:

```powershell
npx tsx .\src\server.ts
```

If the development script is configured in `package.json`, it can also be started with:

```bash
npm run dev
```

Expected output:

```text
SBOM backend running on http://localhost:5000
```

The server uses port `5000` by default unless the `PORT` environment variable is configured differently.

---

# 6. Environment Configuration

Create a `.env` file in the backend root:

```env
PORT=5000
NODE_ENV=development
```

`dotenv` loads these values into `process.env` when the server starts.

Do not commit `.env` to source control because later stages will place external-service credentials and database configuration in this file.

---

# 7. Step 1 — Backend Foundation

## 7.1 `src/server.ts`

```typescript
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

// SBOM routes
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
```

**Description:** Initializes the Express/TypeScript backend, loads environment variables, registers middleware, exposes health endpoints, and mounts the SBOM API.

**Collaboration:** `server.ts` is the application entry point and delegates SBOM-specific HTTP handling to `src/modules/sbom/routes.ts`.

---

## 7.2 `tsconfig.json`

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "esModuleInterop": true,
    "strict": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": "src"
  },
  "include": ["src"]
}
```

**Description:** Configures TypeScript compilation for a strict Node.js backend using the NodeNext module system.

**Collaboration:** It defines how TypeScript source files under `src/` are type-checked and compiled into `dist/`.

---

## 7.3 `package.json`

The relevant project configuration contains:

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js"
  }
}
```

Runtime dependencies include:

```json
{
  "dependencies": {
    "cors": "^...",
    "dotenv": "^...",
    "express": "^...",
    "multer": "^...",
    "neo4j-driver": "^..."
  }
}
```

Development dependencies include:

```json
{
  "devDependencies": {
    "@types/cors": "^...",
    "@types/express": "^...",
    "@types/multer": "^...",
    "@types/node": "^...",
    "tsx": "^...",
    "typescript": "^..."
  }
}
```

**Description:** Defines the backend package metadata, runtime dependencies, development dependencies, and executable npm commands.

**Collaboration:** The scripts provide standardized commands for running the TypeScript server, watching changes, compiling the project, and starting the compiled backend.

> Dependency versions are represented with placeholders above; `npm install` writes the exact resolved versions into the actual project.

---

## 7.4 `.env`

```env
PORT=5000
NODE_ENV=development
```

**Description:** Provides environment-specific runtime configuration without hard-coding deployment values into application source.

**Collaboration:** `dotenv.config()` in `server.ts` loads these values, and `PORT` controls the Express listening port.

---

## 7.5 `.gitignore`

```gitignore
node_modules/
dist/
.env
*.log
```

**Description:** Prevents generated dependencies, compiled output, environment secrets, and log files from being committed to source control.

**Collaboration:** It protects the repository while the backend is developed locally and later deployed through different environments.

---

# 8. Step 1 API Endpoints

## Root

```http
GET /
```

Response:

```json
{
  "name": "Centralized SBOM Management System",
  "status": "running"
}
```

## Health Check

```http
GET /api/health
```

Response:

```json
{
  "status": "OK",
  "service": "SBOM Backend"
}
```

The health endpoint is intended as a lightweight service availability check and does not perform SBOM processing.

---

# 9. Step 2 — SBOM Ingestion

Step 2 introduces the first functional SBOM operation: accepting an SBOM file through a multipart HTTP request.

## 9.1 `src/modules/sbom/routes.ts`

The upload route uses Multer and then processes the uploaded SBOM:

```typescript
import { Router } from "express";
import multer from "multer";
import fs from "fs";

import { detectSBOMFormat } from "./formatDetector.js";
import { validateSBOM } from "./validator.js";
import { parseSBOM } from "./parser.js";
import { normalizeSBOM } from "./normalizer.js";

const router = Router();

const upload = multer({
  dest: "src/modules/sbom/uploads/",
});

router.post("/upload", upload.single("sbom"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: "No SBOM file uploaded",
    });
  }

  try {
    // 1. Read uploaded file
    const fileContent = fs.readFileSync(req.file.path, "utf-8");

    // 2. Convert JSON text into an object
    const sbomData = JSON.parse(fileContent);

    // 3. Detect SBOM format
    const format = detectSBOMFormat(sbomData);

    // 4. Validate SBOM
    const validation = validateSBOM(sbomData, format);

    if (!validation.valid) {
      return res.status(400).json({
        message: "SBOM validation failed",
        format,
        errors: validation.errors,
      });
    }

    // 5. Parse SBOM
    const parsedSBOM = parseSBOM(sbomData, format);

    // 6. Normalize parsed SBOM
    const normalizedSBOM = normalizeSBOM(parsedSBOM);

    // 7. Return result
    res.json({
      message: "SBOM uploaded successfully",
      format,
      validation: {
        valid: true,
      },
      parsedSBOM,
      normalizedSBOM,
      file: {
        originalName: req.file.originalname,
        storedName: req.file.filename,
        size: req.file.size,
        path: req.file.path,
      },
    });
  } catch (error) {
    console.error("SBOM processing error:", error);

    res.status(400).json({
      error: "Invalid JSON SBOM file",
    });
  }
});

export default router;
```

**Description:** Defines the SBOM upload route and processes the uploaded JSON through format detection, validation, parsing, and normalization.

**Collaboration:** The router is mounted by `server.ts` at `/api/sboms`, producing the complete endpoint `POST /api/sboms/upload`.

---

## 9.2 `src/server.ts` — Step 2 route integration

```typescript
import sbomRoutes from "./modules/sbom/routes.js";

app.use("/api/sboms", sbomRoutes);
```

**Description:** Registers the SBOM router under the `/api/sboms` API namespace.

**Collaboration:** Express forwards `/api/sboms/upload` requests to the upload handler defined in `routes.ts`.

---

# 10. Step 2 API — Upload SBOM

## Endpoint

```http
POST /api/sboms/upload
```

## Content Type

```http
Content-Type: multipart/form-data
```

## Form Field

```text
sbom
```

Request structure:

```text
POST /api/sboms/upload
        |
        v
multipart/form-data
        |
        +-- sbom = <SBOM file>
```

The uploaded file is stored under:

```text
src/modules/sbom/uploads/
```

---

# 11. Step 3 — SBOM Format Detection

The uploaded SBOM is inspected before standard-specific validation and parsing.

Supported formats:

```text
SPDX
CycloneDX
Unknown
```

The current route calls:

```typescript
const format = detectSBOMFormat(sbomData);
```

The detected format is then passed into validation and parsing.

Implementation:

```text
src/modules/sbom/formatDetector.ts
```

---

# 12. Step 4 — SBOM Validation

After format detection, the uploaded SBOM is validated:

```typescript
const validation = validateSBOM(sbomData, format);
```

If validation fails, the API returns a `400 Bad Request` response containing the detected format and validation errors.

Example structure:

```json
{
  "message": "SBOM validation failed",
  "format": "SPDX",
  "errors": []
}
```

Implementation:

```text
src/modules/sbom/validator.ts
```

---

# 13. Step 5 — SBOM Parsing

After successful validation, the SBOM is parsed into the application's internal representation:

```typescript
const parsedSBOM = parseSBOM(sbomData, format);
```

The parser converts the detected SBOM format into a common application-level structure containing information such as components and dependencies.

Implementation:

```text
src/modules/sbom/parser.ts
```

The parsed SBOM is included in the upload API response.

---

# 14. Step 6 — SBOM Normalization

The parsed SBOM is normalized:

```typescript
const normalizedSBOM = normalizeSBOM(parsedSBOM);
```

Normalization provides a common representation for later stages.

The normalized component structure contains information such as:

```text
Component
├── id
├── name
├── version
├── supplier
├── packageId
├── ecosystem
├── dependencies
├── licenses
└── hashes
```

Implementation:

```text
src/modules/sbom/normalizer.ts
```

The normalized SBOM is returned in the API response.

---

# 15. Current Upload Processing Pipeline

```text
SBOM File
    |
    v
POST /api/sboms/upload
    |
    v
Multer
    |
    v
Stored Upload
    |
    v
Read File
    |
    v
JSON.parse()
    |
    v
Format Detection
    |
    +-------- SPDX
    |
    +-------- CycloneDX
    |
    +-------- Unknown
    |
    v
Validation
    |
    v
Parsing
    |
    v
Normalization
    |
    v
Normalized SBOM
    |
    v
API Response
```

---

# 16. Upload API Response

A successful request returns the processing results together with upload metadata.

Example structure:

```json
{
  "message": "SBOM uploaded successfully",
  "format": "SPDX",
  "validation": {
    "valid": true
  },
  "parsedSBOM": {},
  "normalizedSBOM": {
    "format": "SPDX",
    "components": []
  },
  "file": {
    "originalName": "example.json",
    "storedName": "generated-file-name",
    "size": 12345,
    "path": "src/modules/sbom/uploads/generated-file-name"
  }
}
```

The exact contents of `parsedSBOM` and `normalizedSBOM` depend on the uploaded SBOM.

---

# 17. Error Handling

## No SBOM file

```text
400 Bad Request
```

Response:

```json
{
  "error": "No SBOM file uploaded"
}
```

## Invalid JSON or processing error

```text
400 Bad Request
```

Response:

```json
{
  "error": "Invalid JSON SBOM file"
}
```

## Validation failure

```text
400 Bad Request
```

Response structure:

```json
{
  "message": "SBOM validation failed",
  "format": "SPDX",
  "errors": []
}
```

---

# 18. Testing the SBOM Processing Pipeline

Start the backend:

```bash
npm run dev
```

or:

```powershell
npx tsx .\src\server.ts
```

Using Postman:

1. Create a `POST` request.
2. Set the URL to:

```text
http://localhost:5000/api/sboms/upload
```

3. Select **Body → form-data**.
4. Create a field named:

```text
sbom
```

5. Change its type from `Text` to `File`.
6. Select a valid SPDX or CycloneDX JSON SBOM.
7. Click **Send**.

The request should pass through:

```text
Upload
 → JSON parsing
 → Format detection
 → Validation
 → Parsing
 → Normalization
 → Response
```

---

# 19. Neo4j Preparation

The Neo4j driver has been added to the backend:

```json
"neo4j-driver": "^6.2.0"
```

At the current stage, the driver is installed as preparation for the graph database layer.

The following functionality has not yet been implemented:

```text
Neo4j Connection
      ↓
Graph Schema
      ↓
Component Nodes
      ↓
Dependency Relationships
      ↓
SBOM Graph Storage
```

This will be developed in the next backend stage.

---

# 20. Current Processing Boundary

The current implementation ends after SBOM normalization:

```text
Stored SBOM
    |
    v
Format Detection
    |
    v
Validation
    |
    v
Parsing
    |
    v
Normalization
    |
    v
Normalized SBOM
```

The planned system will extend this into:

```text
Normalized SBOM
    |
    v
Neo4j Graph Database
    |
    v
Dependency Analysis
    |
    v
Vulnerability Intelligence
    |
    +------ NVD
    |
    +------ OSV
    |
    v
Vulnerability Correlation
    |
    v
Impact Analysis
    |
    v
CRA Compliance Validation
    |
    v
Reporting API
    |
    v
Frontend Dashboard
```

---

# 21. Development Principles

## Modular backend

SBOM-specific functionality is placed under `src/modules/sbom/` rather than implementing all application logic inside `server.ts`.

## Separation of concerns

`server.ts` is responsible for application startup and route registration, while the SBOM module handles SBOM-specific processing.

The processing responsibilities are separated into:

```text
routes.ts
    ↓
formatDetector.ts
    ↓
validator.ts
    ↓
parser.ts
    ↓
normalizer.ts
```

## Type safety

TypeScript strict mode is enabled to detect type errors during development and compilation.

## Configuration separation

Runtime configuration is supplied through `.env` rather than being embedded directly into application code.

## Incremental implementation

The backend is intentionally developed in small verified stages. Each stage is implemented and tested before moving to the next major capability.

---

# 22. Next Development Stage

The next backend stage is:

## Step 7 — Neo4j Graph Database Integration

The intended processing flow is:

```text
Normalized SBOM
       |
       v
Neo4j Connection
       |
       v
Create SBOM Graph
       |
       +---- Component Nodes
       |
       +---- Dependency Relationships
       |
       v
Graph Storage
       |
       v
Dependency Traversal
```

After the graph database layer is working, the project can proceed to dependency analysis, vulnerability intelligence integration, impact analysis, CRA validation, reporting, and eventually the frontend dashboard.

---

# 23. Development Roadmap

```text
Step 1   Backend Foundation                 ✓
Step 2   SBOM Ingestion                     ✓
Step 3   Format Detection                   ✓
Step 4   Validation                         ✓
Step 5   Parsing                            ✓
Step 6   Normalization                      ✓
Step 7   Neo4j Graph Database               → NEXT
Step 8   Dependency Analysis
Step 9   NVD Integration
Step 10  OSV Integration
Step 11  Vulnerability Correlation
Step 12  Impact Analysis
Step 13  CRA Rules
Step 14  CRA Validation
Step 15  Combined Analysis API
Step 16  Reports
Step 17  React Frontend
Step 18  Testing and Evaluation
Step 19  Final Demonstration
```

The check marks indicate functionality already implemented in the current backend. The remaining stages are planned development work.
