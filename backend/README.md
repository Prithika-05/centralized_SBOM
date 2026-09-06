# Centralized SBOM Management System --- Backend

A TypeScript/Node.js backend for the Centralized Software Bill of
Materials (SBOM) Management System. The backend is being developed
incrementally, beginning with the HTTP/API foundation and SBOM ingestion
layer.

The target architecture supports SPDX and CycloneDX SBOM ingestion,
validation, parsing, dependency normalization, graph-based dependency
analysis, vulnerability intelligence integration, CRA compliance
validation, and reporting.

------------------------------------------------------------------------

## 1. Backend

### Technology Stack

-   **Runtime:** Node.js
-   **Language:** TypeScript
-   **HTTP Framework:** Express
-   **CORS:** `cors`
-   **Environment Configuration:** `dotenv`
-   **File Upload Handling:** `multer`
-   **Development Runner:** `tsx`
-   **Type Definitions:** `@types/node`, `@types/express`,
    `@types/cors`, `@types/multer`

### Current Implementation Scope

The current backend implementation covers the first two development
stages:

1.  **Step 1 --- Backend Foundation**
    -   TypeScript project configuration
    -   Express HTTP server
    -   CORS and JSON middleware
    -   Environment-based port configuration
    -   Root and health-check endpoints
2.  **Step 2 --- SBOM Ingestion**
    -   Multipart SBOM file upload
    -   File persistence under the SBOM upload directory
    -   Basic upload response metadata
    -   Missing-file error handling

SBOM format detection, validation, parsing, normalization, graph
storage, vulnerability intelligence, CRA compliance validation, and
reporting are intentionally implemented in later development stages.

------------------------------------------------------------------------

# 2. Prerequisites

Install the following before starting the backend:

-   Node.js --- LTS version recommended
-   npm --- installed with Node.js
-   A terminal such as PowerShell, Command Prompt, or Bash
-   Postman or another HTTP client for API testing

Verify the installation:

``` bash
node --version
npm --version
```

------------------------------------------------------------------------

# 3. Installation

From the repository root:

``` bash
cd backend
```

Initialize the project if it has not already been initialized:

``` bash
npm init -y
```

Install runtime dependencies:

``` bash
npm install express cors dotenv multer
```

Install development and TypeScript dependencies:

``` bash
npm install -D typescript tsx @types/node @types/express @types/cors @types/multer
```

------------------------------------------------------------------------

# 4. Backend Structure

Current implementation:

``` text
backend/
├── src/
│   ├── modules/
│   │   └── sbom/
│   │       ├── routes.ts
│   │       └── uploads/
│   │
│   └── server.ts
│
├── .env
├── .gitignore
├── package.json
└── tsconfig.json
```

### Runtime flow

``` text
Client
  |
  | HTTP request
  v
Express Server
  |
  +--> /api/health
  |
  +--> /api/sboms/upload
           |
           v
        Multer
           |
           v
      Upload Directory
```

------------------------------------------------------------------------

# 5. Starting the Backend

The backend can be started directly with `tsx`:

``` powershell
npx tsx .\src\server.ts
```

If the development script is configured in `package.json`, it can also
be started with:

``` bash
npm run dev
```

Expected output:

``` text
SBOM backend running on http://localhost:5000
```

The server uses port `5000` by default unless the `PORT` environment
variable is configured differently.

------------------------------------------------------------------------

# 6. Environment Configuration

Create a `.env` file in the backend root:

``` env
PORT=5000
NODE_ENV=development
```

`dotenv` loads these values into `process.env` when the server starts.

Do not commit `.env` to source control because later development stages
will place external-service credentials and database configuration in
this file.

------------------------------------------------------------------------

# 7. Step 1 --- Backend Foundation

## 7.1 `src/server.ts`

``` typescript
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

**Description:** Initializes the Express/TypeScript backend, loads
environment variables, registers middleware, exposes health endpoints,
and mounts the SBOM API.\
**Collaboration:** `server.ts` is the application entry point and
delegates SBOM-specific HTTP handling to `src/modules/sbom/routes.ts`.

------------------------------------------------------------------------

## 7.2 `tsconfig.json`

``` json
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

**Description:** Configures TypeScript compilation for a strict Node.js
backend using the NodeNext module system.\
**Collaboration:** It defines how all TypeScript source files under
`src/` are type-checked and compiled into `dist/`.

------------------------------------------------------------------------

## 7.3 `package.json`

The relevant project configuration is:

``` json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js"
  }
}
```

The installed dependencies are:

``` json
{
  "dependencies": {
    "cors": "^...",
    "dotenv": "^...",
    "express": "^...",
    "multer": "^..."
  },
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

**Description:** Defines the backend package metadata, runtime
dependencies, development dependencies, and executable npm commands.\
**Collaboration:** The scripts provide standardized commands for running
the TypeScript server, watching changes, compiling the project, and
starting the compiled backend.

> Dependency versions are intentionally represented with placeholders
> above; `npm install` writes the exact versions resolved by npm into
> the actual project.

------------------------------------------------------------------------

## 7.4 `.env`

``` env
PORT=5000
NODE_ENV=development
```

**Description:** Provides environment-specific runtime configuration
without hard-coding deployment values into the application source.\
**Collaboration:** `dotenv.config()` in `server.ts` loads these values,
and `PORT` controls the Express listening port.

------------------------------------------------------------------------

## 7.5 `.gitignore`

``` gitignore
node_modules/
dist/
.env
*.log
```

**Description:** Prevents generated dependencies, compiled output,
environment secrets, and log files from being committed to source
control.\
**Collaboration:** It protects the repository while the backend is
developed locally and later deployed through different environments.

------------------------------------------------------------------------

# 8. Step 1 API Endpoints

## Root

``` http
GET /
```

Response:

``` json
{
  "name": "Centralized SBOM Management System",
  "status": "running"
}
```

## Health Check

``` http
GET /api/health
```

Response:

``` json
{
  "status": "OK",
  "service": "SBOM Backend"
}
```

The health endpoint is intended as a lightweight service availability
check and does not perform SBOM processing.

------------------------------------------------------------------------

# 9. Step 2 --- SBOM Ingestion

Step 2 introduces the first functional SBOM operation: accepting an SBOM
file through a multipart HTTP request.

## 9.1 `src/modules/sbom/routes.ts`

``` typescript
import { Router } from "express";
import multer from "multer";

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

  res.json({
    message: "SBOM uploaded successfully",
    file: {
      originalName: req.file.originalname,
      storedName: req.file.filename,
      size: req.file.size,
      path: req.file.path,
    },
  });
});

export default router;
```

**Description:** Defines the SBOM upload route and uses Multer to
receive a single multipart file named `sbom`.\
**Collaboration:** The router is mounted by `server.ts` at `/api/sboms`,
producing the complete endpoint `POST /api/sboms/upload`.

------------------------------------------------------------------------

## 9.2 `src/server.ts` --- Step 2 route integration

The SBOM route is connected to Express with:

``` typescript
import sbomRoutes from "./modules/sbom/routes.js";

app.use("/api/sboms", sbomRoutes);
```

**Description:** Registers the SBOM router under the `/api/sboms` API
namespace.\
**Collaboration:** Express forwards `/api/sboms/upload` requests to the
upload handler defined in `routes.ts`.

------------------------------------------------------------------------

# 10. Step 2 API --- Upload SBOM

### Endpoint

``` http
POST /api/sboms/upload
```

### Content Type

``` http
Content-Type: multipart/form-data
```

### Form field

``` text
sbom
```

The request structure is:

``` text
POST /api/sboms/upload
        |
        v
multipart/form-data
        |
        +-- sbom = <SBOM file>
```

### Successful response

Example:

``` json
{
  "message": "SBOM uploaded successfully",
  "file": {
    "originalName": "example.json",
    "storedName": "generated-file-name",
    "size": 12345,
    "path": "src/modules/sbom/uploads/generated-file-name"
  }
}
```

### Missing file response

HTTP status:

``` text
400 Bad Request
```

Response:

``` json
{
  "error": "No SBOM file uploaded"
}
```

------------------------------------------------------------------------

# 11. Testing the Upload

Start the backend:

``` bash
npm run dev
```

or:

``` powershell
npx tsx .\src\server.ts
```

Using Postman:

1.  Create a `POST` request.
2.  Set the URL to:

``` text
http://localhost:5000/api/sboms/upload
```

3.  Select **Body → form-data**.
4.  Create a field named:

``` text
sbom
```

5.  Change its type from `Text` to `File`.
6.  Select an SBOM file.
7.  Click **Send**.

The uploaded file should be written to:

``` text
src/modules/sbom/uploads/
```

At this stage, the backend only receives and stores the file. It does
not yet verify whether the document is a valid SPDX or CycloneDX SBOM.

------------------------------------------------------------------------

# 12. Current Processing Boundary

The current implementation ends here:

``` text
SBOM File
    |
    v
POST /api/sboms/upload
    |
    v
Multer
    |
    v
Stored File
```

The next development stages will extend this into:

``` text
Stored SBOM
    |
    v
Format Detection
    |
    +------ SPDX
    |
    +------ CycloneDX
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
Graph Database
    |
    v
Vulnerability Intelligence
    |
    +------ NVD
    |
    +------ OSV
    |
    v
Impact Analysis
    |
    v
CRA Compliance Validation
    |
    v
Reporting API
```

This ordering follows the proposed system design: ingestion, validation,
parsing, dependency normalization, graph storage, vulnerability
intelligence, CRA compliance validation, and reporting.

------------------------------------------------------------------------

# 13. Development Principles

### Modular backend

SBOM-specific functionality is placed under `src/modules/sbom/` rather
than implementing all application logic inside `server.ts`.

### Separation of concerns

`server.ts` is responsible for application startup and route
registration, while SBOM routes handle SBOM-specific HTTP operations.

### Type safety

TypeScript strict mode is enabled to detect type errors during
development and compilation.

### Configuration separation

Runtime configuration is supplied through `.env` rather than being
embedded directly into application code.

### Incremental implementation

The backend is intentionally developed in small verified stages: server
foundation first, ingestion second, and processing/security capabilities
afterwards.

------------------------------------------------------------------------

# 14. Next Development Stage

The next stage is **Step 3 --- SBOM Format Detection**.

The intended processing decision is:

``` text
Uploaded SBOM
      |
      v
Read document
      |
      v
Identify format
      |
      +---- SPDX
      |
      +---- CycloneDX
      |
      +---- Unknown → reject/handle
```

Only after format identification will the backend proceed to
standard-specific validation and parsing.