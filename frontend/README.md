# Centralized SBOM Management System

A prototype platform for centralized Software Bill of Materials (SBOM)
management, vulnerability intelligence, dependency analysis, and
preliminary Cyber Resilience Act (CRA)-related checks.

## 1. Overview

Modern applications depend on many third-party packages. When a
vulnerability is disclosed, teams need to know which components are
present, how they depend on one another, and which applications may be
affected.

The **Centralized SBOM Management System** aims to bring these
activities into one workflow. It accepts SBOM files, extracts and
normalizes component data, supports graph-based dependency analysis,
queries public vulnerability sources, and provides an initial set of
CRA-related metadata checks.

> **Project status:** This README describes the prototype and the
> implementation steps discussed so far. Some services and frontend
> features have been implemented or started, but complete end-to-end
> operation has not yet been verified. In particular, Neo4j connectivity
> has previously failed because the driver could not connect to
> `127.0.0.1:7687`.

## 2. Project Goals

-   Centralize SBOM ingestion and component inventory.
-   Support SPDX and CycloneDX SBOM formats.
-   Normalize component information into a common internal
    representation.
-   Represent components and dependencies in a graph database.
-   Correlate components with vulnerability information from NVD and
    OSV.
-   Explore direct and transitive dependency impact.
-   Provide preliminary automated checks for selected CRA-related
    documentation requirements.
-   Present analysis results through a web interface and, as the project
    develops, reports.

## 3. Main Features and Current Status

  -----------------------------------------------------------------------
  Area                    Purpose                 Status based on work
                                                  discussed
  ----------------------- ----------------------- -----------------------
  Backend foundation      Node.js, Express, and   Implemented
                          TypeScript API          

  File upload             Accept SBOM files using Implemented
                          Multer                  

  Format detection        Identify SPDX and       Implemented
                          CycloneDX inputs        

  Validation and parsing  Validate and extract    Implemented; needs test
                          component data          coverage

  Normalization           Convert extracted data  Implemented; needs
                          to a common structure   cross-format
                                                  verification

  Dependency analysis     Identify direct and     Implemented; requires
                          transitive dependencies graph-data testing

  Neo4j integration       Store and query         Service created;
                          component relationships connection needs fixing
                                                  and verification

  NVD integration         Retrieve vulnerability  Implemented; matching
                          intelligence            accuracy needs
                                                  evaluation

  OSV integration         Retrieve open-source    Implemented; matching
                          vulnerability           accuracy needs
                          intelligence            evaluation

  Vulnerability           Combine findings from   Implemented; requires
  correlation             vulnerability sources   test cases

  Impact analysis         Explore dependency      Implemented; requires
                          relationships related   graph verification
                          to vulnerable           
                          components              

  CRA-related checks      Check selected metadata Prototype only; not
                          and documentation       legal compliance
                          conditions              certification

  Combined                Return analysis data    Implemented; end-to-end
  analysis/report service through the backend     verification pending

  React frontend          Vite, React, and        Started
                          TypeScript application  

  Upload interface        Select/upload an SBOM   Started
                          and display a response  

  Component analysis      Request component       Proposed next frontend
  panel                   analysis from the UI    step; confirm route and
                                                  implementation before
                                                  use

  Dashboard and           Visual summaries and    Not yet confirmed as
  downloadable reports    exportable reports      completed
  -----------------------------------------------------------------------

**Important:** "Implemented" means the feature has been discussed or its
code has been developed. It does not mean the feature has passed
integration or acceptance testing.

## 4. Technology Stack

-   **Backend:** Node.js, Express, TypeScript
-   **Frontend:** React, TypeScript, Vite
-   **File upload:** Multer
-   **Graph database:** Neo4j
-   **SBOM formats:** SPDX and CycloneDX
-   **Vulnerability sources:** National Vulnerability Database (NVD) and
    Open Source Vulnerabilities (OSV)

The exact versions, environment variables, scripts, and dependency
requirements should be taken from the current `package.json` files and
environment configuration in the repository.

## 5. Architecture

The intended data flow is:

``` text
User
  |
  v
React Web Interface
  |
  v
Express / TypeScript API
  |
  +--> Upload and format detection
  |
  +--> Validation, parsing, and normalization
  |
  +--> Neo4j component and dependency graph
  |
  +--> NVD and OSV vulnerability lookups
  |
  +--> Vulnerability correlation and impact analysis
  |
  +--> Preliminary CRA-related checks
  |
  v
Analysis response / report
  |
  v
Web interface
```

### Core modules

1.  **SBOM ingestion:** Receives an SBOM file and detects its supported
    format.
2.  **Validation and parsing:** Checks the input and extracts package
    identifiers, names, versions, and dependency information available
    in the file.
3.  **Normalization:** Converts format-specific fields into a consistent
    internal structure.
4.  **Graph storage:** Stores components and relationships in Neo4j to
    support dependency traversal.
5.  **Vulnerability intelligence:** Queries NVD and OSV and correlates
    returned records with package data.
6.  **Impact analysis:** Uses dependency relationships to explore which
    components may be affected by a vulnerable dependency.
7.  **CRA-related checks:** Evaluates selected metadata or documentation
    conditions and reports missing information.
8.  **Frontend and reporting:** Lets users upload SBOMs and view backend
    results; richer dashboard and export features remain future work
    unless present in the current code.

## 6. Repository Layout

The backend paths confirmed in the implementation discussion include:

``` text
centralized_SBOM/
├── backend/
│   ├── src/
│   │   ├── server.ts
│   │   └── services/
│   │       └── neo4jService.ts
│   ├── package.json
│   └── ...
└── frontend/
    ├── src/
    │   ├── App.tsx
    │   └── App.css
    ├── package.json
    └── ...
```

This is an indicative layout, not a complete file listing. Keep the
actual repository structure as the source of truth.

## 7. Setup and Configuration

### Prerequisites

Install a compatible Node.js version and npm. Run Neo4j locally or
configure access to a reachable Neo4j instance. Network access is
required for live NVD/OSV lookups.

### Install dependencies

Open separate terminals for the backend and frontend:

``` bash
cd backend
npm install
```

``` bash
cd frontend
npm install
```

Use the scripts defined in each directory's `package.json`; do not
assume script names that are not present in the repository.

### Configure environment variables

Set the Neo4j URI, username, password, and any API keys or backend
settings required by the current source code in a local environment
file. Use the exact variable names read by the application.

Example values are illustrative only:

``` dotenv
# Example only — match these names to your source code.
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=replace-with-your-local-password
```

Do not commit passwords, API keys, or other secrets to version control.
If the project uses a `neo4j://` URI, ensure the target database
supports routing and is reachable; for a local standalone instance, use
the connection URI appropriate to that instance.

### Start the services

Use the development commands defined in the respective `package.json`
files. The backend and frontend normally run in separate terminals.
Confirm the backend port and frontend API URL from the current
configuration before testing.

## 8. Neo4j Connection Troubleshooting

A previously observed error was:

``` text
Could not perform discovery. No routing servers available.
ECONNREFUSED 127.0.0.1:7687
```

This indicates that the driver could not establish a connection to the
Bolt endpoint. It is generally a connectivity/configuration problem, not
proof that the Cypher query itself is incorrect.

Check in this order:

1.  Confirm Neo4j is installed and the database instance is running.
2.  Confirm Bolt is enabled and listening on the configured host and
    port (commonly `localhost:7687` for a local setup).
3.  Check that the URI scheme matches the deployment. Routing schemes
    such as `neo4j://` require routing discovery to work; a local
    standalone instance may use `bolt://`.
4.  Verify the username and password.
5.  Confirm the configured database name exists and is accessible.
6.  Restart the backend after changing environment settings.
7.  Re-run the project's connection test and check the server logs.

Never publish database credentials in logs, screenshots, or this README.

## 9. Typical Workflow

1.  Prepare an SBOM in SPDX or CycloneDX format.
2.  Upload the file through the web interface or the configured API
    endpoint.
3.  Validate the file and detect its format.
4.  Parse and normalize component and dependency data.
5.  Store the graph data in Neo4j, once database connectivity is
    working.
6.  Query NVD and OSV for vulnerability information.
7.  Correlate findings with package names, identifiers, and versions.
8.  Traverse dependency relationships to investigate potential impact.
9.  Run the available CRA-related metadata checks.
10. Review the response and record test results.

The precise endpoint paths and request schemas should be confirmed from
the current Express route definitions. Do not rely on an endpoint
example unless it exists in the code.

## 10. Testing and Evaluation Plan

The project's research design identifies two principal evaluation areas.

### A. Vulnerability detection

-   Use representative SPDX and CycloneDX SBOM files.
-   Include packages with known vulnerable and non-vulnerable versions.
-   Compare system findings with authoritative NVD/OSV records.
-   Record true positives, false positives, false negatives, and true
    negatives where a reliable ground truth is available.
-   Test direct and transitive dependency discovery.
-   Record lookup failures, response times, and incomplete API results.

### B. CRA-related validation

-   Prepare SBOMs with required fields present and deliberately missing.
-   Check whether the prototype identifies missing metadata
    consistently.
-   Record each rule, its expected outcome, and the observed outcome.
-   Clearly distinguish automated metadata checks from a legal
    assessment of CRA compliance.

### Integration checks

-   Upload valid and invalid files in both supported formats.
-   Verify component and relationship persistence in Neo4j.
-   Test backend errors and unavailable external APIs.
-   Confirm the frontend handles loading states, unsuccessful responses,
    and network failures.
-   Repeat tests with documented inputs so results are reproducible.

Do not claim accuracy or compliance performance until these experiments
have been run and their results recorded.

## 11. Known Limitations

-   Neo4j connectivity has previously failed with `ECONNREFUSED` on
    `127.0.0.1:7687`; graph persistence and graph queries therefore need
    confirmation.
-   Full frontend-to-backend integration has not yet been confirmed.
-   Package-name or keyword matching can produce false positives.
    Correct vulnerability matching requires package identity and
    affected-version evaluation.
-   Vulnerability data can be incomplete, delayed, or unavailable when
    external APIs fail.
-   Dependency impact analysis is only as reliable as the parsed SBOM
    and stored graph relationships.
-   The CRA module is a prototype of selected checks. It must not be
    presented as proof of full compliance with Regulation (EU)
    2024/2847.
-   A polished dashboard and downloadable report are planned
    improvements, not confirmed completed features.

## 12. Development Roadmap

1.  **Stabilize the foundation:** Fix Neo4j connectivity and verify
    upload, parsing, normalization, and storage.
2.  **Verify API contracts:** Confirm actual routes, request parameters,
    response shapes, and error handling.
3.  **Complete end-to-end tests:** Run sample SBOMs through the entire
    backend workflow.
4.  **Build the analysis dashboard:** Present component counts,
    vulnerability findings, severity, dependencies, and CRA-check
    results in readable sections.
5.  **Improve analysis quality:** Validate package identifiers,
    affected-version ranges, duplicate findings, and direct/transitive
    impact.
6.  **Add reporting:** Provide a clear exportable analysis report with
    timestamps and source information.
7.  **Evaluate and document:** Record experimental data, limitations,
    screenshots, and reproducible results.

## 13. Security and Responsible Use

-   Use public or otherwise authorized SBOM and vulnerability data for
    testing.
-   Keep credentials and API keys out of source control.
-   Validate uploaded files and apply sensible file-size and request
    limits.
-   Treat SBOM contents and external API responses as untrusted input.
-   Do not describe a component as vulnerable solely because a text
    search returns a similarly named package.
-   Present findings as analysis results requiring appropriate
    verification, not as a guarantee that a system is secure.

## 14. Research Context

The project follows an iterative, Design Science Research approach:
identify the SBOM-management problem, define objectives, build the
software artefact, demonstrate it with sample data, evaluate it, and
communicate the results. Its central research concerns are
cross-ecosystem SBOM management, vulnerability detection and dependency
impact analysis, and preliminary CRA-related validation.

The planned evaluation focuses on **vulnerability detection accuracy**
and **CRA-related validation performance**. Results should be reported
from actual experiments rather than inferred from the existence of code.

## 15. Summary

The prototype brings together SBOM ingestion, normalization,
vulnerability intelligence, graph-based dependency analysis, and
preliminary CRA-related checks. The next priority is to resolve Neo4j
connectivity and verify the complete data path. Once that foundation is
stable, frontend integration, dashboard presentation, reporting, and
measured evaluation can be completed.

------------------------------------------------------------------------

**Project:** Centralized SBOM Management System\
**Status:** Prototype under active development\
**Primary objective:** Improve software-component visibility and support
vulnerability and compliance-related analysis through a centralized
workflow
