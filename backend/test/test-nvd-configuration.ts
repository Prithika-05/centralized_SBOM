import assert from "node:assert/strict";
import { hasMatchingCPE } from "../src/services/nvdService.js";

const configuration = {
  operator: "AND",
  nodes: [
    {
      cpeMatch: [
        {
          vulnerable: true,
          criteria:
            "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
          versionStartIncluding: "2.13.0",
          versionEndExcluding: "2.15.0",
        },
      ],
    },
    {
      cpeMatch: [
        {
          vulnerable: false,
          criteria:
            "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
        },
      ],
    },
  ],
};

const result = hasMatchingCPE(
  configuration,
  "2.14.1",
  "log4j-core",
  "Maven"
);

console.log("AND configuration test result:", result);

assert.equal(
  result.status,
  "INDETERMINATE",
  "An unknown environmental requirement should be indeterminate"
);

console.log("AND configuration test passed.");


// Test: An empty configuration must be indeterminate.
const emptyResult = hasMatchingCPE(
  { operator: "AND", nodes: [] },
  "2.14.1",
  "log4j-core",
  "Maven"
);

assert.equal(emptyResult.status, "INDETERMINATE");

// Test: A confirmed package match should return MATCH.
const packageMatch = hasMatchingCPE(
  {
    operator: "OR",
    nodes: [
      {
        cpeMatch: [
          {
            vulnerable: true,
            criteria:
              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            versionStartIncluding: "2.13.0",
            versionEndExcluding: "2.15.0",
          },
        ],
      },
    ],
  },
  "2.14.1",
  "log4j-core",
  "Maven"
);

assert.equal(packageMatch.status, "MATCH");

// Test: A version outside the affected range must not match.
const versionMismatch = hasMatchingCPE(
  {
    operator: "OR",
    nodes: [
      {
        cpeMatch: [
          {
            vulnerable: true,
            criteria:
              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            versionStartIncluding: "2.13.0",
            versionEndExcluding: "2.15.0",
          },
        ],
      },
    ],
  },
  "2.15.0",
  "log4j-core",
  "Maven"
);

assert.equal(versionMismatch.status, "INDETERMINATE");

console.log("All configuration assertions passed.");