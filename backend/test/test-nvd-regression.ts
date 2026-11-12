
import { searchNVD } from "../src/services/nvdService";

const expectedCVEs = [
  "CVE-2023-42794",
  "CVE-2023-42795",
  "CVE-2023-45648",
  "CVE-2024-23672",
];

async function testTomcatVersion(
  version: string,
  expectedAffected: boolean
) {
  const results = await searchNVD(
    "tomcat-catalina",
    version,
    "Maven"
  );

  for (const cve of expectedCVEs) {
    const found = results.some((item) => item.id === cve);
    const passed = found === expectedAffected;

    console.log({
      version,
      cve,
      expectedAffected,
      found,
      passed,
    });
  }
  console.log("\n===== TOMCAT EVIDENCE TEST =====");

const tomcatResults = await searchNVD(
  "tomcat-catalina",
  "9.0.80",
  "Maven"
);

console.log(
  "Sample Tomcat evidence:",
  tomcatResults.slice(0, 3).map((vulnerability) => ({
    id: vulnerability.id,
    matchedCPE: vulnerability.matchedCPE,
    matchedVersionRange: vulnerability.matchedVersionRange,
  }))
);

const evidencePassed = tomcatResults.length > 0 &&
  tomcatResults.every(
    (vulnerability) =>
      typeof vulnerability.matchedCPE === "string" &&
      vulnerability.matchedCPE.length > 0
  );

console.log(
  "Tomcat evidence test:",
  evidencePassed ? "PASS" : "FAIL"
);
}


async function testLog4jEvidence() {
  console.log("\n===== LOG4J EVIDENCE TEST =====");

  const results = await searchNVD(
    "log4j-core",
    "2.14.1",
    "Maven"
  );

  console.log(
    "Sample NVD evidence:",
    results.slice(0, 3).map((vulnerability) => ({
      id: vulnerability.id,
      matchedCPE: vulnerability.matchedCPE,
      matchedVersionRange: vulnerability.matchedVersionRange,
    }))
  );

  const evidencePassed =
    results.length > 0 &&
    results.every(
      (vulnerability) =>
        typeof vulnerability.matchedCPE === "string" &&
        vulnerability.matchedCPE.length > 0 &&
        vulnerability.matchedVersionRange !== undefined
    );

  console.log("Evidence test:", evidencePassed ? "PASS" : "FAIL");
}


async function runTests() {
  await testTomcatVersion("9.0.80", true);
  await testTomcatVersion("9.0.86", false);

  await testLog4jEvidence();
}

runTests().catch(console.error);
