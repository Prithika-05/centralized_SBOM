import { searchNVD } from "./src/services/nvdService";

async function test() {
  const results = await searchNVD("log4j-core", "2.14.1");

  console.log("\nTotal NVD findings:", results.length);

  for (const vulnerability of results) {
    console.log({
      id: vulnerability.id,
      severity: vulnerability.severity,
      cvssScore: vulnerability.cvssScore,
    });
  }

  const expectedCVEs = [
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2021-44832",
  ];

  console.log("\nExpected CVE verification:");

  for (const cve of expectedCVEs) {
    console.log({
      cve,
      found: results.some((item) => item.id === cve),
    });
  }
}

test().catch(console.error);