
import { searchNVD } from "../src/services/nvdService";

async function test() {
  const results = await searchNVD(
    "tomcat-catalina",
    "9.0.80",
    "Maven"
  );

  const expectedCVEs = [
    "CVE-2023-42794",
    "CVE-2023-42795",
    "CVE-2023-45648",
    "CVE-2024-23672",
  ];

  for (const cve of expectedCVEs) {
    const finding = results.find((item) => item.id === cve);

    console.log({
      cve,
      found: !!finding,
      severity: finding?.severity,
      cvssScore: finding?.cvssScore,
      description: finding?.description,
    });
  }
}

test().catch(console.error);

