
import { findImpactedComponents } from "../src/services/impactAnalysisService.js";

const tests = [
  {
    label: "SBOM 1 - Log4j 2.14.1",
    sbomId: "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:152",
    componentId:
      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  },
  {
    label: "SBOM 2 - Log4j 2.17.1",
    sbomId: "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:157",
    componentId:
      "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
  },
];

async function runTests() {
  for (const test of tests) {
    console.log(`\n--- ${test.label} ---`);

    const impacted = await findImpactedComponents(
      test.componentId,
      test.sbomId
    );

    console.log("SBOM ID:", test.sbomId);
    console.log("Impacted components:");
    console.log(JSON.stringify(impacted, null, 2));
  }

  process.exit(0);
}

runTests().catch((error) => {
  console.error("TEST FAILED:", error);
  process.exit(1);
});
