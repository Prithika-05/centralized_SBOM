
import { findImpactedComponents, hasDependencyRelationships } from "../src/services/impactAnalysisService.js";
import { hasValidatedSBOM } from "../src/services/sbomGraphService.js";

const tests = [
  {
    name: "SBOM 1 - Log4j 2.14.1",
    sbomId: "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:152",
    componentId: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  },
  {
    name: "SBOM 2 - Log4j 2.17.1",
    sbomId: "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:160",
    componentId: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
  },
  {
  name: "SBOM 3 - Log4j 2.14.1",
  sbomId: "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:166",
  componentId: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
},
];

async function runTests() {
  try {
    for (const test of tests) {
      console.log(`\n========== ${test.name} ==========`);

      const impacted = await findImpactedComponents(
        test.componentId,
        test.sbomId
      );

      const hasSBOM = await hasValidatedSBOM(
        test.componentId,
        test.sbomId
      );

      const hasDependencies = await hasDependencyRelationships(
        test.componentId,
        test.sbomId
      );

      console.log("Impacted components:", impacted);
      console.log("Validated SBOM:", hasSBOM);
      console.log("Has dependency relationships:", hasDependencies);
    }
  } catch (error) {
    console.error("ISOLATION TEST FAILED:", error);
  } finally {
    process.exit(0);
  }
}

runTests();
