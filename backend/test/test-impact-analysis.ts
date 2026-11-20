
import { analyzeComponent } from "../src/services/analysisService.js";

const sbomId =
  "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:152";

async function testCRAValidation() {
  try {
    const result = await analyzeComponent(
      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "log4j-core",
      "2.14.1",
      sbomId
    );

    console.log("\n--- CRA VALIDATION RESULTS ---");
    console.log(
      JSON.stringify(result.craValidation, null, 2)
    );

    console.log("\n--- CRA SUMMARY ---");
    console.log(
      "All checks passed:",
      result.craValidation.compliant
    );
  } catch (error) {
    console.error("CRA TEST FAILED:", error);
  } finally {
    process.exit(0);
  }
}

testCRAValidation();
