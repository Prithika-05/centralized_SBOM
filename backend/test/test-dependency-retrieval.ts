import {
  getDirectDependencies,
  getTransitiveDependencies,
} from "../src/services/dependencyService.js";

const sbomId =
  "4:77ebe7e0-220f-4804-aa1c-5ffad78600cb:151";

async function testDependencies() {
  try {
    const applicationId = "my-application@1.0.0";
    const libraryId = "pkg:npm/library-a@1.0.0";

    console.log("\n--- APPLICATION: DIRECT ---");
    console.log(
      JSON.stringify(
        await getDirectDependencies(applicationId, sbomId),
        null,
        2
      )
    );

    console.log("\n--- APPLICATION: TRANSITIVE ---");
    console.log(
      JSON.stringify(
        await getTransitiveDependencies(applicationId, sbomId),
        null,
        2
      )
    );

    console.log("\n--- LIBRARY-A: DIRECT ---");
    console.log(
      JSON.stringify(
        await getDirectDependencies(libraryId, sbomId),
        null,
        2
      )
    );
  } catch (error) {
    console.error("DEPENDENCY TEST FAILED:", error);
  } finally {
    process.exit(0);
  }
}

testDependencies();