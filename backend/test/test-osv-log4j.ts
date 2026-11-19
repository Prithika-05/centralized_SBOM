
import { searchOSV } from "../src/services/osvService";

async function testLog4jVersions() {
  const versions = ["2.14.1", "2.17.1", "2.25.5"];

  for (const version of versions) {
    const results = await searchOSV(
      "org.apache.logging.log4j:log4j-core",
      version,
      "Maven"
    );

    console.log(`\nLog4j ${version}`);
    console.log(
      results.map((v) => ({
        id: v.id,
        aliases: v.aliases,
        severity: v.severity
      }))
    );
  }
}

testLog4jVersions().catch(console.error);
