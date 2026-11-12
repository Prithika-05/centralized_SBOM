
import {
  detectEcosystem,
  extractOSVPackageName,
} from "./src/services/vulnerabilityCorrelationService";

const testCases = [
  {
    id: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    expected: "org.apache.logging.log4j:log4j-core",
  },
  {
    id: "pkg:npm/express@4.18.2",
    expected: "express",
  },
  {
    id: "pkg:npm/%40angular/core@17.0.0",
    expected: "@angular/core",
  },
  {
    id: "pkg:pypi/requests@2.31.0",
    expected: "requests",
  },
  {
    id: "pkg:nuget/Newtonsoft.Json@13.0.1",
    expected: "Newtonsoft.Json",
  },
];

for (const test of testCases) {
  const ecosystem = detectEcosystem(test.id);

  const actual = extractOSVPackageName(
    test.id,
    ecosystem,
    "fallback"
  );

  console.log({
    packageId: test.id,
    expected: test.expected,
    actual,
    passed: actual === test.expected,
  });
}
