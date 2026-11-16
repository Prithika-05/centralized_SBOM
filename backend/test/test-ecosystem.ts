import { detectEcosystem } from "../src/services/vulnerabilityCorrelationService";

const testCases = [
  { id: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", expected: "Maven" },
  { id: "pkg:npm/express@4.18.2", expected: "npm" },
  { id: "pkg:pypi/requests@2.31.0", expected: "PyPI" },
  { id: "pkg:nuget/Newtonsoft.Json@13.0.1", expected: "NuGet" },
  { id: "unknown-package", expected: "" },
];

for (const test of testCases) {
  const actual = detectEcosystem(test.id);

  console.log({
    package: test.id,
    expected: test.expected,
    actual,
    passed: actual === test.expected,
  });
}