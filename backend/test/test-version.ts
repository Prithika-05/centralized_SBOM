import { compareVersions } from "../src/services/nvdService";

const testCases = [
  {
    a: "2.14.1",
    b: "2.14.1",
    expected: 0,
  },
  {
    a: "2.14.1",
    b: "2.14.2",
    expected: -1,
  },
  {
    a: "2.15.0",
    b: "2.14.1",
    expected: 1,
  },
  {
    a: "2.14.1-beta",
    b: "2.14.1",
    expected: -1,
  },
  {
    a: "2.14.1-rc1",
    b: "2.14.1",
    expected: -1,
  },
  {
    a: "2.14.1",
    b: "2.14.1.Final",
    expected: 0,
    },
    {
    a: "2.14.1",
    b: "2.14.1.1",
    expected: -1,
    },
    {
    a: "2.14.10",
    b: "2.14.9",
    expected: 1,
    }
];

for (const test of testCases) {
  const actual = compareVersions(test.a, test.b);

  console.log({
    comparison: `${test.a} vs ${test.b}`,
    expected: test.expected,
    actual,
    passed: actual === test.expected,
  });
}