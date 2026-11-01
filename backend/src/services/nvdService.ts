
import dotenv from "dotenv";

dotenv.config();

export interface NVDVulnerability {
  id: string;
  description: string;
  severity?: string;
  cvssScore?: number;
}

// Compare common software version formats, including versions with qualifiers.
function compareVersions(a: string, b: string): number {
  const tokenize = (value: string): (number | string)[] =>
    value.match(/\d+|[a-zA-Z]+/g)?.map((part) =>
      /^\d+$/.test(part) ? Number(part) : part.toLowerCase()
    ) ?? [];

  const left = tokenize(a);
  const right = tokenize(b);

  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i];
    const y = right[i];

    if (x === undefined && y === undefined) return 0;
    if (x === undefined) return typeof y === "string" ? 1 : -1;
    if (y === undefined) return typeof x === "string" ? -1 : 1;

    if (x === y) continue;

    if (typeof x === "number" && typeof y === "number") {
      return x < y ? -1 : 1;
    }

    if (typeof x === "number") return 1;
    if (typeof y === "number") return -1;

    return x < y ? -1 : 1;
  }

  return 0;
}

function matchesAffectedVersion(
  cpeMatch: any,
  installedVersion: string
): boolean {
  if (cpeMatch.vulnerable !== true) return false;

  const criteria = cpeMatch.criteria || cpeMatch.cpe23Uri;
  if (typeof criteria !== "string") return false;

  const parts = criteria.split(":");

  // CPE format: cpe:2.3:type:vendor:product:version:...
  const vendor = parts[3]?.toLowerCase();
  const product = parts[4]?.toLowerCase();
  const cpeVersion = parts[5];

  // Match Apache Log4j CPEs, not unrelated products mentioning Log4j.
  if (vendor !== "apache") return false;
  if (product !== "log4j" && product !== "log4j-core") return false;

  const hasRange =
    cpeMatch.versionStartIncluding !== undefined ||
    cpeMatch.versionStartExcluding !== undefined ||
    cpeMatch.versionEndIncluding !== undefined ||
    cpeMatch.versionEndExcluding !== undefined;

  // If there is no range, require an exact CPE version.
  if (!hasRange) {
    if (!cpeVersion || cpeVersion === "*" || cpeVersion === "-") {
      return false;
    }

    return compareVersions(installedVersion, cpeVersion) === 0;
  }

  if (
    cpeMatch.versionStartIncluding &&
    compareVersions(installedVersion, cpeMatch.versionStartIncluding) < 0
  ) {
    return false;
  }

  if (
    cpeMatch.versionStartExcluding &&
    compareVersions(installedVersion, cpeMatch.versionStartExcluding) <= 0
  ) {
    return false;
  }

  if (
    cpeMatch.versionEndIncluding &&
    compareVersions(installedVersion, cpeMatch.versionEndIncluding) > 0
  ) {
    return false;
  }

  if (
    cpeMatch.versionEndExcluding &&
    compareVersions(installedVersion, cpeMatch.versionEndExcluding) >= 0
  ) {
    return false;
  }

  return true;
}

// Recursively inspect NVD configuration nodes and their CPE matches.

function hasMatchingCPE(
  configuration: any,
  installedVersion: string
): boolean {
  const nodes = configuration.nodes || [];

  if (nodes.length === 0) {
    return false;
  }

  const results = nodes.map((node: any) =>
    evaluateNode(node, installedVersion)
  );

  const operator = String(
    configuration.operator || "OR"
  ).toUpperCase();

  let result: boolean;

  if (operator === "AND") {
    result = results.every(Boolean);
  } else {
    result = results.some(Boolean);
  }

  if (configuration.negate === true) {
    result = !result;
  }

  return result;
}

export async function searchNVD(
  packageName: string,
  version: string
): Promise<NVDVulnerability[]> {
  const url = new URL(
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
  );

  const apiKey = process.env.NVD_API_KEY;

  // Broad discovery search; applicability is checked using CPE data below.
  url.searchParams.set("keywordSearch", "log4j");

  console.log("NVD request URL:", url.toString());

  const response = await fetch(url, {
    headers: apiKey ? { apiKey } : undefined,
  });

  if (!response.ok) {
    throw new Error(`NVD API request failed: ${response.status}`);
  }

  const data = await response.json();

  const matchingVulnerabilities = (data.vulnerabilities || []).filter(
    (item: any) => {
      const configurations = item.cve?.configurations || [];

      return configurations.some((configuration: any) =>
      hasMatchingCPE(configuration, version)
    );
    }
  );

  console.log(
    `NVD returned ${matchingVulnerabilities.length} version-matched finding(s) for ${packageName}@${version}.`
  );

  return matchingVulnerabilities.map((item: any) => {
    const cve = item.cve;

    const description =
      cve.descriptions?.find(
        (description: any) => description.lang === "en"
      )?.value || "";

    const cvss =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
      cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
      cve.metrics?.cvssMetricV2?.[0]?.cvssData;

    return {
      id: cve.id,
      description,
      severity: cvss?.baseSeverity,
      cvssScore: cvss?.baseScore,
    };
  });
}

export async function testNVDConnection(): Promise<boolean> {
  try {
    const results = await searchNVD("log4j-core", "2.14.1");

    console.log(
      `NVD returned ${results.length} version-matched vulnerability result(s).`
    );

    return true;
  } catch (error) {
    console.error("NVD request failed:", error);
    return false;
  }
}



function evaluateNode(
  node: any,
  installedVersion: string
): boolean {
  const operator = String(node.operator || "OR").toUpperCase();

  const cpeMatches = node.cpeMatch || [];

  const childResults = (node.children || []).map(
    (child: any) => evaluateNode(child, installedVersion)
  );

  const matchResults = cpeMatches.map((match: any) =>
    matchesAffectedVersion(match, installedVersion)
  );

  const results = [...matchResults, ...childResults];

  if (results.length === 0) {
    return false;
  }

  let result: boolean;

  if (operator === "AND") {
    result = results.every(Boolean);
  } else {
    result = results.some(Boolean);
  }

  // Apply NVD's explicit negation condition.
  if (node.negate === true) {
    result = !result;
  }

  return result;
}


