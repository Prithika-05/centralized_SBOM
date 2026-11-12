
import dotenv from "dotenv";

dotenv.config();

export interface NVDVulnerability {
  id: string;
  description: string;
  severity?: string;
  cvssScore?: number;
}

// Compare common software version formats, including versions with qualifiers.
export function compareVersions(a: string, b: string): number {
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

    if (x === undefined) {
      const remaining = right.slice(i);

      if (
        remaining.every(
          (part) =>
            typeof part === "string" &&
            ["final", "ga", "release"].includes(part)
        )
      ) {
        return 0;
      }

      return typeof y === "string" ? 1 : -1;
    }

    if (y === undefined) {
      const remaining = left.slice(i);

      if (
        remaining.every(
          (part) =>
            typeof part === "string" &&
            ["final", "ga", "release"].includes(part)
        )
      ) {
        return 0;
      }

      return typeof x === "string" ? -1 : 1;
    }

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

// Map supported package names to their corresponding CPE identities.
const CPE_IDENTITIES: Record<
  string,
  { vendor: string; products: string[] }
> = {
  "maven:log4j-core": {
    vendor: "apache",
    products: ["log4j-core", "log4j"],
  },
  "maven:log4j": {
    vendor: "apache",
    products: ["log4j"],
  },
};

// Check whether an installed package version falls within
// the affected version range specified by an NVD CPE match.
function matchesAffectedVersion(
  cpeMatch: any,
  installedVersion: string,
  packageName: string,
  ecosystem: string
): boolean {
  if (cpeMatch.vulnerable !== true) return false;

  const criteria = cpeMatch.criteria || cpeMatch.cpe23Uri;

  if (typeof criteria !== "string") return false;

  const parts = criteria.split(":");

  // CPE format: cpe:2.3:type:vendor:product:version:...
  const vendor = parts[3]?.toLowerCase();
  const product = parts[4]?.toLowerCase();
  const cpeVersion = parts[5];

  const identityKey =
    `${ecosystem.toLowerCase().trim()}:${packageName.toLowerCase().trim()}`;

  const identity = CPE_IDENTITIES[identityKey];

  if (!identity) return false;

  // Match the expected vendor and product.
  if (vendor !== identity.vendor) return false;

  if (!product || !identity.products.includes(product)) {
    return false;
  }

  const hasRange =
    cpeMatch.versionStartIncluding !== undefined ||
    cpeMatch.versionStartExcluding !== undefined ||
    cpeMatch.versionEndIncluding !== undefined ||
    cpeMatch.versionEndExcluding !== undefined;

  // If there is no version range, check the CPE version.
  if (!hasRange) {
    if (cpeVersion === "*") {
      return true;
    }

    if (!cpeVersion || cpeVersion === "-") {
      return false;
    }

    return compareVersions(installedVersion, cpeVersion) === 0;
  }

  // Check the lower version boundary.
  if (
    cpeMatch.versionStartIncluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionStartIncluding
    ) < 0
  ) {
    return false;
  }

  if (
    cpeMatch.versionStartExcluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionStartExcluding
    ) <= 0
  ) {
    return false;
  }

  // Check the upper version boundary.
  if (
    cpeMatch.versionEndIncluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionEndIncluding
    ) > 0
  ) {
    return false;
  }

  if (
    cpeMatch.versionEndExcluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionEndExcluding
    ) >= 0
  ) {
    return false;
  }

  return true;
}

// Recursively inspect NVD configuration nodes and their CPE matches.
function hasMatchingCPE(
  configuration: any,
  installedVersion: string,
  packageName: string,
  ecosystem: string
): boolean {
  const nodes = configuration.nodes || [];

  if (nodes.length === 0) {
    return false;
  }

  const results = nodes.map((node: any) =>
    evaluateNode(
      node,
      installedVersion,
      packageName,
      ecosystem
    )
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

// Search the NVD database for vulnerabilities affecting
// the specified package, version and ecosystem.
export async function searchNVD(
  packageName: string,
  version: string,
  ecosystem: string = ""
): Promise<NVDVulnerability[]> {
  const normalizedPackageName = packageName
    .toLowerCase()
    .trim();

  const normalizedEcosystem = ecosystem
    .toLowerCase()
    .trim();

  // Build the ecosystem-aware package identity.
  const identityKey =
    `${normalizedEcosystem}:${normalizedPackageName}`;

  // Skip packages without a registered CPE mapping.
  if (!CPE_IDENTITIES[identityKey]) {
    console.log(
      `Skipping NVD search: no verified CPE mapping for ${ecosystem}:${packageName}`
    );

    return [];
  }

  const url = new URL(
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
  );

  const apiKey = process.env.NVD_API_KEY;

  // Broad discovery search; applicability is checked using CPE data.
  url.searchParams.set("keywordSearch", "log4j");

  console.log("NVD request URL:", url.toString());

  const response = await fetch(url, {
    headers: apiKey ? { apiKey } : undefined,
  });

  if (!response.ok) {
    throw new Error(
      `NVD API request failed: ${response.status}`
    );
  }

  const data = await response.json();

  // Filter vulnerabilities using package identity and version matching.
  const matchingVulnerabilities = (
    data.vulnerabilities || []
  ).filter((item: any) => {
    const configurations = item.cve?.configurations || [];

    return configurations.some((configuration: any) =>
      hasMatchingCPE(
        configuration,
        version,
        normalizedPackageName,
        normalizedEcosystem
      )
    );
  });

  console.log(
    `NVD returned ${matchingVulnerabilities.length} version-matched finding(s) for ${packageName}@${version}.`
  );

  // Extract relevant vulnerability information.
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

// Test the NVD API connection.
export async function testNVDConnection(): Promise<boolean> {
  try {
    const results = await searchNVD(
      "log4j-core",
      "2.14.1",
      "Maven"
    );

    console.log(
      `NVD returned ${results.length} version-matched vulnerability result(s).`
    );

    console.log("NVD sample results:", results.slice(0, 4));

    return true;
  } catch (error) {
    console.error("NVD request failed:", error);
    return false;
  }
}

// Recursively evaluate NVD configuration nodes.
function evaluateNode(
  node: any,
  installedVersion: string,
  packageName: string,
  ecosystem: string
): boolean {
  const operator = String(
    node.operator || "OR"
  ).toUpperCase();

  const cpeMatches = node.cpeMatch || [];

  // Evaluate nested child nodes recursively.
  const childResults = (node.children || []).map(
    (child: any) =>
      evaluateNode(
        child,
        installedVersion,
        packageName,
        ecosystem
      )
  );

  // Evaluate individual CPE matches.
  const matchResults = cpeMatches.map((match: any) =>
    matchesAffectedVersion(
      match,
      installedVersion,
      packageName,
      ecosystem
    )
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
