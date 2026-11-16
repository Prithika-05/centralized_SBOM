
import dotenv from "dotenv";

dotenv.config();

export interface NVDVulnerability {
  id: string;
  description: string;
  severity?: string;
  cvssScore?: number;
  matchedCPE?: string;
  matchedVersionRange?: {
    startIncluding?: string;
    startExcluding?: string;
    endIncluding?: string;
    endExcluding?: string;
  };
}

interface CPEMatchEvidence {
  matchedCPE: string;
  matchedVersionRange?: {
    startIncluding?: string;
    startExcluding?: string;
    endIncluding?: string;
    endExcluding?: string;
  };
}

type CPEMatchStatus =
  | "MATCH"
  | "NO_MATCH"
  | "INDETERMINATE";

interface CPEEvaluationResult {
  status: CPEMatchStatus;
  evidence: CPEMatchEvidence[];
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
  {
    vendor: string;
    products: string[];
    searchKeyword: string;
  }
> = {
  "maven:log4j-core": {
    vendor: "apache",
    products: ["log4j-core", "log4j"],
    searchKeyword: "log4j",
  },
  "maven:log4j": {
    vendor: "apache",
    products: ["log4j"],
    searchKeyword: "log4j",
  },
  "maven:tomcat-catalina": {
    vendor: "apache",
    products: ["tomcat"],
    searchKeyword: "tomcat",
  },
};
// Check whether an installed package version falls within
// the affected version range specified by an NVD CPE match.

function matchesAffectedVersion(
  cpeMatch: any,
  installedVersion: string,
  packageName: string,
  ecosystem: string
): {
  matchedCPE: string;
  matchedVersionRange?: {
    startIncluding?: string;
    startExcluding?: string;
    endIncluding?: string;
    endExcluding?: string;
  };
} | null {
  if (cpeMatch.vulnerable !== true) return null;

  const criteria = cpeMatch.criteria || cpeMatch.cpe23Uri;

  if (typeof criteria !== "string") return null;

  const parts = criteria.split(":");

  // CPE format: cpe:2.3:type:vendor:product:version:...
  const vendor = parts[3]?.toLowerCase();
  const product = parts[4]?.toLowerCase();
  const cpeVersion = parts[5];

  const identityKey =
    `${ecosystem.toLowerCase().trim()}:${packageName.toLowerCase().trim()}`;

  const identity = CPE_IDENTITIES[identityKey];

  if (!identity) return null;

  // Match the expected vendor and product.
  if (vendor !== identity.vendor) return null;

  if (!product || !identity.products.includes(product)) {
    return null;
  }

  const hasRange =
    cpeMatch.versionStartIncluding !== undefined ||
    cpeMatch.versionStartExcluding !== undefined ||
    cpeMatch.versionEndIncluding !== undefined ||
    cpeMatch.versionEndExcluding !== undefined;

  // Handle exact CPE versions and wildcard versions.
  if (!hasRange) {
    if (cpeVersion === "*") {
      return {
        matchedCPE: criteria,
        matchedVersionRange: {},
      };
    }

    if (!cpeVersion || cpeVersion === "-") {
      return null;
    }

    if (compareVersions(installedVersion, cpeVersion) !== 0) {
      return null;
    }

    return {
      matchedCPE: criteria,
      matchedVersionRange: {},
    };
  }

  // Check the lower version boundary.
  if (
    cpeMatch.versionStartIncluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionStartIncluding
    ) < 0
  ) {
    return null;
  }

  if (
    cpeMatch.versionStartExcluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionStartExcluding
    ) <= 0
  ) {
    return null;
  }

  // Check the upper version boundary.
  if (
    cpeMatch.versionEndIncluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionEndIncluding
    ) > 0
  ) {
    return null;
  }

  if (
    cpeMatch.versionEndExcluding &&
    compareVersions(
      installedVersion,
      cpeMatch.versionEndExcluding
    ) >= 0
  ) {
    return null;
  }

  return {
    matchedCPE: criteria,
    matchedVersionRange: {
      startIncluding: cpeMatch.versionStartIncluding,
      startExcluding: cpeMatch.versionStartExcluding,
      endIncluding: cpeMatch.versionEndIncluding,
      endExcluding: cpeMatch.versionEndExcluding,
    },
  };
}

export function hasMatchingCPE(
  configuration: any,
  installedVersion: string,
  packageName: string,
  ecosystem: string
): CPEEvaluationResult {
  const nodes = configuration.nodes || [];

  if (nodes.length === 0) {
    return { status: "INDETERMINATE", evidence: [] };
  }

  const results: CPEEvaluationResult[] = nodes.map((node: any) =>
    evaluateNode(node, installedVersion, packageName, ecosystem)
  );

  const operator = String(configuration.operator || "OR").toUpperCase();

  let status: CPEMatchStatus;

  if (operator === "AND") {
    if (results.some((result) => result.status === "NO_MATCH")) {
      status = "NO_MATCH";
    } else if (results.every((result) => result.status === "MATCH")) {
      status = "MATCH";
    } else {
      status = "INDETERMINATE";
    }
  } else {
    if (results.some((result) => result.status === "MATCH")) {
      status = "MATCH";
    } else if (results.every((result) => result.status === "NO_MATCH")) {
      status = "NO_MATCH";
    } else {
      status = "INDETERMINATE";
    }
  }

  if (configuration.negate === true) {
    if (status === "MATCH") status = "NO_MATCH";
    else if (status === "NO_MATCH") status = "MATCH";

    return { status, evidence: [] };
  }

  return {
    status,
    evidence:
      status === "MATCH"
        ? results
            .filter((result) => result.status === "MATCH")
            .flatMap((result) => result.evidence)
        : [],
  };
}

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
  `${ecosystem.toLowerCase().trim()}:${normalizedPackageName}`;

  const identity = CPE_IDENTITIES[identityKey];

  if (!identity) {
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
  url.searchParams.set(
    "keywordSearch",
    identity.searchKeyword
  );

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
)
  .map((item: any) => {
    const configurations = item.cve?.configurations || [];

    const evidence = configurations
      .map((configuration: any) =>
        hasMatchingCPE(
          configuration,
          version,
          normalizedPackageName,
          normalizedEcosystem
        )
      )
      .filter(
        (result: CPEEvaluationResult) => result.status === "MATCH"
      )
      .flatMap((result: CPEEvaluationResult) => result.evidence);

    return {
      item,
      evidence,
    };
  })
  .filter(
    (result: any) => result.evidence.length > 0
  );

  console.log(
    `NVD returned ${matchingVulnerabilities.length} version-matched finding(s) for ${packageName}@${version}.`
  );

  // Extract relevant vulnerability information.
  return matchingVulnerabilities.map((result: any) => {
  const cve = result.item.cve;
  const matchedEvidence = result.evidence[0];

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
      matchedCPE: matchedEvidence?.matchedCPE,
      matchedVersionRange: matchedEvidence?.matchedVersionRange,
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
): CPEEvaluationResult {
  const operator = String(node.operator || "OR").toUpperCase();

  const cpeMatches = node.cpeMatch || [];

  const childResults: CPEEvaluationResult[] = (
    node.children || []
  ).map((child: any) =>
    evaluateNode(child, installedVersion, packageName, ecosystem)
  );

  const matchResults: CPEEvaluationResult[] = cpeMatches.map(
    (match: any) => {
      const evidence = matchesAffectedVersion(
        match,
        installedVersion,
        packageName,
        ecosystem
      );

      return evidence
        ? { status: "MATCH", evidence: [evidence] }
        : { status: "INDETERMINATE", evidence: [] };
    }
  );

  const results = [...matchResults, ...childResults];

  if (results.length === 0) {
    return { status: "INDETERMINATE", evidence: [] };
  }

  let status: CPEMatchStatus;

  if (operator === "AND") {
    if (results.some((result) => result.status === "NO_MATCH")) {
      status = "NO_MATCH";
    } else if (results.every((result) => result.status === "MATCH")) {
      status = "MATCH";
    } else {
      status = "INDETERMINATE";
    }
  } else {
    if (results.some((result) => result.status === "MATCH")) {
      status = "MATCH";
    } else if (results.every((result) => result.status === "NO_MATCH")) {
      status = "NO_MATCH";
    } else {
      status = "INDETERMINATE";
    }
  }

  if (node.negate === true) {
    if (status === "MATCH") status = "NO_MATCH";
    else if (status === "NO_MATCH") status = "MATCH";

    return { status, evidence: [] };
  }

  return {
    status,
    evidence:
      status === "MATCH"
        ? results
            .filter((result) => result.status === "MATCH")
            .flatMap((result) => result.evidence)
        : [],
  };
}
