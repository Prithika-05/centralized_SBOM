export interface OSVVulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severity?: string;
  cvssScore?: number;
}

interface OSVSeverity {
  type?: string;
  score?: string | number;
}

interface OSVVulnerabilityResponse {
  id: string;
  aliases?: string[];
  summary?: string;
  database_specific?: {
    severity?: string;
    cvss_score?: number;
  };
  severity?: OSVSeverity[];
}

interface OSVQueryResponse {
  vulns?: OSVVulnerabilityResponse[];
}

export async function searchOSV(
  packageName: string,
  version: string,
  ecosystem: string
): Promise<OSVVulnerability[]> {
  const response = await fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      package: {
        name: packageName,
        ecosystem,
      },
      version,
    }),
  });

  if (!response.ok) {
    throw new Error(
      `OSV API request failed: ${response.status}`
    );
  }

  const data: OSVQueryResponse = await response.json();

  return (data.vulns || []).map((vulnerability) => {
    const databaseSeverity =
      vulnerability.database_specific?.severity;

    const databaseCvssScore =
      vulnerability.database_specific?.cvss_score;

    // Only accept a numeric score, not a CVSS vector string.
    const numericCvssScore =
      typeof databaseCvssScore === "number"
        ? databaseCvssScore
        : undefined;

    return {
      id: vulnerability.id,
      aliases: vulnerability.aliases || [],
      summary: vulnerability.summary || "",
      severity:
        typeof databaseSeverity === "string"
          ? databaseSeverity.toUpperCase()
          : undefined,
      cvssScore: numericCvssScore,
    };
  });
}


export async function testOSVConnection(): Promise<boolean> {
  const testPackages = [
    {
      name: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
      ecosystem: "Maven",
    },
    {
      name: "lodash",
      version: "4.17.20",
      ecosystem: "npm",
    },
    {
      name: "Django",
      version: "3.2.0",
      ecosystem: "PyPI",
    },
    {
      name: "Newtonsoft.Json",
      version: "12.0.1",
      ecosystem: "NuGet",
    },
  ];

  let successfulRequests = 0;

  for (const pkg of testPackages) {
    try {
      const results = await searchOSV(
        pkg.name,
        pkg.version,
        pkg.ecosystem
      );

      console.log("--------------------------------");
      console.log(`Ecosystem: ${pkg.ecosystem}`);
      console.log(`Package: ${pkg.name}`);
      console.log(`Version: ${pkg.version}`);
      console.log(`Vulnerabilities found: ${results.length}`);
      console.log("Sample results:", results.slice(0, 3));

      successfulRequests++;
    } catch (error) {
      console.error(
        `OSV test failed for ${pkg.ecosystem}:`,
        error
      );
    }
  }

  console.log(
    `OSV test completed: ${successfulRequests}/${testPackages.length} requests succeeded.`
  );

  return successfulRequests === testPackages.length;
}

