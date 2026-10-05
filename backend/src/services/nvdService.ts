import dotenv from "dotenv";

dotenv.config();

export interface NVDVulnerability {
  id: string;
  description: string;
  severity?: string;
  cvssScore?: number;
}

export async function searchNVD(
  packageName: string,
  version: string
): Promise<NVDVulnerability[]> {
  const url = new URL(
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
  );

  const apiKey = process.env.NVD_API_KEY;

  url.searchParams.set(
    "keywordSearch",
    `${packageName} ${version}`
  );

  const response = await fetch(url, {
    headers: apiKey
        ? {
            apiKey,
        }
        : undefined,
    });

  if (!response.ok) {
    throw new Error(
      `NVD API request failed: ${response.status}`
    );
  }

  const data = await response.json();

  return data.vulnerabilities.map((item: any) => {
    const cve = item.cve;

    const description =
      cve.descriptions?.find(
        (description: any) =>
          description.lang === "en"
      )?.value || "";

    const cvss =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
      cve.metrics?.cvssMetricV30?.[0]?.cvssData;

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
      `NVD returned ${results.length} vulnerability result(s).`
    );

    return true;
  } catch (error) {
    console.error("NVD request failed:", error);
    return false;
  }
}