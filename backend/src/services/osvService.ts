export interface OSVVulnerability {
  id: string;
  summary: string;
  severity?: string;
  cvssScore?: number;
}


export async function searchOSV(
  packageName: string,
  version: string
): Promise<OSVVulnerability[]> {
  const response = await fetch(
    "https://api.osv.dev/v1/query",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        package: {
          name: packageName,
        },
        version,
      }),
    }
  );

  if (!response.ok) {
    throw new Error(
      `OSV API request failed: ${response.status}`
    );
  }

  const data = await response.json();

  return (data.vulns || []).map((vulnerability: any) => ({
    id: vulnerability.id,
    summary: vulnerability.summary || "",
    severity: vulnerability.severity?.[0]?.score
      ? vulnerability.severity[0].score
      : undefined,
  }));
}

export async function testOSVConnection(): Promise<boolean> {
  try {
    const results = await searchOSV(
      "log4j-core",
      "2.14.1"
    );

    console.log(
      `OSV returned ${results.length} vulnerability result(s).`
    );

    return true;
  } catch (error) {
    console.error("OSV request failed:", error);
    return false;
  }
}