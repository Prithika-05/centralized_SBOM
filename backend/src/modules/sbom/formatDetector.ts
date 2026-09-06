export type SbomFormat = "SPDX" | "CycloneDX" | "Unknown";

export function detectSbomFormat(sbom: unknown): SbomFormat {
  if (!sbom || typeof sbom !== "object") {
    return "Unknown";
  }

  const data = sbom as Record<string, unknown>;

  // CycloneDX
  if ("bomFormat" in data && data.bomFormat === "CycloneDX") {
    return "CycloneDX";
  }

  // SPDX
  if ("spdxVersion" in data) {
    return "SPDX";
  }

  return "Unknown";
}