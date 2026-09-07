export type SBOMFormat = "SPDX" | "CycloneDX" | "UNKNOWN";

export function detectSBOMFormat(data: any): SBOMFormat {
  // SPDX detection
  if (
    data.spdxVersion ||
    data.SPDXID ||
    data.creationInfo
  ) {
    return "SPDX";
  }

  // CycloneDX detection
  if (
    data.bomFormat === "CycloneDX" ||
    data.specVersion ||
    data.components
  ) {
    return "CycloneDX";
  }

  return "UNKNOWN";
}