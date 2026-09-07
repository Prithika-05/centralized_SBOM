import { SBOMFormat } from "./formatDetector.js";

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateSBOM(
  data: any,
  format: SBOMFormat
): ValidationResult {
  const errors: string[] = [];

  if (format === "UNKNOWN") {
    errors.push("SBOM format could not be detected.");
    return {
      valid: false,
      errors,
    };
  }

  if (format === "SPDX") {
    if (!data.spdxVersion) {
      errors.push("Missing SPDX version.");
    }

    if (!data.SPDXID) {
      errors.push("Missing SPDX document ID.");
    }

    if (!data.creationInfo) {
      errors.push("Missing SPDX creation information.");
    }
  }

  if (format === "CycloneDX") {
    if (!data.bomFormat) {
      errors.push("Missing CycloneDX bomFormat.");
    }

    if (!data.specVersion) {
      errors.push("Missing CycloneDX specification version.");
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}