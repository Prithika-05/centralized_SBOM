import { SBOMFormat } from "./formatDetector.js";

export interface ParsedComponent {
  name: string;
  version: string;
  supplier?: string;
  packageId?: string;
  dependencies: string[];
  licenses: string[];
  hashes: string[];
}

export interface ParsedSBOM {
  format: SBOMFormat;
  components: ParsedComponent[];
}

export function parseCycloneDX(data: any): ParsedSBOM {
  const components: ParsedComponent[] = [];

  if (!Array.isArray(data.components)) {
    return {
      format: "CycloneDX",
      components,
    };
  }

  for (const component of data.components) {
    const licenses: string[] = [];

    if (Array.isArray(component.licenses)) {
      for (const license of component.licenses) {
        if (license.license?.id) {
          licenses.push(license.license.id);
        } else if (license.license?.name) {
          licenses.push(license.license.name);
        }
      }
    }

    const hashes: string[] = [];

    if (Array.isArray(component.hashes)) {
      for (const hash of component.hashes) {
        if (hash.value) {
          hashes.push(hash.value);
        }
      }
    }

    components.push({
      name: component.name || "Unknown",
      version: component.version || "Unknown",
      supplier: component.supplier?.name,
      packageId: component.purl,
      dependencies: [],
      licenses,
      hashes,
    });
  }

  return {
    format: "CycloneDX",
    components,
  };
}

export function parseSPDX(data: any): ParsedSBOM {
  const components: ParsedComponent[] = [];

  if (!Array.isArray(data.packages)) {
    return {
      format: "SPDX",
      components,
    };
  }

  for (const pkg of data.packages) {
    const licenses: string[] = [];

    if (pkg.licenseConcluded) {
      licenses.push(pkg.licenseConcluded);
    }

    if (
      pkg.licenseDeclared &&
      pkg.licenseDeclared !== pkg.licenseConcluded
    ) {
      licenses.push(pkg.licenseDeclared);
    }

    const hashes: string[] = [];

    if (Array.isArray(pkg.checksums)) {
      for (const checksum of pkg.checksums) {
        if (checksum.checksumValue) {
          hashes.push(checksum.checksumValue);
        }
      }
    }

    components.push({
      name: pkg.name || "Unknown",
      version: pkg.versionInfo || "Unknown",
      supplier: pkg.supplier,
      packageId: pkg.externalRefs?.[0]?.referenceLocator,
      dependencies: [],
      licenses,
      hashes,
    });
  }

  return {
    format: "SPDX",
    components,
  };
}

export function parseSBOM(
  data: any,
  format: SBOMFormat
): ParsedSBOM {
  switch (format) {
    case "CycloneDX":
      return parseCycloneDX(data);

    case "SPDX":
      return parseSPDX(data);

    default:
      return {
        format: "UNKNOWN",
        components: [],
      };
  }
}