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

  // First, parse all components.
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

  // Build a lookup from CycloneDX bom-ref values to components.
  const componentMap = new Map<string, ParsedComponent>();

  for (const component of data.components) {
    if (component["bom-ref"]) {
      const parsedComponent = components.find(
        (item) =>
          item.name === (component.name || "Unknown") &&
          item.version === (component.version || "Unknown") &&
          item.packageId === component.purl
      );

      if (parsedComponent) {
        componentMap.set(component["bom-ref"], parsedComponent);
      }
    }
  }

  // Process top-level CycloneDX dependency relationships.
  if (Array.isArray(data.dependencies)) {
    for (const dependency of data.dependencies) {
      const source = componentMap.get(dependency.ref);

      if (!source || !Array.isArray(dependency.dependsOn)) {
        continue;
      }

      source.dependencies.push(...dependency.dependsOn);
    }
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

  // Build a map of SPDX package IDs to component indexes
  const packageMap = new Map<string, number>();

  data.packages.forEach((pkg: any, index: number) => {
    if (pkg.SPDXID) {
      packageMap.set(pkg.SPDXID, index);
    }
  });

  // First parse the packages
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

  // Process SPDX document-level relationships
  if (Array.isArray(data.relationships)) {
    for (const relationship of data.relationships) {
      if (relationship.relationshipType !== "DEPENDS_ON") {
        continue;
      }

      const sourceIndex = packageMap.get(
        relationship.spdxElement
      );

      const targetIndex = packageMap.get(
        relationship.relatedSpdxElement
      );

      if (
        sourceIndex !== undefined &&
        targetIndex !== undefined
      ) {
        const targetPackage = data.packages[targetIndex];

        const dependencyId =
          targetPackage.externalRefs?.[0]?.referenceLocator ||
          targetPackage.SPDXID ||
          targetPackage.name;

        components[sourceIndex].dependencies.push(
          dependencyId
        );
      }
    }
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