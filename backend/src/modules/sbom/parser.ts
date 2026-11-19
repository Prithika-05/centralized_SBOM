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
  const componentMap = new Map<string, ParsedComponent>();

  // Parse a CycloneDX component and register its bom-ref.
  const addComponent = (component: any): ParsedComponent => {
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

    const parsedComponent: ParsedComponent = {
      name: component.name || "Unknown",
      version: component.version || "Unknown",
      supplier: component.supplier?.name,
      packageId: component.purl,
      dependencies: [],
      licenses,
      hashes,
    };

    components.push(parsedComponent);

    // Register the original CycloneDX bom-ref.
    if (component["bom-ref"]) {
      componentMap.set(component["bom-ref"], parsedComponent);
    }

console.log(
  "REFERENCE REGISTERED:",
  component["bom-ref"],
  "->",
  componentMap.get(component["bom-ref"])?.name
);
    // Register the canonical name@version only if it is not already used.
    const canonicalRef = `${component.name}@${component.version}`;

    if (
      component.name &&
      component.version &&
      !componentMap.has(canonicalRef)
    ) {
      componentMap.set(canonicalRef, parsedComponent);
    }

    // Register the name alias only if it is not already used.
    if (component.name && !componentMap.has(component.name)) {
      componentMap.set(component.name, parsedComponent);
    }

    return parsedComponent;
  };

  // 1. Parse the root application from CycloneDX metadata.
  if (data.metadata?.component) {
    addComponent(data.metadata.component);
  }

  // 2. Parse all regular components.
  if (Array.isArray(data.components)) {
    for (const component of data.components) {
      addComponent(component);
    }
  }

  console.log(
  "REGISTERED COMPONENT REFERENCES:",
  Array.from(componentMap.keys())
);

  console.log(
  "ROOT COMPONENT:",
  components[0]?.name,
  components[0]?.version
);
  // 3. Process top-level dependency relationships.
  if (Array.isArray(data.dependencies)) {
    for (const dependency of data.dependencies) {
      const source = componentMap.get(dependency.ref);
      console.log("SOURCE LOOKUP DETAILS:", {
        requestedRef: dependency.ref,
        resolvedName: source?.name,
        resolvedVersion: source?.version,
        resolvedPackageId: source?.packageId,
        isRoot: source?.name === data.metadata?.component?.name,
      });

      if (!source || !Array.isArray(dependency.dependsOn)) {
        continue;
      }

      for (const targetRef of dependency.dependsOn) {
        const targetComponent = componentMap.get(targetRef);

        if (!targetComponent) {
          continue;
        }

        console.log("DEPENDENCY OBJECT CHECK:", {
  sourceName: source.name,
  sourceVersion: source.version,
  targetName: targetComponent.name,
  targetVersion: targetComponent.version,
  sameObject: source === targetComponent,
  sourcePackageId: source.packageId,
  targetPackageId: targetComponent.packageId,
});

        // Prevent a component from depending on itself.
        if (source === targetComponent) {
          console.warn(
            "Skipping self-dependency:",
            dependency.ref,
            "->",
            targetRef
          );
          continue;
        }

        const targetId =
          targetComponent.packageId ||
          `${targetComponent.name}@${targetComponent.version}`;

        if (!source.dependencies.includes(targetId)) {
          source.dependencies.push(targetId);
        }
      }
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

  // Map SPDX package identifiers to component indexes.
  const packageMap = new Map<string, number>();

  data.packages.forEach((pkg: any, index: number) => {
    if (pkg.SPDXID) {
      packageMap.set(pkg.SPDXID, index);
    }
  });

  // Parse all SPDX packages.
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
      packageId: pkg.externalRefs?.find(
        (ref: any) =>
          ref.referenceCategory === "PACKAGE-MANAGER" &&
          ref.referenceType === "purl"
      )?.referenceLocator,
      dependencies: [],
      licenses,
      hashes,
    });
  }

  // Process SPDX dependency relationships.
  if (Array.isArray(data.relationships)) {
    for (const relationship of data.relationships) {
      if (relationship.relationshipType !== "DEPENDS_ON") {
        continue;
      }

      // SPDX 2.3 uses spdxElementId.
      const sourceIndex = packageMap.get(
        relationship.spdxElementId
      );

      const targetIndex = packageMap.get(
        relationship.relatedSpdxElement
      );

      if (
        sourceIndex === undefined ||
        targetIndex === undefined
      ) {
        continue;
      }

      const targetPackage = data.packages[targetIndex];

      const dependencyId =
        targetPackage.externalRefs?.find(
          (ref: any) =>
            ref.referenceCategory === "PACKAGE-MANAGER" &&
            ref.referenceType === "purl"
        )?.referenceLocator ||
        `${targetPackage.name}@${targetPackage.versionInfo || "Unknown"}`;

      const sourceComponent = components[sourceIndex];

      if (!sourceComponent.dependencies.includes(dependencyId)) {
        sourceComponent.dependencies.push(dependencyId);
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