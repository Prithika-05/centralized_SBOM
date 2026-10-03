import { ParsedSBOM, ParsedComponent } from "./parser.js";

export interface NormalizedComponent {
  id: string;
  name: string;
  version: string;
  supplier?: string;
  packageId?: string;
  ecosystem?: string;
  dependencies: string[];
  licenses: string[];
  hashes: string[];
}

export interface NormalizedSBOM {
  format: string;
  components: NormalizedComponent[];
}

export function normalizeComponent(
  component: ParsedComponent
): NormalizedComponent {
  const id =
    component.packageId ||
    `${component.name}@${component.version}`;

  let ecosystem: string | undefined;

  if (component.packageId?.startsWith("pkg:npm/")) {
    ecosystem = "npm";
  } else if (component.packageId?.startsWith("pkg:pypi/")) {
    ecosystem = "PyPI";
  } else if (component.packageId?.startsWith("pkg:maven/")) {
    ecosystem = "Maven";
  } else if (component.packageId?.startsWith("pkg:nuget/")) {
    ecosystem = "NuGet";
  }

  return {
    id,
    name: component.name,
    version: component.version,
    supplier: component.supplier,
    packageId: component.packageId,
    ecosystem,
    dependencies: component.dependencies,
    licenses: component.licenses,
    hashes: component.hashes,
  };
}

export function normalizeSBOM(
  sbom: ParsedSBOM
): NormalizedSBOM {
  const components = sbom.components.map(
    (component) => normalizeComponent(component)
  );

  return {
    format: sbom.format,
    components,
  };
}