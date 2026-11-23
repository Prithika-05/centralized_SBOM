
export interface CRARule {
  id: string;
  name: string;
  description: string;
}

export const craRules: CRARule[] = [
  {
    id: "CRA-001",
    name: "SBOM Available",
    description: "A valid SBOM must be available for the product.",
  },
  {
    id: "CRA-002",
    name: "Vulnerability Detection",
    description: "Known vulnerabilities affecting components should be identified.",
  },
  {
    id: "CRA-003",
    name: "Dependency Analysis",
    description: "Dependencies should be identifiable for security analysis.",
  },
  {
    id: "CRA-004",
    name: "Vulnerability Impact Analysis",
    description: "The impact of identified vulnerabilities should be assessable.",
  },
  {
    id: "CRA-005",
    name: "Component Metadata Validation",
    description: "Components should have valid names and version information.",
  },
  {
    id: "CRA-006",
    name: "Supplier Metadata Validation",
    description:
      "Supplier information should be available to support component identification and traceability.",
  },
];

export function getCRARules(): CRARule[] {
  return craRules;
}
