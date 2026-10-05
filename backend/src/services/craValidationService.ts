import { getCRARules, CRARule } from "./craRulesService.js";

export interface CRAValidationResult {
  ruleId: string;
  ruleName: string;
  passed: boolean;
  message: string;
}

export interface CRAValidationSummary {
  compliant: boolean;
  results: CRAValidationResult[];
}

export function validateCRA(
  hasSBOM: boolean,
  vulnerabilityCount: number,
  hasDependencies: boolean,
  hasImpactAnalysis: boolean
): CRAValidationSummary {
  const rules: CRARule[] = getCRARules();

  const results: CRAValidationResult[] = rules.map((rule) => {
    let passed = false;
    let message = "";

    switch (rule.id) {
      case "CRA-001":
        passed = hasSBOM;
        message = passed
          ? "SBOM is available."
          : "No valid SBOM is available.";

        break;

      case "CRA-002":
        passed = vulnerabilityCount >= 0;
        message = passed
          ? "Vulnerability analysis has been performed."
          : "Vulnerability analysis has not been performed.";

        break;

      case "CRA-003":
        passed = hasDependencies;
        message = passed
          ? "Dependency information is available."
          : "Dependency information is missing.";

        break;

      case "CRA-004":
        passed = hasImpactAnalysis;
        message = passed
          ? "Vulnerability impact analysis is available."
          : "Vulnerability impact analysis is missing.";

        break;
    }

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      passed,
      message,
    };
  });

  return {
    compliant: results.every((result) => result.passed),
    results,
  };
}