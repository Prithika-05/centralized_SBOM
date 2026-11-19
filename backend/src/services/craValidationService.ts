
import { getCRARules, CRARule } from "./craRulesService.js";

export interface CRAValidationResult {
  ruleId: string;
  ruleName: string;
  passed: boolean;
  message: string;
  expected: string;
  actual: string;
  failureReason: string | null;
  suggestedAction: string | null;
}

export interface CRAValidationSummary {
  compliant: boolean;
  results: CRAValidationResult[];
}

export function validateCRA(
  hasSBOM: boolean,
  vulnerabilityAnalysisCompleted: boolean,
  vulnerabilityCount: number,
  hasDependencies: boolean,
  hasImpactAnalysis: boolean
): CRAValidationSummary {
  const rules: CRARule[] = getCRARules();

  const results: CRAValidationResult[] = rules.map((rule) => {
    let passed = false;
    let message = "";
    let expected = "";
    let actual = "";
    let failureReason: string | null = null;
    let suggestedAction: string | null = null;

    switch (rule.id) {
      case "CRA-001":
        passed = hasSBOM;
        expected = "A valid SBOM should be available.";
        actual = hasSBOM
          ? "A valid SBOM is available."
          : "No valid SBOM was found.";

        message = passed
          ? "SBOM is available."
          : "SBOM validation failed.";

        if (!passed) {
          failureReason =
            "The system could not confirm the availability of a valid SBOM.";

          suggestedAction =
            "Upload an SPDX or CycloneDX SBOM and ensure that validation succeeds.";
        }
        break;

      case "CRA-002": {
        const validCount =
          Number.isInteger(vulnerabilityCount) && vulnerabilityCount >= 0;

        passed = vulnerabilityAnalysisCompleted && validCount;

        expected =
          "Vulnerability analysis should complete successfully and return a valid non-negative finding count.";

        actual = `Analysis completed: ${vulnerabilityAnalysisCompleted}. Finding count: ${vulnerabilityCount}.`;

        message = passed
          ? `Vulnerability analysis completed; ${vulnerabilityCount} findings recorded.`
          : "Vulnerability analysis did not complete successfully.";

        if (!vulnerabilityAnalysisCompleted) {
          failureReason =
            "The vulnerability analysis was not completed successfully.";
          suggestedAction =
            "Check the analysis service, vulnerability data sources, and backend logs, then run the analysis again.";
        } else if (!Number.isInteger(vulnerabilityCount)) {
          failureReason =
            "The vulnerability finding count is not a valid integer.";
          suggestedAction =
            "Check the vulnerability analysis response and ensure the finding count is a valid integer.";
        } else if (vulnerabilityCount < 0) {
          failureReason =
            "The vulnerability finding count cannot be negative.";
          suggestedAction =
            "Check the vulnerability counting logic and correct the returned count.";
        }
        break;
      }

      case "CRA-003":
        passed = hasDependencies;
        expected =
          "Dependency relationships should be available for the SBOM components.";
        actual = hasDependencies
          ? "Dependency information is available."
          : "No dependency relationships were detected.";

        message = passed
          ? "Dependency information is available."
          : "Dependency information is missing.";

        if (!passed) {
          failureReason =
            "The system could not find dependency relationships in the SBOM graph.";

          suggestedAction =
            "Check the SBOM dependencies section, verify that dependency references match component identifiers, and confirm that relationships were stored in Neo4j.";
        }
        break;

      case "CRA-004":
        passed = hasImpactAnalysis;
        expected =
          "Vulnerability impact analysis should complete and return a valid result.";
        actual = hasImpactAnalysis
          ? "Impact analysis is available."
          : "Impact analysis is unavailable.";

        message = passed
          ? "Vulnerability impact analysis is available."
          : "Vulnerability impact analysis is missing.";

        if (!passed) {
          failureReason =
            "The system could not confirm that vulnerability impact analysis completed successfully.";

          suggestedAction =
            "Check the impact analysis service, component identifiers, dependency relationships, and backend logs.";
        }
        break;

      default:
        expected = "A recognized CRA validation rule should be available.";
        actual = `Unknown rule ID: ${rule.id}`;
        message = "CRA validation rule is not recognized.";
        failureReason = "No validation logic is defined for this rule.";
        suggestedAction =
          "Add the corresponding validation logic to craValidationService.ts.";
        break;
    }

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      passed,
      message,
      expected,
      actual,
      failureReason,
      suggestedAction,
    };
  });

  return {
    compliant: results.every((result) => result.passed),
    results,
  };
}
