import { correlateComponent } from "./vulnerabilityCorrelationService.js";
import { findImpactedComponents } from "./impactAnalysisService.js";
import { validateCRA } from "./craValidationService.js";

export async function analyzeComponent(
  componentId: string,
  name: string,
  version: string
) {
  const vulnerabilityAnalysis = await correlateComponent(
    componentId,
    name,
    version
  );

  const impactedComponents = await findImpactedComponents(componentId);

  const vulnerabilityCount =
    vulnerabilityAnalysis.vulnerabilities.nvd.length +
    vulnerabilityAnalysis.vulnerabilities.osv.length;

  const craValidation = validateCRA(
    true,
    vulnerabilityCount,
    true,
    true
  );

  return {
    component: {
      id: componentId,
      name,
      version,
    },
    vulnerabilityAnalysis,
    impactAnalysis: {
      impactedComponents,
    },
    craValidation,
  };
}