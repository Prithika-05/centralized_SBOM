import { correlateComponent } from "./vulnerabilityCorrelationService.js";
import {
  findImpactedComponents,
  hasDependencyRelationships,
} from "./impactAnalysisService.js";
import { validateCRA } from "./craValidationService.js";
import { hasValidatedSBOM } from "./sbomGraphService.js";

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

  const hasDependencies =
  await hasDependencyRelationships(componentId);
  const hasImpactAnalysis =
    Array.isArray(impactedComponents) &&
    impactedComponents.length > 0;  
  const vulnerabilityAnalysisCompleted = !!vulnerabilityAnalysis;
  const hasSBOM = await hasValidatedSBOM(componentId);

  const vulnerabilityCount =
    ((vulnerabilityAnalysis as any)?.vulnerabilities?.nvd?.length ?? 0) +
    ((vulnerabilityAnalysis as any)?.vulnerabilities?.osv?.length ?? 0);

  const craValidation = validateCRA(
    hasSBOM,                           // hasSBOM
    vulnerabilityAnalysisCompleted,  // vulnerabilityAnalysisCompleted
    vulnerabilityCount,               // vulnerabilityCount
    hasDependencies,                  // hasDependencies
    hasImpactAnalysis                 // hasImpactAnalysis
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
