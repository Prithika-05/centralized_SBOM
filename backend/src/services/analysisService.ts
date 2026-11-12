import {
  correlateComponent,
  buildUnifiedVulnerabilities,
} from "./vulnerabilityCorrelationService.js";
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
  const unifiedVulnerabilities = buildUnifiedVulnerabilities(
    vulnerabilityAnalysis.vulnerabilities
  );
  const impactedComponents = await findImpactedComponents(componentId);

  const hasDependencies =
  await hasDependencyRelationships(componentId);
  const hasImpactAnalysis =
    Array.isArray(impactedComponents) &&
    impactedComponents.length > 0;  
  const vulnerabilityAnalysisCompleted = !!vulnerabilityAnalysis;
  const hasSBOM = await hasValidatedSBOM(componentId);

  const vulnerabilityCount = unifiedVulnerabilities.length;

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
    vulnerabilityAnalysis: {
      ...vulnerabilityAnalysis,
      unifiedVulnerabilities,
    },
    impactAnalysis: {
      impactedComponents,
    },
    craValidation,
  };
}
