
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
  version: string,
  sbomId: string
) {
  const vulnerabilityAnalysis = await correlateComponent(
    componentId,
    name,
    version
  );

  const unifiedVulnerabilities = buildUnifiedVulnerabilities(
    vulnerabilityAnalysis.vulnerabilities
  );

  const impactedComponents = await findImpactedComponents(
    componentId,
    sbomId
  );

  const hasDependencies = await hasDependencyRelationships(
    componentId,
    sbomId
  );

  const hasImpactAnalysis = Array.isArray(impactedComponents);
  const vulnerabilityAnalysisCompleted = !!vulnerabilityAnalysis;
  const hasSBOM = await hasValidatedSBOM(componentId, sbomId);

  const vulnerabilityCount = unifiedVulnerabilities.length;

  const craValidation = validateCRA(
    hasSBOM,
    vulnerabilityAnalysisCompleted,
    vulnerabilityCount,
    hasDependencies,
    hasImpactAnalysis,
    name,
    version
  );

  return {
    sbomId,
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
