
import {
  correlateComponent,
  buildUnifiedVulnerabilities,
} from "./vulnerabilityCorrelationService.js";
import {
  findImpactedComponents,
  hasDependencyRelationships,
} from "./impactAnalysisService.js";
import { validateCRA } from "./craValidationService.js";
import {
  hasValidatedSBOM,
  getComponentMetadata,
} from "./sbomGraphService.js";

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
  const componentMetadata = await getComponentMetadata(
    componentId,
    sbomId
  );

  const vulnerabilityCount = unifiedVulnerabilities.length;

  const craValidation = validateCRA(
    hasSBOM,
    vulnerabilityAnalysisCompleted,
    vulnerabilityCount,
    hasDependencies,
    hasImpactAnalysis,
    componentMetadata?.name ?? "",
    componentMetadata?.version ?? "",
    componentMetadata?.supplier ?? ""
  );

  return {
    sbomId,
    component: {
      id: componentId,
      name: componentMetadata?.name ?? name,
      version: componentMetadata?.version ?? version,
      supplier: componentMetadata?.supplier ?? null,
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
