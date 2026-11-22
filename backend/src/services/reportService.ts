
import { analyzeComponent } from "./analysisService.js";

export interface SecurityReport {
  generatedAt: string;
  sbomId: string;
  component: {
    id: string;
    name: string;
    version: string;
  };
  vulnerabilityAnalysis: unknown;
  impactAnalysis: unknown;
  craValidation: unknown;
}

export async function generateSecurityReport(
  componentId: string,
  name: string,
  version: string,
  sbomId: string
): Promise<SecurityReport> {
  const analysis = await analyzeComponent(
    componentId,
    name,
    version,
    sbomId
  );

  return {
    generatedAt: new Date().toISOString(),
    sbomId,
    component: analysis.component,
    vulnerabilityAnalysis: analysis.vulnerabilityAnalysis,
    impactAnalysis: analysis.impactAnalysis,
    craValidation: analysis.craValidation,
  };
}
