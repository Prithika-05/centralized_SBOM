import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Terminal, UploadCloud, FileJson, CheckCircle2, AlertCircle, ShieldAlert} from "lucide-react";
import { normalizeSeverity } from "./utils/severity";
import "./App.css"; 

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const [componentId, setComponentId] = useState("");
  const [packageName, setPackageName] = useState("");
  const [packageVersion, setPackageVersion] = useState("");
  const [analysisResult, setAnalysisResult] = useState<unknown>(null);
  const [analysisMessage, setAnalysisMessage] = useState("");
  const [analysisLoading, setAnalysisLoading] = useState(false);

  async function handleUpload() {
    if (!file) {
      setMessage("Please select an SBOM file first.");
      setIsSuccess(false);
      return;
    }

    const formData = new FormData();
    formData.append("sbom", file);

    setLoading(true);
    setMessage("");
    setResult(null);
    setIsSuccess(false);

    try {
      const response = await fetch(
        "http://localhost:5000/api/sboms/upload",
        { method: "POST", body: formData }
      );

      const data: unknown = await response.json();

      if (!response.ok) {
        setMessage("Upload failed. Check the response below.");
        setIsSuccess(false);
        setResult(data);
        return;
      }

      setMessage("SBOM uploaded successfully.");
      setIsSuccess(true);
      setResult(data);
    } catch {
      setMessage("Could not connect to the backend. Check that it is running.");
      setIsSuccess(false);
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalyze() {
    if (!componentId.trim() || !packageName.trim() || !packageVersion.trim()) {
      setAnalysisMessage("Please enter all component details.");
      return;
    }

    setAnalysisLoading(true);
    setAnalysisMessage("");
    setAnalysisResult(null);

    try {
      const params = new URLSearchParams({
        name: packageName.trim(),
        version: packageVersion.trim(),
      });

      const response = await fetch(
        `http://localhost:5000/api/components/${encodeURIComponent(
          componentId.trim()
        )}/analysis?${params.toString()}`
      );

      const data: unknown = await response.json();

      if (!response.ok) {
        setAnalysisMessage("Analysis failed. Check the response.");
        setAnalysisResult(data);
        return;
      }

      setAnalysisResult(data);
      setAnalysisMessage("Security analysis completed.");
    } catch {
      setAnalysisMessage(
        "Could not connect to the backend. Check that it is running."
      );
    } finally {
      setAnalysisLoading(false);
    }
  }

  
  function getAnalysisSection(key: string): Record<string, any> | null {
    if (
      typeof analysisResult !== "object" ||
      analysisResult === null ||
      !(key in analysisResult)
    ) {
      return null;
    }

    const value = (analysisResult as Record<string, unknown>)[key];

    if (typeof value !== "object" || value === null) {
      return null;
    }

    return value as Record<string, any>;
  }

  function renderVulnerabilityList(
    source: "nvd" | "osv"
  ) {
    const vulnerabilityAnalysis = getAnalysisSection(
      "vulnerabilityAnalysis"
    );

    const vulnerabilities =
      vulnerabilityAnalysis?.vulnerabilities?.[source];

    if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
      return <p>No findings returned by {source.toUpperCase()}.</p>;
    }

    return (
      <div className="vulnerability-list">
        {vulnerabilities.map((vulnerability: any, index: number) => (
          <article
            className="vulnerability-item"
            key={`${vulnerability.id ?? source}-${index}`}
          >
            <div className="vulnerability-heading">
              <strong>{vulnerability.id ?? "Unknown ID"}</strong>
              <span className="severity-label">
                {normalizeSeverity(vulnerability.severity)}
              </span>
            </div>

            <p>
              {vulnerability.description ??
                vulnerability.summary ??
                "No description provided."}
            </p>

            {vulnerability.cvssScore !== undefined && (
              <p>CVSS score: {vulnerability.cvssScore}</p>
            )}
          </article>
        ))}
      </div>
    );
  }

  function renderImpactedComponents() {
    const impactAnalysis = getAnalysisSection("impactAnalysis");
    const components = impactAnalysis?.impactedComponents;

    if (!Array.isArray(components) || components.length === 0) {
      return <p>No impacted components were returned.</p>;
    }

    return (
      <div className="vulnerability-list">
        {components.map((component: any, index: number) => (
          <article
            className="vulnerability-item"
            key={`${component.id ?? component.name}-${index}`}
          >
            <strong>{component.name ?? "Unknown component"}</strong>
            <p>Version: {component.version ?? "Unknown"}</p>
            <p>Component ID: {component.id ?? "Unavailable"}</p>
          </article>
        ))}
      </div>
    );
  }

  return (
    // CENTERED LAYOUT CONTAINER
    <div className="min-h-screen w-full flex items-center justify-center p-4 relative overflow-hidden">
      
      {/* Ambient Glow Effects */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-green-500/5 rounded-full blur-[100px] pointer-events-none" />
      
      {/* MAIN FORM CARD */}
      <main className="w-full max-w-md relative z-10 space-y-6">
        
        {/* Header / Title Block */}
        <div className="text-center space-y-2 mb-6">
          <div className="inline-flex items-center justify-center gap-2 mb-2">
            <Terminal className="h-6 w-6 text-green-400 animate-pulse" />
            <h1 className="text-2xl font-bold tracking-tighter text-green-400 uppercase">
              CreatorHub Security
            </h1>
          </div>
          <p className="text-xs text-green-600/70 font-mono uppercase tracking-widest">
            System Status: ONLINE // Backend: ACTIVE
          </p>
        </div>

        {/* Panel 1: SBOM Upload */}
        <Card className="shadow-[0_0_40px_-10px_rgba(34,197,94,0.15)] border-green-500/20 bg-black/80 backdrop-blur-xl">
          <CardHeader className="pb-4 border-b border-green-500/10">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-950/30 rounded border border-green-500/20">
                <FileJson className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <CardTitle className="text-base font-bold text-green-400 uppercase tracking-wide">
                  SBOM Management
                </CardTitle>
                <CardDescription className="text-green-600/60 text-xs mt-0.5">
                  Upload SPDX or CycloneDX files
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          
          <CardContent className="pt-6 space-y-5">
            <div className="space-y-2">
              <label htmlFor="sbom-file" className="text-xs font-bold text-green-500 uppercase tracking-wider flex items-center gap-2">
                <span className="w-1 h-1 bg-green-500 rounded-full"></span>
                Target File
              </label>
              <Input
                id="sbom-file"
                type="file"
                accept=".json,application/json"
                onChange={(event) => {
                  setFile(event.target.files?.[0] ?? null);
                  setMessage("");
                  setResult(null);
                  setIsSuccess(false);
                }}
                className="cursor-pointer file:text-green-400 file:font-bold file:bg-green-950/20 file:border file:border-green-500/20 file:rounded file:px-3 file:py-1 hover:file:bg-green-900/30 transition-all bg-black/50 border-green-500/20 focus:border-green-400 focus:ring-green-500/20 text-green-300 placeholder:text-green-800 text-sm"
              />
              {file && (
                <p className="text-[10px] text-green-500/70 flex items-center gap-1.5 bg-green-950/10 p-1.5 rounded border border-green-500/10 font-mono truncate">
                  <CheckCircle2 className="h-3 w-3 shrink-0" />
                  {file.name}
                </p>
              )}
            </div>

            <Button 
              onClick={handleUpload} 
              disabled={loading || !file}
              className="w-full bg-green-600 hover:bg-green-500 text-black font-bold shadow-[0_0_15px_-3px_rgba(34,197,94,0.4)] hover:shadow-[0_0_20px_-3px_rgba(34,197,94,0.6)] transition-all duration-300 border-0 h-9 text-sm uppercase tracking-wider"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 animate-spin" />
                  Processing...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <UploadCloud className="h-3.5 w-3.5" />
                  Upload SBOM
                </span>
              )}
            </Button>

            {message && (
              <Alert 
                variant={isSuccess ? "default" : "destructive"} 
                className={`${
                  isSuccess ? "bg-green-950/20 text-green-400 border-green-500/30" : "bg-red-950/20 text-red-400 border-red-500/30"
                } backdrop-blur-sm py-3`}
              >
                {isSuccess ? <CheckCircle2 className="h-3.5 w-3.5" /> : <AlertCircle className="h-3.5 w-3.5" />}
                <AlertTitle className="text-xs font-bold uppercase">{isSuccess ? "Success" : "Error"}</AlertTitle>
                <AlertDescription className="text-xs mt-0.5 font-mono opacity-90">{message}</AlertDescription>
              </Alert>
            )}

            {result !== null && (
              <div className="rounded border border-green-500/20 bg-black/80 p-3 overflow-x-auto">
                <div className="flex items-center gap-2 mb-2 text-[10px] font-bold text-green-500 uppercase tracking-wider">
                  <Terminal className="h-3 w-3" /> Response Data
                </div>
                <pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-green-300/70 bg-black/50 p-2 rounded border border-green-500/10">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Panel 2: Component Analysis */}
        <Card className="shadow-[0_0_40px_-10px_rgba(6,182,212,0.15)] border-cyan-500/20 bg-black/80 backdrop-blur-xl">
          <CardHeader className="pb-4 border-b border-cyan-500/10">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-950/30 rounded border border-cyan-500/20">
                <ShieldAlert className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <CardTitle className="text-base font-bold text-cyan-400 uppercase tracking-wide">
                  Security Analysis
                </CardTitle>
                <CardDescription className="text-cyan-600/60 text-xs mt-0.5">
                  Vulnerability & CRA compliance check
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent className="pt-6 space-y-4">
            <div className="space-y-2">
              <label htmlFor="componentId" className="text-xs font-bold text-cyan-500 uppercase tracking-wider">
                Component ID
              </label>
              <Input
                id="componentId"
                type="text"
                value={componentId}
                onChange={(event) => setComponentId(event.target.value)}
                placeholder="pkg:npm/example-library@1.0.0"
                className="bg-black/50 border-cyan-500/20 focus:border-cyan-400 focus:ring-cyan-500/20 text-cyan-300 placeholder:text-cyan-800 font-mono text-sm h-9"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <label htmlFor="packageName" className="text-xs font-bold text-cyan-500 uppercase tracking-wider">Package</label>
                <Input
                  id="packageName"
                  type="text"
                  value={packageName}
                  onChange={(event) => setPackageName(event.target.value)}
                  placeholder="example-lib"
                  className="bg-black/50 border-cyan-500/20 focus:border-cyan-400 focus:ring-cyan-500/20 text-cyan-300 placeholder:text-cyan-800 font-mono text-sm h-9"
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="packageVersion" className="text-xs font-bold text-cyan-500 uppercase tracking-wider">Version</label>
                <Input
                  id="packageVersion"
                  type="text"
                  value={packageVersion}
                  onChange={(event) => setPackageVersion(event.target.value)}
                  placeholder="1.0.0"
                  className="bg-black/50 border-cyan-500/20 focus:border-cyan-400 focus:ring-cyan-500/20 text-cyan-300 placeholder:text-cyan-800 font-mono text-sm h-9"
                />
              </div>
            </div>

            <Button
              onClick={handleAnalyze}
              disabled={analysisLoading}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-black font-bold shadow-[0_0_15px_-3px_rgba(6,182,212,0.4)] hover:shadow-[0_0_20px_-3px_rgba(6,182,212,0.6)] transition-all duration-300 border-0 h-9 text-sm uppercase tracking-wider mt-2"
            >
              {analysisLoading ? (
                <span className="flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 animate-spin" />
                  Scanning...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Analyze Component
                </span>
              )}
            </Button>

            {analysisMessage && (
              <Alert className="mt-2 bg-cyan-950/20 border-cyan-500/30 text-cyan-400 backdrop-blur-sm py-3">
                <Terminal className="h-3.5 w-3.5" />
                <AlertDescription className="text-xs font-mono">{analysisMessage}</AlertDescription>
              </Alert>
            )}

            {/* Updated Dashboard View */}
            {analysisResult !== null && (
              <div className="dashboard-grid">
                <article className="dashboard-card col-span-full">
                  <h3>Vulnerability Analysis</h3>
                  {getAnalysisSection("vulnerabilityAnalysis") ? (
                    <>
                      <p>
                        Severity:{" "}
                        {getAnalysisSection("vulnerabilityAnalysis")?.severity ?? "Unknown"}
                      </p>
                      <p>
                        NVD findings:{" "}
                        {getAnalysisSection("vulnerabilityAnalysis")
                          ?.vulnerabilities?.nvd?.length ?? 0}
                      </p>
                      <p>
                        OSV findings:{" "}
                        {getAnalysisSection("vulnerabilityAnalysis")
                          ?.vulnerabilities?.osv?.length ?? 0}
                      </p>
                      
                      <h4>NVD Findings</h4>
                      {renderVulnerabilityList("nvd")}

                      <h4>OSV Findings</h4>
                      {renderVulnerabilityList("osv")}
                    </>
                  ) : (
                    <p>Vulnerability results are unavailable.</p>
                  )}
                </article>

                <article className="dashboard-card">
                  <h3>Impact Analysis</h3>

                  <p>
                    Potentially impacted components:{" "}
                    {getAnalysisSection("impactAnalysis")
                      ?.impactedComponents?.length ?? 0}
                  </p>

                  {renderImpactedComponents()}
                </article>

                <article className="dashboard-card">
                  <h3>CRA Validation</h3>
                  {getAnalysisSection("craValidation") ? (
                    <>
                      <p>
                        Result:{" "}
                        {getAnalysisSection("craValidation")?.compliant
                          ? "All prototype checks passed"
                          : "Some prototype checks failed"}
                      </p>
                      <p>
                        Checks passed:{" "}
                        {getAnalysisSection("craValidation")?.results?.filter(
                          (item: any) => item.passed
                        ).length ?? 0}
                        {" / "}
                        {getAnalysisSection("craValidation")?.results?.length ?? 0}
                      </p>
                    </>
                  ) : (
                    <p>CRA results are unavailable.</p>
                  )}
                </article>

                <details className="dashboard-card raw-details col-span-full">
                  <summary>View complete analysis response</summary>
                  <pre className="result">
                    {JSON.stringify(analysisResult, null, 2)}
                  </pre>
                </details>
              </div>
            )}
          </CardContent>
        </Card>

      </main>
    </div>
  );
}

export default App;