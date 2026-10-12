import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Terminal, UploadCloud, FileJson, CheckCircle2, AlertCircle, ShieldAlert} from "lucide-react";

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
  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 md:p-8 space-y-6">
      <main className="w-full max-w-2xl space-y-6">
        
        {/* Panel 1: SBOM Upload & Management */}
        <Card className="shadow-lg border-border/50">
          <CardHeader className="space-y-1 pb-6">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-2 bg-primary/10 rounded-lg">
                <FileJson className="h-6 w-6 text-primary" />
              </div>
              <CardTitle className="text-2xl font-bold tracking-tight">SBOM Management</CardTitle>
            </div>
            <CardDescription>
              Upload and validate Software Bill of Materials files (SPDX or CycloneDX).
            </CardDescription>
          </CardHeader>
          
          <CardContent className="space-y-6">
            <div className="grid w-full max-w-sm items-center gap-1.5">
              <label htmlFor="sbom-file" className="text-sm font-medium leading-none">
                SBOM File
              </label>
              <div className="relative">
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
                  className="cursor-pointer file:text-primary file:font-semibold"
                />
              </div>
              {file && (
                <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  Selected: {file.name}
                </p>
              )}
            </div>

            <Button 
              onClick={handleUpload} 
              disabled={loading || !file}
              className="w-full sm:w-auto"
            >
              {loading ? <>Processing...</> : <><UploadCloud className="mr-2 h-4 w-4" /> Upload SBOM</>}
            </Button>

            {message && (
              <Alert variant={isSuccess ? "default" : "destructive"} className={isSuccess ? "bg-green-50 text-green-900 border-green-200 dark:bg-green-950/30 dark:text-green-400 dark:border-green-900" : ""}>
                {isSuccess ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
                <AlertTitle>{isSuccess ? "Success" : "Error"}</AlertTitle>
                <AlertDescription>{message}</AlertDescription>
              </Alert>
            )}

            {result !== null && (
              <div className="rounded-md border bg-muted/50 p-4 overflow-x-auto">
                <div className="flex items-center gap-2 mb-2 text-sm font-medium text-muted-foreground">
                  <Terminal className="h-4 w-4" />
                  Response Data
                </div>
                <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Panel 2: Component Security Analysis (Converted to shadcn UI components) */}
        <Card className="shadow-lg border-border/50">
          <CardHeader className="space-y-1 pb-6">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-2 bg-destructive/10 rounded-lg">
                <ShieldAlert className="h-6 w-6 text-destructive" />
              </div>
              <CardTitle className="text-2xl font-bold tracking-tight">Component Security Analysis</CardTitle>
            </div>
            <CardDescription>
              Analyze vulnerabilities, dependency impact, and Cyber Resilience Act (CRA) check assessments for a specified component.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="componentId" className="text-sm font-medium leading-none">Component ID</label>
              <Input
                id="componentId"
                type="text"
                value={componentId}
                onChange={(event) => setComponentId(event.target.value)}
                placeholder="pkg:npm/example-library@1.0.0"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label htmlFor="packageName" className="text-sm font-medium leading-none">Package Name</label>
                <Input
                  id="packageName"
                  type="text"
                  value={packageName}
                  onChange={(event) => setPackageName(event.target.value)}
                  placeholder="example-library"
                />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="packageVersion" className="text-sm font-medium leading-none">Package Version</label>
                <Input
                  id="packageVersion"
                  type="text"
                  value={packageVersion}
                  onChange={(event) => setPackageVersion(event.target.value)}
                  placeholder="1.0.0"
                />
              </div>
            </div>

            <Button
              onClick={handleAnalyze}
              disabled={analysisLoading}
              variant="secondary"
              className="w-full sm:w-auto mt-2"
            >
              {analysisLoading ? "Analyzing..." : "Analyze Component"}
            </Button>

            {analysisMessage && (
              <Alert className="mt-4">
                <Terminal className="h-4 w-4" />
                <AlertDescription>{analysisMessage}</AlertDescription>
              </Alert>
            )}

            {analysisResult !== null && (
              <div className="rounded-md border bg-muted/50 p-4 overflow-x-auto mt-4">
                <div className="flex items-center gap-2 mb-2 text-sm font-medium text-muted-foreground">
                  <Terminal className="h-4 w-4" />
                  Analysis Output Data
                </div>
                <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                  {JSON.stringify(analysisResult, null, 2)}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>

      </main>
    </div>
  );
}

export default App;