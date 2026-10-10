import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Terminal, UploadCloud, FileJson, CheckCircle2, AlertCircle } from "lucide-react";

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [isSuccess, setIsSuccess] = useState(false);

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

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4 md:p-8">
      <Card className="w-full max-w-2xl shadow-lg border-border/50">
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
            <label htmlFor="sbom-file" className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
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
            {loading ? (
              <>Processing...</>
            ) : (
              <>
                <UploadCloud className="mr-2 h-4 w-4" /> Upload SBOM
              </>
            )}
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
    </div>
  );
}

export default App;