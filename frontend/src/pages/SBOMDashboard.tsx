// src/pages/SBOMDashboard.tsx (or .jsx)
import { useState } from 'react';

export default function SBOMDashboard() {
  const [componentId, setComponentId] = useState('');
  const [packageName, setPackageName] = useState('');
  const [version, setVersion] = useState('');
  const [results, setResults] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Keep your existing backend logic exactly as-is
  const handleAnalyze = async () => {
    if (!componentId || !packageName || !version) return;
    setIsAnalyzing(true);
    try {
      // Your existing fetch call here...
      // const res = await fetch(`/api/components/${componentId}/analysis?name=${packageName}&version=${version}`);
      // const data = await res.json();
      // setResults(data);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground p-6 md:p-12">
      <div className="mx-auto max-w-3xl space-y-8">
        
        {/* Header */}
        <header className="space-y-2 text-center">
          <h1 className="text-3xl font-bold tracking-tight text-foreground">
            SBOM Security Management
          </h1>
          <p className="text-muted-foreground">
            Upload, validate, and analyze Software Bill of Materials for CRA compliance.
          </p>
        </header>

        {/* Upload Card */}
        <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <h2 className="mb-1 text-lg font-semibold">SBOM File Upload</h2>
          <p className="mb-4 text-sm text-muted-foreground">
            Supports SPDX and CycloneDX JSON formats.
          </p>
          
          <label className="group flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-border bg-muted/50 py-10 transition-all hover:border-primary/50 hover:bg-accent/50">
            <input 
              type="file" 
              accept=".json" 
              className="hidden" 
              onChange={(e) => console.log(e.target.files)} // Replace with your handler
            />
            <svg className="mb-3 h-8 w-8 text-muted-foreground transition-colors group-hover:text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <span className="text-sm font-medium text-foreground">Click to upload or drag & drop</span>
            <span className="mt-1 text-xs text-muted-foreground">JSON files up to 10MB</span>
          </label>
        </section>

        {/* Analysis Form Card */}
        <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
          <h2 className="mb-1 text-lg font-semibold">Component Security Analysis</h2>
          <p className="mb-6 text-sm text-muted-foreground">
            Evaluate vulnerabilities, dependency impact, and Cyber Resilience Act (CRA) readiness.
          </p>

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-2">
              <label className="text-sm font-medium leading-none">Component ID</label>
              <input 
                type="text" 
                value={componentId}
                onChange={(e) => setComponentId(e.target.value)}
                placeholder="pkg:npm/example-lib@"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium leading-none">Package Name</label>
              <input 
                type="text" 
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                placeholder="example-library"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium leading-none">Version</label>
              <input 
                type="text" 
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="1.0.0"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>
          </div>

          <button 
            onClick={handleAnalyze}
            disabled={!componentId || !packageName || !version || isAnalyzing}
            className="mt-6 inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
          >
            {isAnalyzing ? 'Analyzing...' : 'Analyze Component'}
          </button>
        </section>

        {/* Terminal Results Area */}
        {results && (
          <section className="overflow-hidden rounded-xl border border-border bg-black/95 shadow-sm">
            <div className="border-b border-white/10 bg-white/5 px-4 py-2 flex items-center gap-2">
              <div className="h-3 w-3 rounded-full bg-red-500/80" />
              <div className="h-3 w-3 rounded-full bg-yellow-500/80" />
              <div className="h-3 w-3 rounded-full bg-green-500/80" />
              <span className="ml-2 text-xs font-mono text-white/50">security-analysis-output.json</span>
            </div>
            <pre className="p-4 overflow-x-auto font-mono text-sm leading-relaxed text-green-400">
              {JSON.stringify(results, null, 2)}
            </pre>
          </section>
        )}
      </div>
    </div>
  );
}