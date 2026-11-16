import { jsxs as _jsxs, jsx as _jsx, Fragment as _Fragment } from "react/jsx-runtime";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Terminal, UploadCloud, FileJson, CheckCircle2, AlertCircle, ShieldAlert } from "lucide-react";
import { normalizeSeverity } from "./utils/severity";
import "./App.css";
function App() {
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [isSuccess, setIsSuccess] = useState(false);
    const [componentId, setComponentId] = useState("");
    const [packageName, setPackageName] = useState("");
    const [packageVersion, setPackageVersion] = useState("");
    const [analysisResult, setAnalysisResult] = useState(null);
    const [analysisMessage, setAnalysisMessage] = useState("");
    const [analysisLoading, setAnalysisLoading] = useState(false);
    const [reportLoading, setReportLoading] = useState(false);
    const [reportMessage, setReportMessage] = useState("");
    const [reportResult, setReportResult] = useState(null);
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
            const response = await fetch("http://localhost:5000/api/sboms/upload", { method: "POST", body: formData });
            const data = await response.json();
            if (!response.ok) {
                setMessage("Upload failed. Check the response below.");
                setIsSuccess(false);
                setResult(data);
                return;
            }
            setMessage("SBOM uploaded successfully.");
            setIsSuccess(true);
            setResult(data);
        }
        catch {
            setMessage("Could not connect to the backend. Check that it is running.");
            setIsSuccess(false);
        }
        finally {
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
            const response = await fetch(`http://localhost:5000/api/components/${encodeURIComponent(componentId.trim())}/analysis?${params.toString()}`);
            const data = await response.json();
            if (!response.ok) {
                setAnalysisMessage("Analysis failed. Check the response.");
                setAnalysisResult(data);
                return;
            }
            setAnalysisResult(data);
            setAnalysisMessage("Security analysis completed.");
        }
        catch {
            setAnalysisMessage("Could not connect to the backend. Check that it is running.");
        }
        finally {
            setAnalysisLoading(false);
        }
    }
    async function handleGenerateReport() {
        if (!componentId.trim() || !packageName.trim() || !packageVersion.trim()) {
            setReportMessage("Please enter all component details.");
            return;
        }
        setReportLoading(true);
        setReportMessage("");
        try {
            const params = new URLSearchParams({
                name: packageName.trim(),
                version: packageVersion.trim(),
            });
            const response = await fetch(`http://localhost:5000/api/components/${encodeURIComponent(componentId.trim())}/report?${params.toString()}`);
            const data = await response.json();
            if (!response.ok) {
                setReportMessage("Report generation failed.");
                setReportResult(data);
                return;
            }
            setReportResult(data);
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const downloadUrl = window.URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = downloadUrl;
            link.download = `${packageName.trim()}-${packageVersion.trim()}-security-report.json`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(downloadUrl);
            setReportMessage("Security report generated and downloaded successfully.");
        }
        catch {
            setReportMessage("Could not connect to the backend.");
        }
        finally {
            setReportLoading(false);
        }
    }
    function getAnalysisSection(key) {
        if (typeof analysisResult !== "object" ||
            analysisResult === null ||
            !(key in analysisResult)) {
            return null;
        }
        const value = analysisResult[key];
        if (typeof value !== "object" || value === null) {
            return null;
        }
        return value;
    }
    function renderVulnerabilityList(source) {
        const vulnerabilityAnalysis = getAnalysisSection("vulnerabilityAnalysis");
        const vulnerabilities = vulnerabilityAnalysis?.vulnerabilities?.[source];
        if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
            return _jsxs("p", { children: ["No findings returned by ", source.toUpperCase(), "."] });
        }
        return (_jsx("div", { className: "vulnerability-list", children: vulnerabilities.map((vulnerability, index) => (_jsxs("article", { className: "vulnerability-item", children: [_jsxs("div", { className: "vulnerability-heading", children: [_jsx("strong", { children: vulnerability.id ?? "Unknown ID" }), _jsx("span", { className: "severity-label", children: normalizeSeverity(vulnerability.severity) })] }), _jsx("p", { children: vulnerability.description ??
                            vulnerability.summary ??
                            "No description provided." }), vulnerability.cvssScore !== undefined && (_jsxs("p", { children: ["CVSS score: ", vulnerability.cvssScore] })), source === "nvd" && vulnerability.matchedCPE && (_jsxs("div", { className: "cpe-evidence", children: [_jsx("strong", { children: "CPE Matching Evidence" }), _jsxs("p", { children: ["Matched CPE: ", vulnerability.matchedCPE] }), vulnerability.matchedVersionRange && (_jsxs("div", { children: [_jsxs("p", { children: ["Start including:", " ", vulnerability.matchedVersionRange.startIncluding ?? "Not specified"] }), _jsxs("p", { children: ["Start excluding:", " ", vulnerability.matchedVersionRange.startExcluding ?? "Not specified"] }), _jsxs("p", { children: ["End including:", " ", vulnerability.matchedVersionRange.endIncluding ?? "Not specified"] }), _jsxs("p", { children: ["End excluding:", " ", vulnerability.matchedVersionRange.endExcluding ?? "Not specified"] })] }))] }))] }, `${vulnerability.id ?? source}-${index}`))) }));
    }
    function renderImpactedComponents() {
        const impactAnalysis = getAnalysisSection("impactAnalysis");
        const components = impactAnalysis?.impactedComponents;
        if (!Array.isArray(components) || components.length === 0) {
            return _jsx("p", { children: "No impacted components were returned." });
        }
        return (_jsx("div", { className: "vulnerability-list", children: components.map((component, index) => (_jsxs("article", { className: "vulnerability-item", children: [_jsx("strong", { children: component.name ?? "Unknown component" }), _jsxs("p", { children: ["Version: ", component.version ?? "Unknown"] }), _jsxs("p", { children: ["Component ID: ", component.id ?? "Unavailable"] })] }, `${component.id ?? component.name}-${index}`))) }));
    }
    return (_jsxs("div", { className: "min-h-screen w-full flex items-center justify-center p-4 relative overflow-hidden", children: [_jsx("div", { className: "absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-green-500/5 rounded-full blur-[100px] pointer-events-none" }), _jsxs("main", { className: "w-full max-w-md relative z-10 space-y-6", children: [_jsxs("div", { className: "text-center space-y-2 mb-6", children: [_jsxs("div", { className: "inline-flex items-center justify-center gap-2 mb-2", children: [_jsx(Terminal, { className: "h-6 w-6 text-green-400 animate-pulse" }), _jsx("h1", { className: "text-2xl font-bold tracking-tighter text-green-400 uppercase", children: "CreatorHub Security" })] }), _jsx("p", { className: "text-xs text-green-600/70 font-mono uppercase tracking-widest", children: "System Status: ONLINE // Backend: ACTIVE" })] }), _jsxs(Card, { className: "shadow-[0_0_40px_-10px_rgba(34,197,94,0.15)] border-green-500/20 bg-black/80 backdrop-blur-xl", children: [_jsx(CardHeader, { className: "pb-4 border-b border-green-500/10", children: _jsxs("div", { className: "flex items-center gap-3", children: [_jsx("div", { className: "p-2 bg-green-950/30 rounded border border-green-500/20", children: _jsx(FileJson, { className: "h-5 w-5 text-green-400" }) }), _jsxs("div", { children: [_jsx(CardTitle, { className: "text-base font-bold text-green-400 uppercase tracking-wide", children: "SBOM Management" }), _jsx(CardDescription, { className: "text-green-600/60 text-xs mt-0.5", children: "Upload SPDX or CycloneDX files" })] })] }) }), _jsxs(CardContent, { className: "pt-6 space-y-5", children: [_jsxs("div", { className: "space-y-2", children: [_jsxs("label", { htmlFor: "sbom-file", className: "text-xs font-bold text-green-500 uppercase tracking-wider flex items-center gap-2", children: [_jsx("span", { className: "w-1 h-1 bg-green-500 rounded-full" }), "Target File"] }), _jsx(Input, { id: "sbom-file", type: "file", accept: ".json,application/json", onChange: (event) => {
                                                    setFile(event.target.files?.[0] ?? null);
                                                    setMessage("");
                                                    setResult(null);
                                                    setIsSuccess(false);
                                                }, className: "cursor-pointer file:text-green-400 file:font-bold file:bg-green-950/20 file:border file:border-green-500/20 file:rounded file:px-3 file:py-1 hover:file:bg-green-900/30 transition-all bg-black/50 border-green-500/20 focus:border-green-400 focus:ring-green-500/20 text-green-300 placeholder:text-green-800 text-sm" }), file && (_jsxs("p", { className: "text-[10px] text-green-500/70 flex items-center gap-1.5 bg-green-950/10 p-1.5 rounded border border-green-500/10 font-mono truncate", children: [_jsx(CheckCircle2, { className: "h-3 w-3 shrink-0" }), file.name] }))] }), _jsx(Button, { onClick: handleUpload, disabled: loading || !file, className: "w-full bg-green-600 hover:bg-green-500 text-black font-bold shadow-[0_0_15px_-3px_rgba(34,197,94,0.4)] hover:shadow-[0_0_20px_-3px_rgba(34,197,94,0.6)] transition-all duration-300 border-0 h-9 text-sm uppercase tracking-wider", children: loading ? (_jsxs("span", { className: "flex items-center gap-2", children: [_jsx(Terminal, { className: "h-3.5 w-3.5 animate-spin" }), "Processing..."] })) : (_jsxs("span", { className: "flex items-center gap-2", children: [_jsx(UploadCloud, { className: "h-3.5 w-3.5" }), "Upload SBOM"] })) }), message && (_jsxs(Alert, { variant: isSuccess ? "default" : "destructive", className: `${isSuccess ? "bg-green-950/20 text-green-400 border-green-500/30" : "bg-red-950/20 text-red-400 border-red-500/30"} backdrop-blur-sm py-3`, children: [isSuccess ? _jsx(CheckCircle2, { className: "h-3.5 w-3.5" }) : _jsx(AlertCircle, { className: "h-3.5 w-3.5" }), _jsx(AlertTitle, { className: "text-xs font-bold uppercase", children: isSuccess ? "Success" : "Error" }), _jsx(AlertDescription, { className: "text-xs mt-0.5 font-mono opacity-90", children: message })] })), result !== null && (_jsxs("div", { className: "rounded border border-green-500/20 bg-black/80 p-3 overflow-x-auto", children: [_jsxs("div", { className: "flex items-center gap-2 mb-2 text-[10px] font-bold text-green-500 uppercase tracking-wider", children: [_jsx(Terminal, { className: "h-3 w-3" }), " Response Data"] }), _jsx("pre", { className: "text-[10px] font-mono whitespace-pre-wrap break-all text-green-300/70 bg-black/50 p-2 rounded border border-green-500/10", children: JSON.stringify(result, null, 2) })] }))] })] }), _jsxs(Card, { className: "shadow-[0_0_40px_-10px_rgba(6,182,212,0.15)] border-cyan-500/20 bg-black/80 backdrop-blur-xl", children: [_jsx(CardHeader, { className: "pb-4 border-b border-cyan-500/10", children: _jsxs("div", { className: "flex items-center gap-3", children: [_jsx("div", { className: "p-2 bg-cyan-950/30 rounded border border-cyan-500/20", children: _jsx(ShieldAlert, { className: "h-5 w-5 text-cyan-400" }) }), _jsxs("div", { children: [_jsx(CardTitle, { className: "text-base font-bold text-cyan-400 uppercase tracking-wide", children: "Security Analysis" }), _jsx(CardDescription, { className: "text-cyan-600/60 text-xs mt-0.5", children: "Vulnerability & CRA compliance check" })] })] }) }), _jsxs(CardContent, { className: "pt-6 space-y-4", children: [_jsxs("div", { className: "space-y-2", children: [_jsx("label", { htmlFor: "componentId", className: "text-xs font-bold text-cyan-500 uppercase tracking-wider", children: "Component ID" }), _jsx(Input, { id: "componentId", type: "text", value: componentId, onChange: (event) => setComponentId(event.target.value), placeholder: "pkg:npm/example-library@1.0.0", className: "bg-black/50 border-cyan-500/20 focus:border-cyan-400 focus:ring-cyan-500/20 text-cyan-300 placeholder:text-cyan-800 font-mono text-sm h-9" })] }), _jsxs("div", { className: "grid grid-cols-2 gap-3", children: [_jsxs("div", { className: "space-y-2", children: [_jsx("label", { htmlFor: "packageName", className: "text-xs font-bold text-cyan-500 uppercase tracking-wider", children: "Package" }), _jsx(Input, { id: "packageName", type: "text", value: packageName, onChange: (event) => setPackageName(event.target.value), placeholder: "example-lib", className: "bg-black/50 border-cyan-500/20 focus:border-cyan-400 focus:ring-cyan-500/20 text-cyan-300 placeholder:text-cyan-800 font-mono text-sm h-9" })] }), _jsxs("div", { className: "space-y-2", children: [_jsx("label", { htmlFor: "packageVersion", className: "text-xs font-bold text-cyan-500 uppercase tracking-wider", children: "Version" }), _jsx(Input, { id: "packageVersion", type: "text", value: packageVersion, onChange: (event) => setPackageVersion(event.target.value), placeholder: "1.0.0", className: "bg-black/50 border-cyan-500/20 focus:border-cyan-400 focus:ring-cyan-500/20 text-cyan-300 placeholder:text-cyan-800 font-mono text-sm h-9" })] })] }), _jsx(Button, { onClick: handleAnalyze, disabled: analysisLoading, className: "w-full bg-cyan-600 hover:bg-cyan-500 text-black font-bold shadow-[0_0_15px_-3px_rgba(6,182,212,0.4)] hover:shadow-[0_0_20px_-3px_rgba(6,182,212,0.6)] transition-all duration-300 border-0 h-9 text-sm uppercase tracking-wider mt-2", children: analysisLoading ? (_jsxs("span", { className: "flex items-center gap-2", children: [_jsx(Terminal, { className: "h-3.5 w-3.5 animate-spin" }), "Scanning..."] })) : (_jsxs("span", { className: "flex items-center gap-2", children: [_jsx(ShieldAlert, { className: "h-3.5 w-3.5" }), "Analyze Component"] })) }), _jsx(Button, { onClick: handleGenerateReport, disabled: reportLoading || analysisLoading, className: "w-full bg-green-600 hover:bg-green-500 text-black font-bold h-9 text-sm uppercase tracking-wider", children: reportLoading ? "Generating Report..." : "Generate Security Report" }), reportMessage && (_jsx("p", { className: "text-xs text-green-400 font-mono", children: reportMessage })), reportResult !== null && (_jsxs("details", { className: "dashboard-card", children: [_jsx("summary", { children: "View Generated Security Report" }), _jsx("pre", { className: "result", children: JSON.stringify(reportResult, null, 2) })] })), analysisMessage && (_jsxs(Alert, { className: "mt-2 bg-cyan-950/20 border-cyan-500/30 text-cyan-400 backdrop-blur-sm py-3", children: [_jsx(Terminal, { className: "h-3.5 w-3.5" }), _jsx(AlertDescription, { className: "text-xs font-mono", children: analysisMessage })] })), analysisResult !== null && (_jsxs("div", { className: "dashboard-grid", children: [_jsxs("article", { className: "dashboard-card col-span-full", children: [_jsx("h3", { children: "Vulnerability Analysis" }), getAnalysisSection("vulnerabilityAnalysis") ? (_jsxs(_Fragment, { children: [_jsxs("p", { children: ["Severity:", " ", getAnalysisSection("vulnerabilityAnalysis")?.severity ?? "Unknown"] }), _jsxs("p", { children: ["NVD findings:", " ", getAnalysisSection("vulnerabilityAnalysis")
                                                                        ?.vulnerabilities?.nvd?.length ?? 0] }), _jsxs("p", { children: ["OSV findings:", " ", getAnalysisSection("vulnerabilityAnalysis")
                                                                        ?.vulnerabilities?.osv?.length ?? 0] }), _jsx("h4", { children: "Unified Vulnerability Findings" }), _jsxs("p", { children: ["Unique vulnerabilities:", " ", getAnalysisSection("vulnerabilityAnalysis")
                                                                        ?.unifiedVulnerabilities?.length ?? 0] }), getAnalysisSection("vulnerabilityAnalysis")
                                                                ?.unifiedVulnerabilities?.map((vulnerability) => (_jsxs("div", { className: "vulnerability-item", children: [_jsx("h5", { children: vulnerability.id }), _jsxs("p", { children: ["Severity: ", vulnerability.severity] }), _jsxs("p", { children: ["Sources: ", vulnerability.sources?.join(", ")] }), _jsx("p", { children: vulnerability.description }), vulnerability.cvssScore !== undefined && (_jsxs("p", { children: ["CVSS Score: ", vulnerability.cvssScore] })), vulnerability.matchedCPE && (_jsxs("div", { className: "cpe-evidence", children: [_jsx("strong", { children: "CPE Matching Evidence" }), _jsxs("p", { children: ["Matched CPE: ", vulnerability.matchedCPE] }), vulnerability.matchedVersionRange && (_jsxs("div", { children: [_jsxs("p", { children: ["Start including:", " ", vulnerability.matchedVersionRange.startIncluding ?? "Not specified"] }), _jsxs("p", { children: ["Start excluding:", " ", vulnerability.matchedVersionRange.startExcluding ?? "Not specified"] }), _jsxs("p", { children: ["End including:", " ", vulnerability.matchedVersionRange.endIncluding ?? "Not specified"] }), _jsxs("p", { children: ["End excluding:", " ", vulnerability.matchedVersionRange.endExcluding ?? "Not specified"] })] }))] }))] }, vulnerability.id))), _jsx("h4", { children: "NVD Findings" }), renderVulnerabilityList("nvd"), _jsx("h4", { children: "OSV Findings" }), renderVulnerabilityList("osv")] })) : (_jsx("p", { children: "Vulnerability results are unavailable." }))] }), _jsxs("article", { className: "dashboard-card", children: [_jsx("h3", { children: "Impact Analysis" }), _jsxs("p", { children: ["Potentially impacted components:", " ", getAnalysisSection("impactAnalysis")
                                                                ?.impactedComponents?.length ?? 0] }), renderImpactedComponents()] }), _jsxs("article", { className: "dashboard-card", children: [_jsx("h3", { children: "CRA Validation" }), getAnalysisSection("craValidation") ? (_jsxs(_Fragment, { children: [_jsxs("p", { children: ["Result:", " ", getAnalysisSection("craValidation")?.compliant
                                                                        ? "All prototype checks passed"
                                                                        : "Some prototype checks failed"] }), _jsxs("p", { children: ["Checks passed:", " ", getAnalysisSection("craValidation")?.results?.filter((item) => item.passed).length ?? 0, " / ", getAnalysisSection("craValidation")?.results?.length ?? 0] })] })) : (_jsx("p", { children: "CRA results are unavailable." }))] }), _jsxs("details", { className: "dashboard-card raw-details col-span-full", children: [_jsx("summary", { children: "View complete analysis response" }), _jsx("pre", { className: "result", children: JSON.stringify(analysisResult, null, 2) })] })] }))] })] })] })] }));
}
export default App;
