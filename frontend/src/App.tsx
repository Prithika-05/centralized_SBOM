
import { useState } from "react";
import "./App.css";

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<unknown>(null);

  async function handleUpload() {
    if (!file) {
      setMessage("Please select an SBOM file first.");
      return;
    }

    const formData = new FormData();
    formData.append("sbom", file);

    setLoading(true);
    setMessage("");
    setResult(null);

    try {
      const response = await fetch(
        "http://localhost:5000/api/sboms/upload",
        {
          method: "POST",
          body: formData,
        }
      );

      const data: unknown = await response.json();

      if (!response.ok) {
        setMessage("Upload failed. Check the response below.");
        setResult(data);
        return;
      }

      setMessage("SBOM uploaded successfully.");
      setResult(data);
    } catch {
      setMessage(
        "Could not connect to the backend. Check that it is running."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="container">
      <header>
        <h1>Centralized SBOM Management System</h1>
        <p>
          Upload and validate Software Bill of Materials files.
        </p>
      </header>

      <section className="upload-card">
        <h2>Upload an SBOM</h2>
        <p>Choose an SPDX or CycloneDX JSON file.</p>

        <input
          type="file"
          accept=".json,application/json"
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setMessage("");
            setResult(null);
          }}
        />

        {file && <p>Selected file: {file.name}</p>}

        <button
          onClick={handleUpload}
          disabled={loading || !file}
        >
          {loading ? "Uploading..." : "Upload SBOM"}
        </button>

        {message && <p role="status">{message}</p>}

        {result !== null && (
          <pre className="result">
            {JSON.stringify(result, null, 2)}
          </pre>
        )}
      </section>
    </main>
  );
}

export default App;
