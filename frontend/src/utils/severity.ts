
export type Severity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "UNKNOWN";

export function normalizeSeverity(value: unknown): Severity {
  if (typeof value !== "string" && typeof value !== "number") {
    return "UNKNOWN";
  }

  const text = String(value).trim().toUpperCase();

  if (text === "CRITICAL") return "CRITICAL";
  if (text === "HIGH") return "HIGH";
  if (text === "MEDIUM") return "MEDIUM";
  if (text === "LOW") return "LOW";

  // Accept a numeric CVSS base score.
  const score = Number(text);

  if (text !== "" && Number.isFinite(score) && score >= 0 && score <= 10) {
    if (score >= 9) return "CRITICAL";
    if (score >= 7) return "HIGH";
    if (score >= 4) return "MEDIUM";
    if (score > 0) return "LOW";
    return "UNKNOWN";
  }

  if (text.startsWith("CVSS:")) {
    return "UNKNOWN";
  }

  return "UNKNOWN";
}
