import type { FeedbackSummary, ProjectFindings, Scan } from "./types";

const BASE_KEY = "credhunter.apiBase";
const KEY_KEY = "credhunter.apiKey";

export function getApiBase(): string {
  return localStorage.getItem(BASE_KEY) || "http://localhost:8000";
}

export function getApiKey(): string {
  return localStorage.getItem(KEY_KEY) || "";
}

export function saveSettings(base: string, key: string): void {
  localStorage.setItem(BASE_KEY, base.replace(/\/$/, ""));
  localStorage.setItem(KEY_KEY, key);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string>),
  };
  const apiKey = getApiKey();
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  const response = await fetch(`${getApiBase()}${path}`, { ...init, headers });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`${response.status} ${response.statusText}${detail ? ` — ${detail}` : ""}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string }>("/health"),
  projectFindings: (projectId: string) =>
    request<ProjectFindings>(`/api/projects/${encodeURIComponent(projectId)}/findings`),
  feedbackSummary: (projectId: string) =>
    request<FeedbackSummary>(`/api/projects/${encodeURIComponent(projectId)}/feedback-summary`),
  getScan: (scanId: string) => request<Scan>(`/api/scans/${encodeURIComponent(scanId)}`),
  scanPrComment: (scanId: string) =>
    request<{ scan_id: string; markdown: string }>(`/api/scans/${encodeURIComponent(scanId)}/pr-comment`),
  markTruePositive: (findingId: string, reason: string) =>
    request(`/api/findings/${encodeURIComponent(findingId)}/mark-true-positive`, {
      method: "POST",
      body: JSON.stringify({ user: "dashboard", reason }),
    }),
  markFalsePositive: (findingId: string, reason: string) =>
    request(`/api/findings/${encodeURIComponent(findingId)}/mark-false-positive`, {
      method: "POST",
      body: JSON.stringify({ user: "dashboard", reason }),
    }),
  suppress: (findingId: string, reason: string) =>
    request(`/api/findings/${encodeURIComponent(findingId)}/suppress`, {
      method: "POST",
      body: JSON.stringify({ user: "dashboard", reason, scope: "finding" }),
    }),
};
