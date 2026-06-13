import { useState } from "react";
import { api, getApiBase, getApiKey, saveSettings } from "./api";
import type { FeedbackSummary, Finding, ProjectFindings } from "./types";

function riskClass(level: string): string {
  return ["critical", "high", "medium", "low"].includes(level) ? level : "low";
}

function Settings({ onSaved }: { onSaved: () => void }) {
  const [base, setBase] = useState(getApiBase());
  const [key, setKey] = useState(getApiKey());
  const [status, setStatus] = useState<string>("");

  const test = async () => {
    setStatus("checking…");
    try {
      const result = await api.health();
      setStatus(`backend ${result.status}`);
    } catch (e) {
      setStatus(`unreachable: ${(e as Error).message}`);
    }
  };

  return (
    <div className="panel">
      <div className="row">
        <div>
          <label>API base URL</label>
          <input value={base} onChange={(e) => setBase(e.target.value)} />
        </div>
        <div>
          <label>API key (optional)</label>
          <input value={key} onChange={(e) => setKey(e.target.value)} placeholder="X-API-Key" />
        </div>
        <button
          onClick={() => {
            saveSettings(base, key);
            onSaved();
          }}
        >
          Save
        </button>
        <button className="secondary" onClick={test}>
          Test connection
        </button>
        {status && <span className="pill">{status}</span>}
      </div>
    </div>
  );
}

function SummaryBar({ summary }: { summary: FeedbackSummary }) {
  const items: [string, number][] = [
    ["Findings", summary.finding_count],
    ["True positive", summary.true_positive_count],
    ["False positive", summary.false_positive_count],
    ["Suppressed", summary.suppressed_count],
    ["Unreviewed", summary.unreviewed_count],
  ];
  return (
    <div className="panel stats">
      {items.map(([label, value]) => (
        <div className="stat" key={label}>
          <div className="value">{value}</div>
          <p className="label">{label}</p>
        </div>
      ))}
    </div>
  );
}

function FindingCard({ finding, onChanged }: { finding: Finding; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="finding">
      <div className="head">
        <span className={`badge ${riskClass(finding.risk_level)}`}>{finding.risk_level}</span>
        <span className="pill">{finding.action}</span>
        {finding.suppressed && <span className="pill">suppressed</span>}
        {finding.feedback && <span className="pill">{finding.feedback.label}</span>}
      </div>
      <div className="path">
        {finding.file_path}
        {finding.line_number != null ? `:${finding.line_number}` : ""}
      </div>
      <div>
        {finding.secret_type} · {finding.redacted_secret ?? "—"}
        {finding.risk_score ? ` · score ${finding.risk_score.score}` : ""}
      </div>
      {finding.decision_reason && <p className="reason">{finding.decision_reason}</p>}
      <div className="actions">
        <button disabled={busy} onClick={() => run(() => api.markTruePositive(finding.finding_id, "reviewed in dashboard"))}>
          True positive
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => run(() => api.markFalsePositive(finding.finding_id, "reviewed in dashboard"))}
        >
          False positive
        </button>
        <button className="secondary" disabled={busy} onClick={() => run(() => api.suppress(finding.finding_id, "suppressed in dashboard"))}>
          Suppress
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

export default function App() {
  const [projectId, setProjectId] = useState("");
  const [findings, setFindings] = useState<ProjectFindings | null>(null);
  const [summary, setSummary] = useState<FeedbackSummary | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = async () => {
    if (!projectId.trim()) return;
    setLoading(true);
    setError("");
    try {
      const [f, s] = await Promise.all([api.projectFindings(projectId), api.feedbackSummary(projectId)]);
      setFindings(f);
      setSummary(s);
    } catch (e) {
      setError((e as Error).message);
      setFindings(null);
      setSummary(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header>
        <h1>CredHunter-X Dashboard</h1>
        <p>Review and triage Git leak findings across your projects.</p>
      </header>

      <Settings onSaved={() => setError("")} />

      <div className="panel">
        <div className="row">
          <div>
            <label>Project ID</label>
            <input
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
              placeholder="e.g. project-demo"
              onKeyDown={(e) => e.key === "Enter" && load()}
            />
          </div>
          <button onClick={load} disabled={loading || !projectId.trim()}>
            {loading ? "Loading…" : "Load findings"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>

      {summary && <SummaryBar summary={summary} />}

      {findings && (
        <div>
          <h2>
            {findings.finding_count} finding{findings.finding_count === 1 ? "" : "s"}
          </h2>
          {findings.findings.length === 0 && <p>No findings for this project.</p>}
          {findings.findings.map((f) => (
            <FindingCard key={f.finding_id} finding={f} onChanged={load} />
          ))}
        </div>
      )}
    </div>
  );
}
