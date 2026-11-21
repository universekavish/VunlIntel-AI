import { FormEvent, useEffect, useState } from "react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

import { Card, EmptyState, ErrorState, LoadingState } from "../components/ui";
import {
  apiRequest,
  AuthResponse,
  clearAuth,
  getSavedAuth,
  saveAuth,
  type Asset,
  type AssetMatch,
  type IngestionRun,
  type Investigation,
  type MlStatus,
  type RagEvidence,
  type RagSearchResponse,
} from "../lib/api";

type Page =
  | "overview"
  | "vulnerabilities"
  | "assets"
  | "analyst"
  | "investigations"
  | "remediation"
  | "models";

const NAV: { id: Page; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "◫" },
  { id: "vulnerabilities", label: "Vulnerabilities", icon: "◇" },
  { id: "assets", label: "Assets", icon: "▦" },
  { id: "analyst", label: "AI Analyst", icon: "✦" },
  { id: "investigations", label: "Investigations", icon: "⌕" },
  { id: "remediation", label: "Remediation", icon: "✓" },
  { id: "models", label: "Model Ops", icon: "▱" },
];

function pageFromHash(): Page {
  const value = window.location.hash.replace("#/", "");
  return NAV.some((item) => item.id === value) ? (value as Page) : "overview";
}

function AuthScreen({ onAuth }: { onAuth: (auth: AuthResponse) => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      if (mode === "login") {
        const auth = await apiRequest<AuthResponse>("/api/v1/auth/login", {
          method: "POST",
          body: JSON.stringify({
            email: String(form.get("email")),
            password: String(form.get("password")),
          }),
        });
        saveAuth(auth);
        onAuth(auth);
      } else {
        const auth = await apiRequest<AuthResponse>("/api/v1/auth/register", {
          method: "POST",
          body: JSON.stringify({
            organization_name: String(form.get("organization")),
            display_name: String(form.get("name")),
            email: String(form.get("email")),
            password: String(form.get("password")),
          }),
        });
        saveAuth(auth);
        onAuth(auth);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-panel">
        <div className="brand-mark">V</div>
        <p className="eyebrow">VulnIntel AI</p>
        <h1>{mode === "login" ? "Sign in" : "Create organization"}</h1>
        <p className="auth-copy">
          Investigate exposures with evidence-backed, tenant-isolated intelligence.
        </p>
        <form onSubmit={submit}>
          {mode === "register" && (
            <>
              <label>
                Organization
                <input name="organization" minLength={2} required autoComplete="organization" />
              </label>
              <label>
                Display name
                <input name="name" minLength={1} required autoComplete="name" />
              </label>
            </>
          )}
          <label>
            Email
            <input name="email" type="email" required autoComplete="email" />
          </label>
          <label>
            Password
            <input name="password" type="password" minLength={12} required autoComplete={mode === "login" ? "current-password" : "new-password"} />
          </label>
          {error && <div className="inline-error">{error}</div>}
          <button className="button primary full" disabled={busy}>
            {busy ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
        <button className="text-button" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Create a new organization" : "Use an existing account"}
        </button>
      </section>
      <aside className="auth-art">
        <div className="orb orb-one" />
        <div className="orb orb-two" />
        <div className="auth-art-copy">
          <span>Contextual risk</span>
          <strong>Evidence first.<br />LLMs second.</strong>
        </div>
      </aside>
    </main>
  );
}

function useAsync<T>(loader: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    loader()
      .then((value) => active && setData(value))
      .catch((caught) => active && setError(caught instanceof Error ? caught.message : "Request failed"))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
    // loader is intentionally refreshed with the attempt/reload action.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt]);

  return { data, loading, error, reload: () => setAttempt((value) => value + 1) };
}

function MetricCard({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: "red" | "amber" | "blue";
}) {
  return (
    <Card className={`metric-card ${tone || ""}`}>
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{detail}</span>
    </Card>
  );
}

function Overview() {
  const assetsState = useAsync(() => apiRequest<Asset[]>("/api/v1/assets"));
  const investigationsState = useAsync(() => apiRequest<Investigation[]>("/api/v1/investigations"));
  const ingestionState = useAsync(() => apiRequest<IngestionRun[]>("/api/v1/ingestion/runs").catch(() => []));

  const assets = assetsState.data || [];
  const investigations = investigationsState.data || [];
  const runs = ingestionState.data || [];
  const criticalAssets = assets.filter((asset) => asset.criticality === "critical").length;
  const activeInvestigations = investigations.filter((item) =>
    ["running", "waiting_approval"].includes(item.status),
  ).length;
  const latestFailedRuns = runs.filter((run) => run.status === "failed").length;
  const criticalityData = [
    { name: "Low", value: assets.filter((item) => item.criticality === "low").length, color: "#7fd7bd" },
    { name: "Medium", value: assets.filter((item) => item.criticality === "medium").length, color: "#7ea7d8" },
    { name: "High", value: assets.filter((item) => item.criticality === "high").length, color: "#efb66f" },
    { name: "Critical", value: criticalAssets, color: "#ed7a70" },
  ];
  const loading = assetsState.loading || investigationsState.loading;
  const error = assetsState.error || investigationsState.error;

  if (loading) return <LoadingState label="Loading security overview" />;
  if (error) return <ErrorState message={error} onRetry={assetsState.reload} />;

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Security overview</p>
          <h1>Command center</h1>
        </div>
        <span className="live-indicator"><i /> Live workspace</span>
      </div>
      <div className="metric-grid">
        <MetricCard label="Managed assets" value={assets.length} detail={`${assets.filter((asset) => asset.active).length} active`} />
        <MetricCard label="Critical assets" value={criticalAssets} detail="Highest asset tier" tone="red" />
        <MetricCard label="Active investigations" value={activeInvestigations} detail="Awaiting or in progress" tone="amber" />
        <MetricCard label="Failed ingestion runs" value={latestFailedRuns} detail="Latest recorded runs" tone="blue" />
      </div>
      <div className="dashboard-grid">
        <Card title="Asset criticality" className="chart-card">
          {assets.length ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={criticalityData} dataKey="value" nameKey="name" innerRadius={58} outerRadius={90} paddingAngle={3}>
                  {criticalityData.map((item) => <Cell key={item.name} fill={item.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : <EmptyState title="No asset data" message="Import or create assets to populate this view." />}
        </Card>
        <Card title="Ingestion health" action={<span className="card-meta">{runs.length} recent runs</span>}>
          {runs.length ? (
            <div className="run-list">
              {runs.slice(0, 6).map((run) => (
                <div className="run-row" key={run.id}>
                  <span className={`status-dot ${run.status === "completed" ? "ok" : run.status === "failed" ? "bad" : ""}`} />
                  <div><strong>{run.source}</strong><span>{run.mode}</span></div>
                  <div className="run-count"><strong>{run.stored_count}</strong><span>stored</span></div>
                  <span className={`tag ${run.status}`}>{run.status}</span>
                </div>
              ))}
            </div>
          ) : <EmptyState title="No ingestion runs" message="Run an official source synchronization to begin." />}
        </Card>
      </div>
    </>
  );
}

function Vulnerabilities() {
  const assetsState = useAsync(() => apiRequest<Asset[]>("/api/v1/assets"));
  const [assetId, setAssetId] = useState("");
  const [matches, setMatches] = useState<AssetMatch[]>([]);
  const [loadingMatches, setLoadingMatches] = useState(false);
  const [matchError, setMatchError] = useState("");

  async function loadMatches(id: string) {
    setLoadingMatches(true);
    setMatchError("");
    try {
      setMatches(await apiRequest<AssetMatch[]>(`/api/v1/assets/${id}/matches`));
    } catch (caught) {
      setMatchError(caught instanceof Error ? caught.message : "Unable to load matches");
    } finally {
      setLoadingMatches(false);
    }
  }

  useEffect(() => {
    if (assetsState.data?.length && !assetId) {
      setAssetId(assetsState.data[0].id);
      void loadMatches(assetsState.data[0].id);
    }
  }, [assetsState.data, assetId]);

  if (assetsState.loading) return <LoadingState label="Loading vulnerability inventory" />;
  if (assetsState.error) return <ErrorState message={assetsState.error} onRetry={assetsState.reload} />;

  return (
    <>
      <div className="page-heading">
        <div><p className="eyebrow">Deterministic findings</p><h1>Vulnerability explorer</h1></div>
        <label className="select-label">
          Asset
          <select value={assetId} onChange={(event) => { setAssetId(event.target.value); void loadMatches(event.target.value); }}>
            {!assetsState.data?.length && <option value="">No assets</option>}
            {assetsState.data?.map((asset) => <option value={asset.id} key={asset.id}>{asset.name}</option>)}
          </select>
        </label>
      </div>
      {matchError ? <ErrorState message={matchError} /> :
        loadingMatches ? <LoadingState label="Evaluating asset evidence" /> :
        matches.length ? (
          <Card title={`${matches.length} evidence-backed matches`}>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Identifier</th><th>Source</th><th>Outcome</th><th>Confidence</th></tr></thead>
                <tbody>
                  {matches.map((match) => (
                    <tr key={`${match.source}-${match.vulnerability_id}`}>
                      <td><strong>{match.vulnerability_id}</strong></td>
                      <td>{match.source}</td>
                      <td><span className={`tag ${match.outcome}`}>{match.outcome.replace("_", " ")}</span></td>
                      <td>{Math.round(match.confidence * 100)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        ) : <EmptyState title="No vulnerability matches" message="Run matching for this asset or ingest vulnerability ranges first." />}
    </>
  );
}

function AssetsPage() {
  const state = useAsync(() => apiRequest<Asset[]>("/api/v1/assets"));
  const [creating, setCreating] = useState(false);

  async function createAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await apiRequest<Asset>("/api/v1/assets", {
        method: "POST",
        body: JSON.stringify({
          name: String(form.get("name")),
          asset_type: String(form.get("asset_type")),
          hostname: String(form.get("hostname") || "") || null,
          environment: String(form.get("environment") || "") || null,
          criticality: String(form.get("criticality")),
          external_id: String(form.get("external_id") || "") || null,
          software: [],
        }),
      });
      setCreating(false);
      state.reload();
    } catch (caught) {
      window.alert(caught instanceof Error ? caught.message : "Unable to create asset");
    }
  }

  if (state.loading) return <LoadingState label="Loading assets" />;
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;

  return (
    <>
      <div className="page-heading">
        <div><p className="eyebrow">Enterprise inventory</p><h1>Assets</h1></div>
        <button className="button primary" onClick={() => setCreating(true)}>Add asset</button>
      </div>
      {creating && (
        <Card title="Create asset">
          <form className="asset-form" onSubmit={createAsset}>
            <label>Name<input name="name" required /></label>
            <label>Type<input name="asset_type" required placeholder="server" /></label>
            <label>Hostname<input name="hostname" /></label>
            <label>Environment<input name="environment" placeholder="production" /></label>
            <label>Criticality<select name="criticality" defaultValue="medium"><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>External ID<input name="external_id" /></label>
            <div className="form-actions"><button type="button" className="button secondary" onClick={() => setCreating(false)}>Cancel</button><button className="button primary">Create</button></div>
          </form>
        </Card>
      )}
      {state.data?.length ? (
        <Card>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Asset</th><th>Type</th><th>Environment</th><th>Criticality</th><th>Status</th></tr></thead>
              <tbody>
                {state.data.map((asset) => (
                  <tr key={asset.id}>
                    <td><strong>{asset.name}</strong><span className="cell-sub">{asset.hostname || asset.external_id || "No identifier"}</span></td>
                    <td>{asset.asset_type}</td><td>{asset.environment || "—"}</td>
                    <td><span className={`tag ${asset.criticality}`}>{asset.criticality}</span></td>
                    <td><span className={`status-dot ${asset.active ? "ok" : "bad"}`} /> {asset.active ? "Active" : "Inactive"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : <EmptyState title="No assets" message="Create or import assets to build your inventory." />}
    </>
  );
}

function AnalystPage() {
  const [query, setQuery] = useState("");
  const [evidence, setEvidence] = useState<RagEvidence[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [searched, setSearched] = useState(false);

  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setSearched(true);
    try {
      const response = await apiRequest<RagSearchResponse>("/api/v1/rag/search", {
        method: "POST",
        body: JSON.stringify({ query, limit: 8, hybrid: true, rerank: true }),
      });
      setEvidence(response.evidence);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to search evidence");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-heading">
        <div><p className="eyebrow">Evidence-grounded workspace</p><h1>AI Security Analyst</h1></div>
      </div>
      <Card className="analyst-compose">
        <form onSubmit={search}>
          <label htmlFor="analyst-query">Investigation question</label>
          <div className="compose-row">
            <textarea
              id="analyst-query"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Ask about a CVE, affected software, mitigation, or threat context..."
              required
              minLength={3}
            />
            <button className="button primary" disabled={busy}>{busy ? "Searching..." : "Search evidence"}</button>
          </div>
        </form>
      </Card>
      {error && <ErrorState message={error} />}
      {busy && <LoadingState label="Retrieving validated evidence" />}
      {!busy && searched && !error && (
        evidence.length ? (
          <div className="evidence-grid">
            {evidence.map((item) => (
              <Card key={`${item.source}-${item.source_id}-${item.citation}`} className="evidence-card">
                <div className="evidence-head">
                  <span className="tag evidence">{item.document_type}</span>
                  <span>{Math.round(item.score * 100)}% relevance</span>
                </div>
                <h3>{item.source_id}</h3>
                <p>{item.text}</p>
                <footer>
                  <span className="citation">[{item.citation}]</span>
                  {item.citation_valid && <span className="validated">Verified source</span>}
                </footer>
              </Card>
            ))}
          </div>
        ) : <EmptyState title="No validated evidence" message="Try broader terms or index available source records first." />
      )}
    </>
  );
}

function InvestigationsPage() {
  const state = useAsync(() => apiRequest<Investigation[]>("/api/v1/investigations"));
  const [selected, setSelected] = useState<Investigation | null>(null);
  const [creating, setCreating] = useState(false);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const investigation = await apiRequest<Investigation>("/api/v1/investigations", {
        method: "POST",
        body: JSON.stringify({
          query: String(form.get("query")),
          cve_id: String(form.get("cve_id") || "") || null,
          asset_id: String(form.get("asset_id") || "") || null,
        }),
      });
      setCreating(false);
      setSelected(investigation);
      state.reload();
    } catch (caught) {
      window.alert(caught instanceof Error ? caught.message : "Unable to start investigation");
    }
  }

  if (state.loading) return <LoadingState label="Loading investigations" />;
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;

  return (
    <>
      <div className="page-heading">
        <div><p className="eyebrow">Workflow audit trail</p><h1>Investigations</h1></div>
        <button className="button primary" onClick={() => setCreating(true)}>New investigation</button>
      </div>
      {creating && (
        <Card title="Start investigation">
          <form className="investigation-form" onSubmit={create}>
            <label>Question or entity<textarea name="query" required minLength={3} /></label>
            <label>CVE identifier<input name="cve_id" placeholder="CVE-2026-0001" /></label>
            <label>Asset ID<input name="asset_id" placeholder="Optional UUID" /></label>
            <div className="form-actions"><button type="button" className="button secondary" onClick={() => setCreating(false)}>Cancel</button><button className="button primary">Start</button></div>
          </form>
        </Card>
      )}
      <div className="investigation-layout">
        <Card title={`${state.data?.length || 0} investigations`}>
          {state.data?.length ? (
            <div className="investigation-list">
              {state.data.map((item) => (
                <button
                  className={`investigation-row ${selected?.id === item.id ? "selected" : ""}`}
                  key={item.id}
                  onClick={() => setSelected(item)}
                >
                  <div><strong>{item.cve_id || "Entity investigation"}</strong><span>{item.updated_at ? new Date(item.updated_at).toLocaleString() : "Unknown time"}</span></div>
                  <span className={`tag ${item.status}`}>{item.status.replace("_", " ")}</span>
                </button>
              ))}
            </div>
          ) : <EmptyState title="No investigations" message="Start an investigation to begin a persisted workflow." />}
        </Card>
        <Card title="Investigation details" className="detail-card">
          {selected ? (
            <div className="detail-content">
              <div className="detail-status"><span className={`tag ${selected.status}`}>{selected.status.replace("_", " ")}</span><span>{selected.langgraph_thread_id}</span></div>
              {selected.error_summary && <div className="inline-error">{selected.error_summary}</div>}
              {selected.report ? (
                <pre>{JSON.stringify(selected.report, null, 2)}</pre>
              ) : (
                <pre>{JSON.stringify(selected.state, null, 2)}</pre>
              )}
            </div>
          ) : <EmptyState title="Select an investigation" message="Choose a workflow to inspect its persisted state." />}
        </Card>
      </div>
    </>
  );
}

function RemediationPage() {
  const state = useAsync(() => apiRequest<Investigation[]>("/api/v1/investigations"));
  const [busyId, setBusyId] = useState("");

  async function decide(investigation: Investigation, approved: boolean) {
    setBusyId(investigation.id);
    try {
      await apiRequest<Investigation>(`/api/v1/investigations/${investigation.id}/approve`, {
        method: "POST",
        body: JSON.stringify({
          approved,
          reviewer: "Security Analyst",
          rationale: approved ? "Approved after evidence review." : "Rejected after evidence review.",
        }),
      });
      state.reload();
    } catch (caught) {
      window.alert(caught instanceof Error ? caught.message : "Unable to record approval");
    } finally {
      setBusyId("");
    }
  }

  if (state.loading) return <LoadingState label="Loading remediation queue" />;
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;
  const queue = state.data?.filter((item) => item.status === "waiting_approval" || item.status === "running") || [];
  const completed = state.data?.filter((item) => ["approved", "rejected", "completed"].includes(item.status)) || [];

  return (
    <>
      <div className="page-heading"><div><p className="eyebrow">Human review required</p><h1>Remediation center</h1></div></div>
      <Card title={`${queue.length} awaiting review`}>
        {queue.length ? (
          <div className="remediation-list">
            {queue.map((item) => (
              <article className="remediation-row" key={item.id}>
                <div><span className="tag waiting_approval">approval</span><h3>{item.cve_id || "Entity investigation"}</h3><p>Investigation {item.id.slice(0, 8)}</p></div>
                <div className="approval-actions">
                  <button className="button secondary" disabled={busyId === item.id} onClick={() => void decide(item, false)}>Reject</button>
                  <button className="button primary" disabled={busyId === item.id} onClick={() => void decide(item, true)}>Approve</button>
                </div>
              </article>
            ))}
          </div>
        ) : <EmptyState title="No pending recommendations" message="New human-approval workflows will appear here." />}
      </Card>
      {completed.length > 0 && (
        <Card title="Recent decisions" className="decision-card">
          <div className="table-wrap"><table><thead><tr><th>Investigation</th><th>Status</th><th>Updated</th></tr></thead><tbody>
            {completed.slice(0, 8).map((item) => <tr key={item.id}><td>{item.cve_id || item.id.slice(0, 8)}</td><td><span className={`tag ${item.status}`}>{item.status}</span></td><td>{new Date(item.updated_at).toLocaleString()}</td></tr>)}
          </tbody></table></div>
        </Card>
      )}
    </>
  );
}

function ModelsPage() {
  const ml = useAsync(() => apiRequest<MlStatus>("/api/v1/ml/inference/status"));
  if (ml.loading) return <LoadingState label="Checking model configuration" />;
  if (ml.error) return <ErrorState message={ml.error} onRetry={ml.reload} />;
  const status = ml.data;
  return (
    <>
      <div className="page-heading"><div><p className="eyebrow">ML operations</p><h1>Model observability</h1></div></div>
      {status ? (
        <div className="model-layout">
          <Card title="Inference configuration">
            <dl className="status-list">
              <div><dt>Fine-tuning enabled</dt><dd>{status.enabled ? "Yes" : "No"}</dd></div>
              <div><dt>Model loaded</dt><dd>{status.model_loaded ? "Yes" : "No"}</dd></div>
              <div><dt>CPU safe</dt><dd>{status.cpu_safe ? "Yes" : "No"}</dd></div>
              <div><dt>Base model</dt><dd>{status.base_model || "Not configured"}</dd></div>
              <div><dt>LoRA adapter</dt><dd>{status.adapter_path || "Not configured"}</dd></div>
            </dl>
          </Card>
          <Card title="Runtime mode">
            <div className={`runtime-state ${status.enabled ? "enabled" : ""}`}>
              <span className="status-dot ok" />
              <div><strong>{status.enabled ? "Inference enabled" : "Deterministic fallback"}</strong><p>{status.enabled ? "Optional model execution is explicitly configured." : "Application runs without PyTorch or a fine-tuned model."}</p></div>
            </div>
          </Card>
        </div>
      ) : <EmptyState title="No model status" message="The backend model status is unavailable." />}
    </>
  );
}

export default function App() {
  const [auth, setAuth] = useState<AuthResponse | null>(() => getSavedAuth());
  const [page, setPage] = useState<Page>(pageFromHash);

  useEffect(() => {
    const listener = () => setPage(pageFromHash());
    window.addEventListener("hashchange", listener);
    return () => window.removeEventListener("hashchange", listener);
  }, []);

  function navigate(next: Page) {
    window.location.hash = `/${next}`;
    setPage(next);
  }

  if (!auth) return <AuthScreen onAuth={setAuth} />;

  const content = (() => {
    switch (page) {
      case "vulnerabilities": return <Vulnerabilities />;
      case "assets": return <AssetsPage />;
      case "analyst": return <AnalystPage />;
      case "investigations": return <InvestigationsPage />;
      case "remediation": return <RemediationPage />;
      case "models": return <ModelsPage />;
      default: return <Overview />;
    }
  })();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button className="brand" onClick={() => navigate("overview")} aria-label="VulnIntel overview">
          <span className="brand-mark">V</span><strong>VulnIntel</strong>
        </button>
        <nav>
          {NAV.map((item) => (
            <button key={item.id} className={page === item.id ? "active" : ""} onClick={() => navigate(item.id)}>
              <span className="nav-icon">{item.icon}</span><span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="org-avatar">{auth.organization.name.slice(0, 1).toUpperCase()}</div>
          <div><strong>{auth.user.display_name}</strong><span>{auth.organization.name}</span></div>
        </div>
      </aside>
      <main className="main-workspace">
        <header className="topbar">
          <div className="topbar-search"><span>⌕</span><span>Search workspace</span></div>
          <div className="topbar-actions">
            <span className="role-badge">{auth.user.role}</span>
            <button className="icon-button" title="Log out" onClick={() => { clearAuth(); setAuth(null); }}>↗</button>
          </div>
        </header>
        <div className="page-content">{content}</div>
      </main>
    </div>
  );
}
