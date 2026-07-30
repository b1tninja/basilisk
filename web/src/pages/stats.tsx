import { createRoot } from "react-dom/client";
import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { fetchJson } from "../lib/utils.js";

const KEY_STATS = [
  { key: "total", label: "Total keys" },
  { key: "approved", label: "Approved" },
  { key: "pending", label: "Pending" },
  { key: "rejected", label: "Rejected" },
];
const RUNTIME_STATS = [
  { key: "rejected_uploads", label: "Rejected uploads" },
  { key: "duplicate_uploads", label: "Duplicate uploads" },
  { key: "rate_limited", label: "Rate limited" },
];

function StatGrid({ items, stats }: { items: typeof KEY_STATS; stats: Record<string, unknown> }) {
  return (
    <div className="stats-grid">
      {items.map(({ key, label }) => (
        <div className="stat-tile" key={key}>
          <div className="stat-value">{String(stats[key] ?? 0)}</div>
          <div className="stat-label">{label}</div>
        </div>
      ))}
    </div>
  );
}

function StatsPage() {
  const [stats, setStats] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchJson("/pks/lookup?op=stats")
      .then((payload: { stats?: Record<string, unknown> }) => setStats(payload.stats || {}))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <Layout active="stats">
      <div className="page-header">
        <h1>Stats</h1>
        <p className="muted">Keyserver inventory and upload counters.</p>
      </div>

      {error && <p className="text-error">{error}</p>}
      {!stats && !error && <p className="muted">Loading…</p>}

      {stats && (
        <div>
          <div className="card">
            <p className="card-title">Keys</p>
            <StatGrid items={KEY_STATS} stats={stats} />
          </div>
          <div className="card">
            <p className="card-title">Runtime counters</p>
            <p className="muted stack-subhead">Per-instance counters since last process start.</p>
            <StatGrid items={RUNTIME_STATS} stats={stats} />
          </div>
          <div className="card">
            <p className="card-title">HKP endpoints</p>
            <ul className="help-list">
              <li><code>GET /pks/lookup?op=get&amp;search=…</code> — fetch key</li>
              <li><code>GET /pks/lookup?op=index&amp;search=…</code> — index (approved)</li>
              <li><code>GET /pks/lookup?op=stats</code> — this page's data</li>
              <li><code>POST /pks/add</code> — <code>gpg --send-keys</code></li>
            </ul>
            <p className="muted mt-md">Point GnuPG at <code>{window.location.origin}</code>.</p>
          </div>
        </div>
      )}
    </Layout>
  );
}

createRoot(document.getElementById("app")!).render(<StatsPage />);
