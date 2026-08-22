// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import {
  getExpertMode,
  getPreferredKeyserver,
  setExpertMode,
  setPreferredKeyserver,
} from "../lib/prefs.js";
import { cacheClear, cacheList } from "../lib/pubkey-cache.js";
import {
  getUpstreamConfig,
  isKeyserverAllowed,
  normalizeKeyserverHost,
} from "../lib/upstream-config.js";

type UpstreamConfig = {
  enabled: boolean;
  allowlist: string[];
  default?: string;
};

function PreferencesPage() {
  const [cfg, setCfg] = useState<UpstreamConfig | null>(null);
  const [expert, setExpert] = useState(() => getExpertMode());
  const [preferredKeyserver, setPreferredKeyserverState] = useState(() => getPreferredKeyserver());
  const [ksStatus, setKsStatus] = useState("");
  const [cachedCount, setCachedCount] = useState<number | null>(null);
  const [cacheStatus, setCacheStatus] = useState("");

  useEffect(() => {
    void getUpstreamConfig().then(setCfg);
    void cacheList().then((c: unknown[]) => setCachedCount(c.length));
  }, []);

  const onExpertChange = (checked: boolean) => {
    setExpert(checked);
    setExpertMode(checked);
  };

  const onKeyserverChange = async (value: string) => {
    if (!cfg) return;
    const host = normalizeKeyserverHost(value);
    if (host && !isKeyserverAllowed(host, cfg.allowlist)) {
      setPreferredKeyserverState("");
      setPreferredKeyserver("");
      setKsStatus("Using server default.");
      return;
    }
    setPreferredKeyserverState(host || "");
    setPreferredKeyserver(host || "");
    setKsStatus(host ? `Saved preferred keyserver: ${host}` : "Using server default.");
  };

  const onClearCache = async () => {
    await cacheClear();
    setCacheStatus("Pubkey cache cleared.");
    setCachedCount(0);
  };

  return (
    <Layout active="preferences">
      <div className="page-header">
        <h1>Preferences</h1>
        <p className="muted">Browser-local settings only — never uploaded to the keyserver.</p>
      </div>

      <section className="card prefs-card">
        <h2 className="card-title">Encrypt UI</h2>
        <label className="radio-row">
          <input
            type="checkbox"
            checked={expert}
            onChange={(e) => onExpertChange(e.target.checked)}
          />
          Expert mode (show advanced encryption options)
        </label>
        <p className="muted fs-sm mt-xs mb-0">Stored in this browser only.</p>
      </section>

      <section className="card prefs-card mt-lg">
        <h2 className="card-title">Upstream keyserver</h2>
        {cfg?.enabled ? (
          <>
            <p className="muted fs-md m-0-b-md">
              When this directory has no match, signed-in lookups can query an allowlisted
              verifying keyserver from your browser (not proxied by Basilisk).
            </p>
            <label className="field-label" htmlFor="pref-keyserver">
              Default upstream
            </label>
            <select
              id="pref-keyserver"
              className="text-input keyserver-select"
              aria-label="Upstream keyserver"
              value={preferredKeyserver}
              onChange={(e) => void onKeyserverChange(e.target.value)}
            >
              <option value="">
                {cfg.default ? `Server default (${cfg.default})` : "Server default"}
              </option>
              {cfg.allowlist.map((host) => {
                const h = normalizeKeyserverHost(host);
                return h ? (
                  <option key={h} value={h}>
                    {h}
                  </option>
                ) : null;
              })}
            </select>
            <p className="muted fs-sm mt-xs mb-0">
              Allowlist: {cfg.allowlist.join(", ") || "—"}. Server default:{" "}
              <code>{cfg.default || "—"}</code>.
            </p>
            <p className="muted fs-sm mt-sm" role="status">
              {ksStatus}
            </p>
          </>
        ) : cfg ? (
          <p className="muted fs-md m-0">
            Upstream search is disabled on this server (
            <code>BASILISK_UPSTREAM_ENABLED=0</code>).
          </p>
        ) : null}
      </section>

      <section className="card prefs-card mt-lg">
        <h2 className="card-title">Local public-key cache</h2>
        <p className="muted fs-md m-0-b-md">
          {cachedCount ?? 0} public key{cachedCount === 1 ? "" : "s"} cached in IndexedDB on this
          device (encrypt recipients you have looked up).
        </p>
        <button type="button" className="btn btn-ghost" onClick={() => void onClearCache()}>
          Clear pubkey cache
        </button>
        <p className="muted fs-sm mt-sm" role="status">
          {cacheStatus}
        </p>
      </section>
    </Layout>
  );
}

installBootDiagnostics();
createRoot(document.getElementById("app")!).render(<PreferencesPage />);
