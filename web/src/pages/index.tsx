// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useRef, useState } from "react";
import { Layout } from "../components/Layout";
import { normalizeSearchQuery } from "../lib/pgp/verify-fpr.js";
import { fetchJson, queryParam } from "../lib/utils.js";
import { Fingerprint } from "../components/ui/fingerprint";
import { sortByTrust } from "../lib/trust.js";
import { userLabelOf } from "../lib/key-hit.js";
import { renderSearchHelpSnippets, wireSnippetCopy } from "../lib/snippets.js";

type SearchValidation = {
  ok: boolean;
  message?: string;
  shortKeyId?: boolean;
  nameSearch?: boolean;
};

type KeyHit = {
  fingerprint?: string;
  approval_state?: string;
  revoked?: boolean;
  approved_uids?: { email?: string; raw?: string }[];
  userLabel?: string;
  label?: string;
};

type SearchPayload = {
  results?: KeyHit[];
  reason?: string;
  error?: string;
  warning?: string;
  fingerprint?: string;
};

function initialsFor(label: string): string {
  const letters = String(label || "")
    .split("@")[0]
    .replace(/[^a-zA-Z0-9]/g, "");
  return (letters.slice(0, 2) || "?").toUpperCase();
}

function resultLabel(item: KeyHit): string {
  const uid = item.approved_uids?.[0];
  return userLabelOf(item) || uid?.email || uid?.raw || "Unknown";
}

function ResultCard({ item }: { item: KeyHit }) {
  const label = resultLabel(item);
  const state = item.revoked ? "revoked" : item.approval_state || "";
  return (
    <div className="result-card">
      <span className="result-avatar">{initialsFor(label)}</span>
      <div className="result-main">
        <div className="result-email-row">
          <span className="result-email">{label}</span>
          {state ? (
            <span className={state === "approved" ? "result-pill" : "result-pill pending"}>
              {state}
            </span>
          ) : null}
        </div>
        {/* This page already printed the whole fingerprint — it is the page
            that tells the reader to check one. What it did not do was let them
            take it anywhere: the value was inert text beside a View button, so
            confirming a key out of band meant selecting 49 characters by hand.
            Same characters, now a control that copies all of them, marks trust,
            and opens the key page. */}
        {item.fingerprint ? (
          <div className="result-fpr">
            <Fingerprint fpr={item.fingerprint} />
          </div>
        ) : null}
      </div>
      <a className="result-view-btn" href={`/key?fpr=${encodeURIComponent(item.fingerprint || "")}`}>
        View
      </a>
    </div>
  );
}

function isNameQuery(q: string): boolean {
  const s = q.trim();
  if (!s || s.includes("@")) return false;
  if (s.toLowerCase().startsWith("0x")) return false;
  const hex = s.replace(/\s+/g, "");
  if (
    /^[0-9a-fA-F]{8}$/.test(hex) ||
    /^[0-9a-fA-F]{16}$/.test(hex) ||
    /^[0-9a-fA-F]{32}$/.test(hex) ||
    /^[0-9a-fA-F]{40}$/.test(hex) ||
    /^[0-9a-fA-F]{64}$/.test(hex)
  ) {
    return false;
  }
  return /[a-zA-Z]/.test(s);
}

function validateQuery(q: string): SearchValidation {
  const s = q.trim();
  if (!s) return { ok: false, message: "Enter an email, name, fingerprint, or key ID." };
  if (s.toLowerCase().startsWith("0x")) {
    const hex = s.slice(2).replace(/\s+/g, "");
    if (
      !/^[0-9a-fA-F]{8}$/.test(hex) &&
      !/^[0-9a-fA-F]{16}$/.test(hex) &&
      !/^[0-9a-fA-F]{32}$/.test(hex) &&
      !/^[0-9a-fA-F]{40}$/.test(hex) &&
      !/^[0-9a-fA-F]{64}$/.test(hex)
    ) {
      return {
        ok: false,
        message:
          "Fingerprints must be 40 or 64 hex characters; key IDs must be 8 or 16 (32 = half fingerprint).",
      };
    }
    return { ok: true, shortKeyId: hex.length === 8 };
  }
  if (s.includes("@")) return { ok: true };
  const hex = s.replace(/\s+/g, "");
  if (
    /^[0-9a-fA-F]{40}$/.test(hex) ||
    /^[0-9a-fA-F]{64}$/.test(hex) ||
    /^[0-9a-fA-F]{32}$/.test(hex) ||
    /^[0-9a-fA-F]{16}$/.test(hex)
  ) {
    return { ok: true };
  }
  if (/^[0-9a-fA-F]{8}$/.test(hex)) {
    return { ok: true, shortKeyId: true };
  }
  if (isNameQuery(s)) {
    if (s.length < 2) {
      return { ok: false, message: "Name search requires at least 2 characters." };
    }
    return { ok: true, nameSearch: true };
  }
  return { ok: false, message: "Search by email, name, fingerprint, or 8/16-character key ID." };
}

function reasonMessage(payload: SearchPayload, query: string): string {
  const reason = payload.reason || "";
  if (reason === "pending") {
    if (payload.fingerprint) {
      return `A key matches <code>${query}</code> but is still pending approval. <a class="text-link" href="/key?fpr=${encodeURIComponent(payload.fingerprint)}">View pending key</a>`;
    }
    return "A matching key exists but is still pending approval (not published for email search yet).";
  }
  if (reason === "invalid_query") {
    return payload.error || "Unsupported search format.";
  }
  if (reason === "empty") return "";
  return "No matching approved keys found.";
}

function searchCautionHtml(payload: SearchPayload, v: SearchValidation): string {
  const parts: string[] = [];
  if (v.nameSearch || payload.reason === "name") {
    parts.push(
      `<p class="name-search-caution" role="status"><strong>Names are unverified.</strong> Match keys by verified email and confirm the full fingerprint out of band before trusting a key.</p>`
    );
  }
  if (payload.warning || payload.reason === "short_keyid" || v.shortKeyId) {
    const msg =
      payload.warning ||
      "Short (8-character) key IDs are collision-prone. Confirm the full fingerprint out of band before trusting a key.";
    parts.push(`<p class="name-search-caution" role="status"><strong>Short key ID.</strong> ${msg}</p>`);
  }
  return parts.join("");
}

function IndexPage() {
  const [query, setQuery] = useState(() => queryParam("q"));
  const [results, setResults] = useState<KeyHit[] | null>(null);
  const [message, setMessage] = useState("");
  const [cautionHtml, setCautionHtml] = useState("");
  const [error, setError] = useState("");
  const [searching, setSearching] = useState(false);
  const helpRef = useRef<HTMLDivElement | null>(null);
  const ran = useRef(false);

  useEffect(() => {
    if (helpRef.current) {
      helpRef.current.innerHTML = renderSearchHelpSnippets();
      wireSnippetCopy(helpRef.current);
    }
  }, []);

  const runSearch = async (q: string) => {
    setError("");
    setResults(null);
    setMessage("");
    setCautionHtml("");
    if (!q.trim()) return;

    const v = validateQuery(q);
    if (!v.ok) {
      setMessage(v.message || "");
      return;
    }

    setSearching(true);
    setMessage("Searching…");
    try {
      const normalized = normalizeSearchQuery(q);
      const payload: SearchPayload = await fetchJson(
        `/api/v1/search?q=${encodeURIComponent(normalized)}`
      );
      setCautionHtml(searchCautionHtml(payload, v));
      if (!payload.results || !payload.results.length) {
        setMessage(reasonMessage(payload, normalized));
        return;
      }
      setMessage("");
      setResults(sortByTrust(payload.results));
    } catch (err) {
      setMessage("");
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSearching(false);
    }
  };

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    if (query) void runSearch(query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Layout active="search">
      <div className="search-hero">
        <h1>Search verified public keys</h1>
        <p>Every key here is linked to an email its owner proved they control.</p>
      </div>

      <form
        id="search-form"
        onSubmit={(e) => {
          e.preventDefault();
          const q = query.trim();
          history.replaceState(null, "", q ? `/?q=${encodeURIComponent(q)}` : "/");
          void runSearch(q);
        }}
      >
        <div className="search-input-row">
          <label className="sr-only" htmlFor="q">
            Search by email, fingerprint, or key ID
          </label>
          <div className="search-input-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="10" cy="10" r="6" fill="none" stroke="var(--text-muted)" strokeWidth="2" />
              <line x1="14.5" y1="14.5" x2="20" y2="20" stroke="var(--text-muted)" strokeWidth="2" />
            </svg>
            <input
              type="search"
              id="q"
              name="q"
              placeholder="user@example.com or 0x…"
              autoComplete="off"
              autoFocus
              aria-describedby="search-hint"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          {/* Busy, not refused: the search this button started is running and
              the label says so. `aria-busy` keeps the accessible name, which
              `disabled` was dropping at the one moment it is wanted. */}
          <button
            className="search-submit-btn"
            type="submit"
            aria-busy={searching || undefined}
            onClick={(e) => {
              if (searching) e.preventDefault();
            }}
          >
            {searching ? "Searching…" : "Search"}
          </button>
        </div>
        <p id="search-hint" className="search-hint">
          Exact email, fingerprint, or 16-char key ID.
        </p>
      </form>

      {error ? <p className="text-error">{error}</p> : null}
      {cautionHtml ? <div dangerouslySetInnerHTML={{ __html: cautionHtml }} /> : null}
      {message ? <p className="muted text-center">{message}</p> : null}
      {results ? (
        <div>
          <p className="results-label results-label-wide">
            {results.length} result{results.length === 1 ? "" : "s"}
          </p>
          <div className="result-list">
            {results.map((item) => (
              <ResultCard key={item.fingerprint} item={item} />
            ))}
          </div>
        </div>
      ) : null}

      <p className="mt-lg text-center">
        <a className="text-link" href="/my-keys">
          Submit a public key
        </a>
      </p>

      <div className="mt-2xl" ref={helpRef} />

      <section className="project-info" aria-label="About Basilisk">
        <div className="about-bar">
          <img className="brand-mark brand-mark-light" src="/logo.png" alt="" width={64} height={64} />
          <img className="brand-mark brand-mark-dark" src="/logo-dark.png" alt="" width={64} height={64} />
          <a
            className="github-link"
            href="https://github.com/b1tninja/basilisk"
            target="_blank"
            rel="noopener noreferrer"
          >
            <svg className="github-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
              <path
                d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
            0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13
            -.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66
            .07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15
            -.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68
            0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56
            .82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07
            -.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"
              />
            </svg>
            b1tninja/basilisk
          </a>
          <span className="about-tagline">Open-source verifying OpenPGP keyserver</span>
        </div>

        <div className="tech-pills">
          <span className="tech-pill">OpenPGP RFC&nbsp;9580</span>
          <span className="tech-pill">HKP protocol</span>
          <span className="tech-pill">WKD</span>
          <span className="tech-pill">Azure Functions</span>
          <span className="tech-pill tech-pill-green">Open source · MIT</span>
        </div>

        <div className="feature-grid">
          <div className="feature-card">
            <div className="feature-icon" aria-hidden="true">
              <svg
                viewBox="0 0 20 20"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M10 1l2.39 4.84 5.34.78-3.87 3.77.91 5.32L10 13.27l-4.77 2.44.91-5.32L2.27 6.62l5.34-.78z" />
              </svg>
            </div>
            <p className="feature-title">Verified keys</p>
            <p className="feature-body">
              Every key is linked to an email address you own. Claimants verify via a one-time
              token — no unowned keys in the index.
            </p>
          </div>
          <div className="feature-card">
            <div className="feature-icon" aria-hidden="true">
              <svg
                viewBox="0 0 20 20"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <rect x="3" y="8" width="14" height="10" rx="2" />
                <path d="M7 8V6a3 3 0 016 0v2" />
              </svg>
            </div>
            <p className="feature-title">In-browser crypto</p>
            <p className="feature-body">
              Encrypt and decrypt in the <a className="text-link" href="/toolkit#encrypt">Toolkit</a>{" "}
              notebook, and verify signatures in your browser with OpenPGP.js. Private keys and
              plaintext never leave your device.
            </p>
          </div>
          <div className="feature-card">
            <div className="feature-icon" aria-hidden="true">
              <svg
                viewBox="0 0 20 20"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <circle cx="10" cy="10" r="8" />
                <path d="M10 2c0 0-4 4-4 8s4 8 4 8M10 2c0 0 4 4 4 8s-4 8-4 8M2 10h16" />
              </svg>
            </div>
            <p className="feature-title">Standard protocols</p>
            <p className="feature-body">
              Compatible with GnuPG via HKP (<code>--recv-keys</code>, <code>--send-keys</code>)
              and WKD for automatic key discovery by email domain.
            </p>
          </div>
        </div>
      </section>
    </Layout>
  );
}

installBootDiagnostics();
createRoot(document.getElementById("app")!).render(<IndexPage />);
