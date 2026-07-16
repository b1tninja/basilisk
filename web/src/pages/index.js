import { Auth } from "../lib/auth.js";
import { fetchJson, queryParam, showError } from "../lib/utils.js";
import { renderKeysTable } from "../lib/keys.js";
import {
  renderSearchHelpSnippets,
  wireSnippetCopy,
} from "../lib/snippets.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"));

const form = document.getElementById("search-form");
const input = document.getElementById("q");
const results = document.getElementById("results");
const error = document.getElementById("error");
const help = document.getElementById("cli-help");
const submitBtn = form?.querySelector('button[type="submit"]');

if (help) {
  help.innerHTML = renderSearchHelpSnippets();
  wireSnippetCopy(help);
}

function isNameQuery(q) {
  const s = q.trim();
  if (!s || s.includes("@")) return false;
  if (s.toLowerCase().startsWith("0x")) return false;
  const hex = s.replace(/\s+/g, "");
  if (/^[0-9a-fA-F]{8}$/.test(hex) || /^[0-9a-fA-F]{16}$/.test(hex) || /^[0-9a-fA-F]{40}$/.test(hex)) {
    return false;
  }
  // At least one letter — treat as a name / free-text UID search.
  return /[a-zA-Z]/.test(s);
}

function validateQuery(q) {
  const s = q.trim();
  if (!s) return { ok: false, message: "Enter an email, name, fingerprint, or 16-character key ID." };
  if (s.toLowerCase().startsWith("0x")) {
    const hex = s.slice(2).replace(/\s+/g, "");
    if (/^[0-9a-fA-F]{8}$/.test(hex)) {
      return { ok: false, message: "Short (8-character) key IDs are not supported. Use the full fingerprint or 16-character key ID." };
    }
    if (!/^[0-9a-fA-F]{16}$/.test(hex) && !/^[0-9a-fA-F]{40}$/.test(hex)) {
      return { ok: false, message: "Fingerprints must be 40 hex characters; key IDs must be 16." };
    }
    return { ok: true };
  }
  if (s.includes("@")) return { ok: true };
  const hex = s.replace(/\s+/g, "");
  if (/^[0-9a-fA-F]{40}$/.test(hex) || /^[0-9a-fA-F]{16}$/.test(hex)) return { ok: true };
  if (/^[0-9a-fA-F]{8}$/.test(hex)) {
    return { ok: false, message: "Short (8-character) key IDs are not supported." };
  }
  if (isNameQuery(s)) {
    if (s.length < 2) {
      return { ok: false, message: "Name search requires at least 2 characters." };
    }
    return { ok: true, nameSearch: true };
  }
  return {
    ok: false,
    message: "Search by email, name, 40-character fingerprint, or 16-character key ID.",
  };
}

function reasonMessage(payload, query) {
  const reason = payload.reason || "";
  if (reason === "pending") {
    if (payload.fingerprint) {
      return `A key matches <code>${query}</code> but is still pending approval. <a class="text-link" href="/key?fpr=${encodeURIComponent(payload.fingerprint)}">View pending key</a>`;
    }
    return "A matching key exists but is still pending approval (not published for email search yet).";
  }
  if (reason === "invalid_query" || reason === "short_keyid") {
    return payload.error || "Unsupported search format.";
  }
  if (reason === "empty") return "";
  return "No matching approved keys found.";
}

async function runSearch(query) {
  error.classList.add("hidden");
  results.innerHTML = "";
  if (!query.trim()) return;

  const v = validateQuery(query);
  if (!v.ok) {
    results.innerHTML = `<p class="muted">${v.message}</p>`;
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Searching…";
  }
  results.innerHTML = `<p class="muted">Searching…</p>`;

  try {
    const payload = await fetchJson(`/api/v1/search?q=${encodeURIComponent(query.trim())}`);
    if (!payload.results || !payload.results.length) {
      results.innerHTML = `<p class="muted">${reasonMessage(payload, query.trim())}</p>`;
      return;
    }
    const caution =
      v.nameSearch || payload.reason === "name"
        ? `<p class="name-search-caution" role="status"><strong>Names are unverified.</strong> Match keys by verified email and confirm the full fingerprint out of band before trusting a key.</p>`
        : "";
    results.innerHTML = caution + renderKeysTable(payload.results);
  } catch (err) {
    results.innerHTML = "";
    showError(error, err.message);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Search";
    }
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const q = input.value.trim();
  history.replaceState(null, "", q ? `/?q=${encodeURIComponent(q)}` : "/");
  runSearch(q);
});

const initial = queryParam("q");
if (initial) {
  input.value = initial;
  runSearch(initial);
}
