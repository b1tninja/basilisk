import { Auth } from "../lib/auth.js";
import { escapeHtml, fetchJson, showError } from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/stats");

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

function renderStatGrid(items, stats) {
  return `<div class="stats-grid">${items
    .map(
      ({ key, label }) => `
    <div class="stat-tile">
      <div class="stat-value">${escapeHtml(String(stats[key] ?? 0))}</div>
      <div class="stat-label">${escapeHtml(label)}</div>
    </div>`
    )
    .join("")}</div>`;
}

async function loadStats() {
  const loading = document.getElementById("loading");
  const content = document.getElementById("content");
  const error = document.getElementById("error");
  try {
    const payload = await fetchJson("/pks/lookup?op=stats");
    const stats = payload.stats || {};
    content.innerHTML = `
      <div class="card">
        <p class="card-title">Keys</p>
        ${renderStatGrid(KEY_STATS, stats)}
      </div>
      <div class="card">
        <p class="card-title">Runtime counters</p>
        <p class="muted stack-subhead">Per-instance counters since last process start.</p>
        ${renderStatGrid(RUNTIME_STATS, stats)}
      </div>
      <div class="card">
        <p class="card-title">HKP endpoints</p>
        <ul class="help-list">
          <li><code>GET /pks/lookup?op=get&amp;search=…</code> — fetch key</li>
          <li><code>GET /pks/lookup?op=index&amp;search=…</code> — index (approved)</li>
          <li><code>GET /pks/lookup?op=stats</code> — this page’s data</li>
          <li><code>POST /pks/add</code> — <code>gpg --send-keys</code></li>
        </ul>
        <p class="muted mt-md">Point GnuPG at <code>${escapeHtml(window.location.origin)}</code>.</p>
      </div>`;
    loading.classList.add("hidden");
    content.classList.remove("hidden");
  } catch (err) {
    loading.classList.add("hidden");
    showError(error, err.message);
  }
}

loadStats();
