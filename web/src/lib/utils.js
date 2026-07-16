export function escapeHtml(text) {
  const d = document.createElement("div");
  d.textContent = text == null ? "" : String(text);
  return d.innerHTML;
}

export function queryParam(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

export function showError(el, msg) {
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
}

export async function fetchJson(url, opts) {
  const r = await fetch(url, { credentials: "include", ...opts });
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    let msg = txt;
    try {
      msg = JSON.parse(txt).error || txt;
    } catch (_) {
      /* keep txt */
    }
    throw Object.assign(new Error(msg || `Request failed (${r.status})`), { status: r.status });
  }
  return r.json();
}

export async function fetchText(url) {
  const r = await fetch(url, { credentials: "include" });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return r.text();
}

export function formatFingerprint(fpr) {
  const clean = String(fpr || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return clean.replace(/(.{4})(?=.)/g, "$1 ");
}

export function formatDate(value) {
  if (!value) return "Does not expire";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export function extractEmail(uid) {
  const m = String(uid).match(/<([^>]+)>/);
  if (m && m[1].includes("@")) return m[1].toLowerCase();
  if (String(uid).includes("@")) return String(uid).trim().toLowerCase();
  return "";
}
