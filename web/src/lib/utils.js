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

/**
 * Human-friendly expiry: absolute UTC plus relative badge text.
 * @returns {{ absolute: string, relative: string, tone: "ok"|"warn"|"expired"|"none" }}
 */
export function describeExpiry(value) {
  if (!value) {
    return { absolute: "Does not expire", relative: "", tone: "none" };
  }
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) {
    return { absolute: String(value), relative: "", tone: "none" };
  }
  const absolute = formatDate(d);
  const ms = d.getTime() - Date.now();
  const days = Math.round(ms / 86400000);
  if (ms < 0) {
    const ago = Math.abs(days);
    return {
      absolute,
      relative: ago <= 1 ? "Expired" : `Expired ${ago} days ago`,
      tone: "expired",
    };
  }
  if (days === 0) return { absolute, relative: "Expires today", tone: "warn" };
  if (days === 1) return { absolute, relative: "Expires tomorrow", tone: "warn" };
  if (days < 30) return { absolute, relative: `Expires in ${days} days`, tone: "warn" };
  if (days < 365) {
    const months = Math.max(1, Math.round(days / 30));
    return { absolute, relative: `Expires in ~${months} mo`, tone: "ok" };
  }
  const years = Math.round(days / 365);
  return { absolute, relative: `Expires in ~${years} yr`, tone: "ok" };
}

export function extractEmail(uid) {
  const m = String(uid).match(/<([^>]+)>/);
  if (m && m[1].includes("@")) return m[1].toLowerCase();
  if (String(uid).includes("@")) return String(uid).trim().toLowerCase();
  return "";
}

/** Relative search URL for email, name, fingerprint, or key ID. */
export function searchUrl(query) {
  const q = String(query || "").trim();
  if (!q) return "/";
  return `/?q=${encodeURIComponent(q)}`;
}

/**
 * Render a UID with the email (or whole string) linked to search.
 * e.g. "Alice <a@b.com>" → Alice &lt;<a href="/?q=a@b.com">a@b.com</a>&gt;
 */
export function uidWithSearchLinks(uid) {
  const raw = String(uid || "");
  const m = raw.match(/^(.*)<([^>]+)>\s*$/);
  if (m && m[2].includes("@")) {
    const name = m[1].trim();
    const email = m[2].trim();
    const nameHtml = name
      ? `<a class="text-link" href="${escapeHtml(searchUrl(name))}" title="Search for this name">${escapeHtml(name)}</a> `
      : "";
    return `${nameHtml}&lt;<a class="text-link" href="${escapeHtml(searchUrl(email))}" title="Search for this email">${escapeHtml(email)}</a>&gt;`;
  }
  const email = extractEmail(raw);
  if (email) {
    return `<a class="text-link" href="${escapeHtml(searchUrl(email))}" title="Search for this email">${escapeHtml(raw)}</a>`;
  }
  if (raw.trim()) {
    return `<a class="text-link" href="${escapeHtml(searchUrl(raw.trim()))}" title="Search for this user ID">${escapeHtml(raw)}</a>`;
  }
  return escapeHtml(raw);
}

export async function copyText(text) {
  await navigator.clipboard.writeText(String(text || ""));
}
