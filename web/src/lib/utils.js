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

/**
 * Structured User ID from the API: { raw, name, email, comment }.
 * Opaque strings are display-only (no client parsing / no search links).
 * @typedef {{ raw?: string, name?: string|null, email?: string|null, comment?: string|null } | string} UidValue
 */

/** Email from a structured UID (server-parsed). Empty for opaque strings. */
export function uidEmail(uid) {
  if (uid && typeof uid === "object" && uid.email) {
    return String(uid.email).toLowerCase();
  }
  return "";
}

/** Raw UID string for display / equality. */
export function uidRaw(uid) {
  if (uid && typeof uid === "object") return String(uid.raw || "");
  if (typeof uid === "string") return uid;
  return "";
}

/**
 * Prefer structured API email; for free-text search inputs only, accept a bare address.
 * Do not parse name-prefixed UID strings on the client.
 */
export function extractEmail(uid) {
  const fromStruct = uidEmail(uid);
  if (fromStruct) return fromStruct;
  if (typeof uid === "string") {
    const s = uid.trim();
    // Bare addr-spec typed by the user (search / encrypt), not a full UID.
    if (/^[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+$/.test(s)) return s.toLowerCase();
  }
  return "";
}

/** Relative search URL for email, fingerprint, or key ID. */
export function searchUrl(query) {
  const q = String(query || "").trim();
  if (!q) return "/";
  return `/?q=${encodeURIComponent(q)}`;
}

/**
 * Render a UID. Verified emails get a normal search link; names get an
 * "unverified" link (searchable but clearly cautioned). Opaque string UIDs
 * are escaped with no links (no client-side UID parsing).
 */
export function uidWithSearchLinks(uid) {
  if (uid && typeof uid === "object") {
    const email = uid.email ? String(uid.email) : "";
    const name = uid.name ? String(uid.name).trim() : "";
    const comment = uid.comment ? String(uid.comment).trim() : "";
    const nameHtml = name
      ? `<a class="text-link unverified" href="${escapeHtml(searchUrl(name))}" title="Name is NOT verified — always confirm the email and fingerprint">${escapeHtml(name)}</a>`
      : "";
    const commentHtml = comment ? `(${escapeHtml(comment)})` : "";
    if (email) {
      const emailLink = `<a class="text-link" href="${escapeHtml(searchUrl(email))}" title="Search for this verified email">${escapeHtml(email)}</a>`;
      const prefix = [nameHtml || null, commentHtml || null].filter(Boolean).join(" ");
      if (prefix) return `${prefix} &lt;${emailLink}&gt;`;
      if (uid.raw && String(uid.raw).includes("<")) {
        return `&lt;${emailLink}&gt;`;
      }
      return emailLink;
    }
    // Name-only UID: still searchable with caution styling.
    if (nameHtml) {
      return commentHtml ? `${nameHtml} ${commentHtml}` : nameHtml;
    }
    return escapeHtml(uid.raw || "");
  }
  return escapeHtml(String(uid || ""));
}

export async function copyText(text) {
  await navigator.clipboard.writeText(String(text || ""));
}

/**
 * Copy text, then best-effort clear the clipboard after `ms` if the document
 * is still focused (cloud clipboard sync / long-lived pastes are a risk for
 * decrypted plaintext).
 * @param {string} text
 * @param {number} [ms=60000]
 * @returns {Promise<{ clear: () => void }>}
 */
export async function copyTextTransient(text, ms = 60000) {
  const value = String(text || "");
  await navigator.clipboard.writeText(value);
  let cleared = false;
  const clear = () => {
    if (cleared) return;
    cleared = true;
    if (typeof document !== "undefined" && document.hasFocus?.() === false) {
      return;
    }
    navigator.clipboard.writeText("").catch(() => {});
  };
  const timer = setTimeout(clear, ms);
  return {
    clear: () => {
      clearTimeout(timer);
      clear();
    },
  };
}
