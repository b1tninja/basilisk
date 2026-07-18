/**
 * Browser-local GPG-style ownertrust marks for public keys.
 * Levels: trusted | marginal | never (absent = unknown).
 * @module lib/trust
 */

const STORAGE_KEY = "basilisk.keyTrust.v1";

/** @typedef {"trusted"|"marginal"|"never"} TrustLevel */

/**
 * @typedef {{ level: TrustLevel, markedAt: string }} TrustRecord
 */

/**
 * @param {string} fingerprint
 * @returns {string}
 */
function cleanFpr(fingerprint) {
  return String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
}

/**
 * @returns {Record<string, TrustRecord>}
 */
function readMap() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return Object.create(null);
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : Object.create(null);
  } catch (_) {
    return Object.create(null);
  }
}

/**
 * @param {Record<string, TrustRecord>} map
 */
function writeMap(map) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch (_) {
    /* ignore quota / private mode */
  }
}

/**
 * @param {string} fingerprint
 * @returns {TrustRecord|null}
 */
export function getTrust(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  if (!fpr) return null;
  const rec = readMap()[fpr];
  if (!rec || typeof rec !== "object") return null;
  if (rec.level !== "trusted" && rec.level !== "marginal" && rec.level !== "never") {
    return null;
  }
  return { level: rec.level, markedAt: String(rec.markedAt || "") };
}

/**
 * @param {string} fingerprint
 * @param {TrustLevel} level
 * @returns {TrustRecord}
 */
export function setTrust(fingerprint, level) {
  if (level !== "trusted" && level !== "marginal" && level !== "never") {
    throw new Error(`Invalid trust level: ${level}`);
  }
  const fpr = cleanFpr(fingerprint);
  if (!fpr) throw new Error("Invalid fingerprint");
  const map = readMap();
  const rec = { level, markedAt: new Date().toISOString() };
  map[fpr] = rec;
  writeMap(map);
  return rec;
}

/**
 * @param {string} fingerprint
 */
export function clearTrust(fingerprint) {
  const fpr = cleanFpr(fingerprint);
  if (!fpr) return;
  const map = readMap();
  delete map[fpr];
  writeMap(map);
}

/**
 * @returns {Array<{ fingerprint: string } & TrustRecord>}
 */
export function listTrusted() {
  const map = readMap();
  /** @type {Array<{ fingerprint: string } & TrustRecord>} */
  const out = [];
  for (const [fingerprint, rec] of Object.entries(map)) {
    if (rec?.level === "trusted" || rec?.level === "marginal" || rec?.level === "never") {
      out.push({
        fingerprint,
        level: rec.level,
        markedAt: String(rec.markedAt || ""),
      });
    }
  }
  return out;
}

/**
 * Sort key: trusted first, then marginal, then unknown, then never.
 * @param {string} fingerprint
 * @returns {number}
 */
export function trustSortKey(fingerprint) {
  const level = getTrust(fingerprint)?.level;
  if (level === "trusted") return 0;
  if (level === "marginal") return 1;
  if (level === "never") return 3;
  return 2;
}

/**
 * Sort an array of items that have a fingerprint field by trust level.
 * @template {{ fingerprint?: string }} T
 * @param {T[]} items
 * @returns {T[]}
 */
export function sortByTrust(items) {
  return [...(items || [])].sort((a, b) => {
    const da = trustSortKey(a?.fingerprint || "");
    const db = trustSortKey(b?.fingerprint || "");
    if (da !== db) return da - db;
    return String(a?.fingerprint || "").localeCompare(String(b?.fingerprint || ""));
  });
}

/**
 * Compact badge HTML for a trust level (escapeHtml not applied — levels are fixed).
 * @param {string} fingerprint
 * @returns {string} empty string when unknown
 */
export function trustBadgeHtml(fingerprint) {
  const level = getTrust(fingerprint)?.level;
  if (!level) return "";
  const labels = {
    trusted: "trusted",
    marginal: "marginal",
    never: "never trust",
  };
  return `<span class="trust-badge trust-${level}" title="Local trust mark (this browser only)">${labels[level]}</span>`;
}

/**
 * Trust control markup for key / verify pages.
 * @param {string} fingerprint
 * @param {string} [idPrefix]
 * @returns {string}
 */
export function trustControlsHtml(fingerprint, idPrefix = "trust") {
  const fpr = cleanFpr(fingerprint);
  const current = getTrust(fpr)?.level || "";
  const opts = [
    ["", "Unknown"],
    ["trusted", "Trusted"],
    ["marginal", "Marginal"],
    ["never", "Never"],
  ];
  return `<div class="trust-controls" data-trust-fpr="${fpr}">
    <label class="field-label" for="${idPrefix}-level">Local trust</label>
    <select id="${idPrefix}-level" class="text-input trust-select" data-trust-select>
      ${opts
        .map(
          ([v, label]) =>
            `<option value="${v}"${current === v ? " selected" : ""}>${label}</option>`
        )
        .join("")}
    </select>
    <p class="muted fs-sm mt-xs mb-0">Stored in this browser only — like GnuPG ownertrust, not uploaded.</p>
  </div>`;
}

/**
 * Wire a trust-controls block: calls onChange after set/clear.
 * @param {ParentNode} root
 * @param {(level: TrustLevel|null) => void} [onChange]
 */
export function wireTrustControls(root, onChange) {
  const select = root.querySelector("[data-trust-select]");
  const wrap = root.querySelector("[data-trust-fpr]");
  if (!(select instanceof HTMLSelectElement) || !(wrap instanceof HTMLElement)) return;
  const fpr = wrap.getAttribute("data-trust-fpr") || "";
  select.addEventListener("change", () => {
    const val = select.value;
    if (!val) {
      clearTrust(fpr);
      onChange?.(null);
      return;
    }
    setTrust(fpr, /** @type {TrustLevel} */ (val));
    onChange?.(/** @type {TrustLevel} */ (val));
  });
}
