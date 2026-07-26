/**
 * Soft FIDO MDS lookup for vault passkey PRF enrollment.
 *
 * Fetches a same-origin cached MDS3 JWT from /api/v1/mds/blob (CSP connect-src
 * 'self'). Does not latch crypto module ERROR — enroll always proceeds.
 *
 * "verified"  = AAGUID found in MDS and no adverse statusReports
 * "unverified"= zero/missing AAGUID, not in MDS, or adverse status
 * "unavailable" = MDS blob could not be loaded
 */

import { ZERO_AAGUID } from "./attestation.js";

const MDS_CACHE_KEY = "basilisk.mdsBlob.v1";
const MDS_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** Status codes that mean do not treat the authenticator as trustworthy. */
const ADVERSE_STATUS = new Set([
  "USER_VERIFICATION_BYPASS",
  "ATTESTATION_KEY_COMPROMISE",
  "USER_KEY_REMOTE_COMPROMISE",
  "USER_KEY_PHYSICAL_COMPROMISE",
  "REVOKED",
]);

/**
 * @typedef {"verified"|"unverified"|"unavailable"} MdsStatus
 *
 * @typedef {object} MdsLookupResult
 * @property {MdsStatus} status
 * @property {string} aaguid
 * @property {string} [description]  Human label from MDS (for device-label prefill)
 * @property {string} [detail]  Short reason for UI tooltips
 */

/**
 * @param {string|null|undefined} aaguid
 * @returns {Promise<MdsLookupResult>}
 */
export async function lookupAaguidInMds(aaguid) {
  const id = normalizeAaguid(aaguid);
  if (!id || id === ZERO_AAGUID) {
    return {
      status: "unverified",
      aaguid: id || ZERO_AAGUID,
      detail: "No AAGUID in attestation (common for synced platform passkeys)",
    };
  }

  let payload;
  try {
    payload = await loadMdsPayload();
  } catch (err) {
    return {
      status: "unavailable",
      aaguid: id,
      detail: err?.message || "MDS blob unavailable",
    };
  }

  const entry = findEntry(payload, id);
  if (!entry) {
    return {
      status: "unverified",
      aaguid: id,
      detail: "AAGUID not present in FIDO MDS",
    };
  }

  const adverse = latestAdverseStatus(entry.statusReports || []);
  const description =
    String(entry.metadataStatement?.description || "").trim() ||
    String(entry.metadataStatement?.alternativeDescriptions?.en || "").trim() ||
    "";

  if (adverse) {
    return {
      status: "unverified",
      aaguid: id,
      description: description || undefined,
      detail: `MDS status: ${adverse}`,
    };
  }

  return {
    status: "verified",
    aaguid: id,
    description: description || undefined,
    detail: description
      ? `Listed in FIDO MDS as ${description}`
      : "Listed in FIDO MDS",
  };
}

/**
 * @param {string|null|undefined} aaguid
 * @returns {string}
 */
export function normalizeAaguid(aaguid) {
  const s = String(aaguid || "")
    .trim()
    .toLowerCase()
    .replace(/[^0-9a-f]/g, "");
  if (s.length !== 32) return String(aaguid || "").trim().toLowerCase();
  return (
    `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-` +
    `${s.slice(16, 20)}-${s.slice(20)}`
  );
}

/**
 * @returns {Promise<object>}
 */
async function loadMdsPayload() {
  const cached = readLocalCache();
  if (cached) return cached;

  const res = await fetch("/api/v1/mds/blob", {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/jwt, text/plain, */*" },
  });
  if (!res.ok) {
    throw new Error(`MDS proxy HTTP ${res.status}`);
  }
  const jwt = (await res.text()).trim();
  const payload = decodeJwtPayload(jwt);
  writeLocalCache(payload);
  return payload;
}

/** @returns {object|null} */
function readLocalCache() {
  try {
    const raw = localStorage.getItem(MDS_CACHE_KEY);
    if (!raw) return null;
    const row = JSON.parse(raw);
    if (!row?.payload || !row?.fetchedAt) return null;
    if (Date.now() - Number(row.fetchedAt) > MDS_CACHE_TTL_MS) return null;
    return row.payload;
  } catch {
    return null;
  }
}

/** @param {object} payload */
function writeLocalCache(payload) {
  try {
    localStorage.setItem(
      MDS_CACHE_KEY,
      JSON.stringify({ fetchedAt: Date.now(), payload })
    );
  } catch {
    /* quota / private mode */
  }
}

/**
 * Decode JWT payload without verifying the JWS (server caches the signed blob;
 * client uses it for soft UX badges / labels only).
 * @param {string} jwt
 * @returns {object}
 */
export function decodeJwtPayload(jwt) {
  const parts = String(jwt || "").split(".");
  if (parts.length < 2) throw new Error("MDS blob is not a JWT");
  const json = base64UrlToUtf8(parts[1]);
  const payload = JSON.parse(json);
  if (!payload || typeof payload !== "object") {
    throw new Error("MDS JWT payload invalid");
  }
  return payload;
}

/** @param {string} b64url */
function base64UrlToUtf8(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/**
 * @param {object} payload
 * @param {string} aaguid
 */
function findEntry(payload, aaguid) {
  const want = normalizeAaguid(aaguid);
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  for (const e of entries) {
    if (!e) continue;
    const id = normalizeAaguid(e.aaguid || e.metadataStatement?.aaguid);
    if (id && id === want) return e;
  }
  return null;
}

/**
 * @param {{ status?: string, effectiveDate?: string }[]} reports
 * @returns {string|null}
 */
function latestAdverseStatus(reports) {
  if (!Array.isArray(reports) || !reports.length) return null;
  const sorted = [...reports].sort((a, b) =>
    String(b.effectiveDate || "").localeCompare(String(a.effectiveDate || ""))
  );
  for (const r of sorted) {
    const st = String(r.status || "");
    if (ADVERSE_STATUS.has(st)) return st;
  }
  return null;
}

/**
 * Badge HTML fragment (caller escapes context as needed — values are fixed enums).
 * @param {MdsStatus|string|undefined|null} status
 * @param {string} [title]
 * @returns {string}
 */
export function mdsStatusBadgeHtml(status, title = "") {
  const s = status === "verified" || status === "unverified" || status === "unavailable"
    ? status
    : "unverified";
  const label =
    s === "verified"
      ? "MDS verified"
      : s === "unavailable"
        ? "MDS unavailable"
        : "MDS unverified";
  const cls =
    s === "verified"
      ? "badge approved"
      : s === "unavailable"
        ? "badge pending"
        : "badge pending";
  const tip = title ? ` title="${escapeAttr(title)}"` : "";
  return `<span class="${cls} mds-badge"${tip}>${label}</span>`;
}

/** @param {string} s */
function escapeAttr(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}
