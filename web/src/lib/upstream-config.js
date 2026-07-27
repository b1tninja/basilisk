/**
 * Portal-advertised upstream HKP config (client-direct; no server proxy).
 */

import { Auth } from "./auth.js";
import { getPreferredKeyserver } from "./prefs.js";
import { fetchJson } from "./utils.js";

/**
 * @typedef {{ enabled: boolean, allowlist: string[], default: string }} UpstreamConfig
 */

/** @type {UpstreamConfig|undefined} */
let _cached;

const FALLBACK = Object.freeze({
  enabled: false,
  allowlist: ["keys.openpgp.org", "keys.mailvelope.com"],
  default: "keys.openpgp.org",
});

/**
 * @param {string} value
 * @returns {string|null}
 */
export function normalizeKeyserverHost(value) {
  let raw = String(value || "")
    .trim()
    .toLowerCase();
  if (!raw) return null;
  if (raw.includes("://")) raw = raw.split("://", 2)[1];
  raw = raw.split("/", 1)[0];
  raw = raw.split("?", 1)[0];
  raw = raw.split("#", 1)[0];
  if (raw.includes("@") || raw.startsWith("[")) return null;
  if (raw.includes(":")) {
    const idx = raw.lastIndexOf(":");
    const port = raw.slice(idx + 1);
    if (!/^\d+$/.test(port)) return null;
    raw = raw.slice(0, idx);
  }
  if (!raw || raw.startsWith(".") || raw.includes("..")) return null;
  const labels = raw.split(".");
  if (labels.length < 2) return null;
  if (labels.every((l) => /^\d+$/.test(l))) return null;
  for (const label of labels) {
    if (!label || label.startsWith("-") || label.endsWith("-")) return null;
    if (!/^[a-z0-9-]+$/.test(label)) return null;
  }
  return raw;
}

/**
 * @param {string} host
 * @param {string[]} allowlist
 * @returns {boolean}
 */
export function isKeyserverAllowed(host, allowlist) {
  const h = normalizeKeyserverHost(host);
  if (!h) return false;
  return (allowlist || []).map((x) => normalizeKeyserverHost(x)).includes(h);
}

/**
 * @param {boolean} [force]
 * @returns {Promise<UpstreamConfig>}
 */
export async function getUpstreamConfig(force = false) {
  if (_cached !== undefined && !force) return _cached;
  try {
    const cfg = await fetchJson("/api/v1/config");
    const up = cfg?.upstream || {};
    const allowlist = Array.isArray(up.allowlist)
      ? up.allowlist
          .map((h) => normalizeKeyserverHost(h))
          .filter(Boolean)
      : [...FALLBACK.allowlist];
    const def =
      normalizeKeyserverHost(up.default) ||
      allowlist[0] ||
      FALLBACK.default;
    _cached = {
      enabled: !!up.enabled,
      allowlist: allowlist.length ? allowlist : [...FALLBACK.allowlist],
      default: allowlist.includes(def) ? def : allowlist[0] || FALLBACK.default,
    };
  } catch (_) {
    _cached = { ...FALLBACK, allowlist: [...FALLBACK.allowlist] };
  }
  return _cached;
}

/**
 * Upstream fetch is only offered when the feature is on and the user is signed in.
 * @returns {Promise<boolean>}
 */
export async function canUseUpstream() {
  const cfg = await getUpstreamConfig();
  if (!cfg.enabled) return false;
  try {
    const user = await Auth.getUser();
    return !!(user && user.authenticated);
  } catch (_) {
    return false;
  }
}

/**
 * Resolve which upstream host to use: explicit override → localStorage pref
 * (if allowlisted) → server-advertised default.
 * @param {string} [explicit]
 * @param {UpstreamConfig} [cfg]
 * @returns {Promise<string>}
 */
export async function resolveUpstreamHost(explicit, cfg) {
  const config = cfg || (await getUpstreamConfig());
  const allow = config.allowlist || [];
  const fromArg = normalizeKeyserverHost(explicit);
  if (fromArg && isKeyserverAllowed(fromArg, allow)) return fromArg;
  const pref = normalizeKeyserverHost(getPreferredKeyserver());
  if (pref && isKeyserverAllowed(pref, allow)) return pref;
  const def = normalizeKeyserverHost(config.default) || allow[0] || FALLBACK.default;
  return def;
}

/** @internal test helper */
export function _resetUpstreamConfigCache() {
  _cached = undefined;
}
