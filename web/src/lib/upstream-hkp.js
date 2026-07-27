/**
 * Browser HKP client — same `/pks/lookup` route for This site (page origin)
 * and allowlisted upstream hosts.
 */

import { readKey } from "openpgp";
import {
  getUpstreamConfig,
  isKeyserverAllowed,
  normalizeKeyserverHost,
} from "./upstream-config.js";

const MAX_BODY_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 8000;

/**
 * Page origin for “This site” HKP (protocol + host + port). Never hardcode hosts.
 * @param {{ origin?: string }|null|undefined} [loc]
 * @returns {string|null}
 */
export function pageKeyserverOrigin(loc = typeof location !== "undefined" ? location : null) {
  try {
    const o = loc?.origin;
    if (!o || o === "null") return null;
    return o;
  } catch {
    return null;
  }
}

/**
 * Build standard HKP lookup URL (path + query match well-known keyservers).
 *
 * @param {string} base  page origin (`https://keys.example.com`) or hostname (`keys.openpgp.org`)
 * @param {string} search
 * @param {{ op?: "get"|"index" }} [opts]
 * @returns {string}
 */
export function hkpLookupUrl(base, search, opts = {}) {
  const op = opts.op === "index" ? "index" : "get";
  const q = new URLSearchParams({
    op,
    options: "mr",
    search: String(search || "").trim(),
  });
  const raw = String(base || "").trim();
  if (/^https?:\/\//i.test(raw)) {
    return new URL(`/pks/lookup?${q}`, raw).href;
  }
  const h = normalizeKeyserverHost(raw);
  if (!h) throw new Error("Invalid keyserver host");
  return `https://${h}/pks/lookup?${q}`;
}

/**
 * @param {string} url
 * @param {{ signal?: AbortSignal, credentials?: RequestCredentials, mode?: RequestMode }} [opts]
 * @returns {Promise<string|null>}
 */
async function fetchLookupBody(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  const onAbort = () => ctrl.abort();
  if (opts.signal) {
    if (opts.signal.aborted) ctrl.abort();
    else opts.signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: ctrl.signal,
      credentials: opts.credentials ?? "omit",
      mode: opts.mode ?? "cors",
      redirect: "follow",
    });
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`Keyserver HTTP ${res.status}`);
    }
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_BODY_BYTES) {
      throw new Error("Keyserver response too large");
    }
    return new TextDecoder().decode(buf);
  } catch (err) {
    if (err?.name === "AbortError") {
      throw new Error("Keyserver timeout");
    }
    throw err;
  } finally {
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
  }
}

/**
 * HKP get against This site (page origin) — same route as upstream.
 * @param {string} search
 * @param {{ signal?: AbortSignal, origin?: string|null }} [opts]
 * @returns {Promise<string|null>} armored or null
 */
export async function thisSiteLookupGet(search, opts = {}) {
  const origin = opts.origin ?? pageKeyserverOrigin();
  if (!origin) throw new Error("No page origin for This site keyserver");
  const needle = String(search || "").trim();
  if (!needle) return null;
  const url = hkpLookupUrl(origin, needle, { op: "get" });
  const text = await fetchLookupBody(url, {
    signal: opts.signal,
    credentials: "same-origin",
    mode: "same-origin",
  });
  if (!text || !text.includes("BEGIN PGP")) return null;
  return text;
}

/**
 * @param {string} host
 * @param {string} search
 * @param {{ allowlist?: string[], signal?: AbortSignal }} [opts]
 * @returns {Promise<string|null>} armored key or null if not found
 */
export async function upstreamLookupGet(host, search, opts = {}) {
  const cfg = await getUpstreamConfig();
  const allowlist = opts.allowlist || cfg.allowlist;
  const h = normalizeKeyserverHost(host);
  if (!h || !isKeyserverAllowed(h, allowlist)) {
    throw new Error("Keyserver not on allowlist");
  }
  const needle = String(search || "").trim();
  if (!needle) return null;

  const url = hkpLookupUrl(h, needle, { op: "get" });
  const resText = await (async () => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const onAbort = () => ctrl.abort();
    if (opts.signal) {
      if (opts.signal.aborted) ctrl.abort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }
    try {
      const res = await fetch(url, {
        method: "GET",
        signal: ctrl.signal,
        credentials: "omit",
        mode: "cors",
        redirect: "follow",
      });
      if (res.status === 404) return null;
      if (!res.ok) {
        throw new Error(`Upstream keyserver HTTP ${res.status}`);
      }
      const finalHost = normalizeKeyserverHost(new URL(res.url).hostname);
      if (!finalHost || !isKeyserverAllowed(finalHost, allowlist)) {
        throw new Error("Upstream redirect left allowlist");
      }
      const buf = await res.arrayBuffer();
      if (buf.byteLength > MAX_BODY_BYTES) {
        throw new Error("Upstream key too large");
      }
      return new TextDecoder().decode(buf);
    } catch (err) {
      if (err?.name === "AbortError") {
        throw new Error("Upstream keyserver timeout");
      }
      throw err;
    } finally {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
    }
  })();

  if (!resText || !resText.includes("BEGIN PGP")) return null;
  return resText;
}

/**
 * Fetch + parse a public key from an allowlisted upstream.
 * @param {string} host
 * @param {string} search  email, 0x fpr, or key id
 * @param {{ allowlist?: string[] }} [opts]
 * @returns {Promise<{
 *   armored: string,
 *   fingerprint: string,
 *   keyId: string,
 *   uids: string[],
 *   email: string,
 *   name: string,
 *   host: string,
 * }|null>}
 */
export async function upstreamFetchKey(host, search, opts = {}) {
  const armored = await upstreamLookupGet(host, search, opts);
  if (!armored) return null;
  const key = await readKey({ armoredKey: armored });
  const fingerprint = String(key.getFingerprint() || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (fingerprint.length < 40) return null;
  const keyId = String(key.getKeyID()?.toHex?.() || fingerprint.slice(-16))
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  /** @type {string[]} */
  const uids = [];
  let email = "";
  let name = "";
  try {
    const userIds = key.getUserIDs?.() || [];
    for (const uid of userIds) {
      const s = String(uid || "").trim();
      if (!s) continue;
      uids.push(s);
      if (!email) {
        const m = s.match(/<([^>]+@[^>]+)>/);
        if (m) {
          email = m[1];
          name = s.slice(0, m.index).trim();
        } else if (s.includes("@")) {
          email = s;
        }
      }
    }
  } catch (_) {
    /* ignore */
  }
  return {
    armored: key.armor(),
    fingerprint,
    keyId: keyId || fingerprint.slice(-16),
    uids,
    email,
    name,
    host: normalizeKeyserverHost(host) || String(host),
  };
}
