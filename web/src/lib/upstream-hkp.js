/**
 * Browser-direct HKP client for allowlisted verifying keyservers.
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
 * @param {string} host
 * @param {string} search
 * @returns {string}
 */
export function hkpLookupUrl(host, search) {
  const h = normalizeKeyserverHost(host);
  if (!h) throw new Error("Invalid keyserver host");
  const q = new URLSearchParams({
    op: "get",
    options: "mr",
    search: String(search || "").trim(),
  });
  return `https://${h}/pks/lookup?${q}`;
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

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  const onAbort = () => ctrl.abort();
  if (opts.signal) {
    if (opts.signal.aborted) ctrl.abort();
    else opts.signal.addEventListener("abort", onAbort, { once: true });
  }
  try {
    const res = await fetch(hkpLookupUrl(h, needle), {
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
    // Refuse redirects that left the allowlist (fetch follows; check final URL).
    const finalHost = normalizeKeyserverHost(new URL(res.url).hostname);
    if (!finalHost || !isKeyserverAllowed(finalHost, allowlist)) {
      throw new Error("Upstream redirect left allowlist");
    }
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_BODY_BYTES) {
      throw new Error("Upstream key too large");
    }
    const text = new TextDecoder().decode(buf);
    if (!text.includes("BEGIN PGP")) return null;
    return text;
  } catch (err) {
    if (err?.name === "AbortError") {
      throw new Error("Upstream keyserver timeout");
    }
    throw err;
  } finally {
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
  }
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
