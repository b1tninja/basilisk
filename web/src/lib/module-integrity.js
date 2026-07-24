/**
 * Module-load integrity digest for the crypto POST banner.
 *
 * Collects Subresource Integrity digests already pinned on the page (script /
 * modulepreload / importmap), binds each to its URL, and folds them into a
 * SHA-256 Merkle root. The browser has already enforced SRI on load; this root
 * is an operator-visible attestation of which pinned modules participated.
 *
 * When no SRI attributes are present (Vite dev / Node tests), falls back to
 * hashing this module’s own source bytes via ``import.meta.url``.
 */

/**
 * @typedef {{ url: string, alg: string, digest: string }} IntegrityLeaf
 * @typedef {{ root: string, leafCount: number, source: "sri" | "self" | "none", pin?: PinCheckResult }} ModuleIntegrity
 * @typedef {{
 *   ok: boolean,
 *   required: boolean,
 *   matched: boolean,
 *   fetched: number,
 *   expectedRoot: string,
 *   message: string,
 * }} PinCheckResult
 * @typedef {{
 *   version: number,
 *   algorithm: string,
 *   builtAt: string,
 *   pages: Record<string, { root: string, leafCount: number }>,
 * }} ModuleRootsPin
 */

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>}
 */
async function sha256(bytes) {
  if (globalThis.crypto?.subtle) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }
  // Node vitest fallback
  const { createHash } = await import("node:crypto");
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

/**
 * @param {string} s
 * @returns {Uint8Array}
 */
function utf8(s) {
  return new TextEncoder().encode(s);
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array}
 */
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToBase64(bytes) {
  if (typeof btoa === "function") {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  return Buffer.from(bytes).toString("base64");
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {number}
 */
function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Canonical leaf: SHA-256(url || NUL || alg || NUL || digest).
 * @param {IntegrityLeaf} leaf
 * @returns {Promise<Uint8Array>}
 */
export async function hashIntegrityLeaf(leaf) {
  const canon = `${leaf.url}\0${leaf.alg}\0${leaf.digest}`;
  return sha256(utf8(canon));
}

/**
 * Pairwise Merkle root over leaf hashes (sorted). Unpaired nodes promote.
 * @param {Uint8Array[]} leafHashes
 * @returns {Promise<string|null>} lowercase hex root, or null if empty
 */
export async function merkleRootHex(leafHashes) {
  if (!leafHashes.length) return null;
  let level = leafHashes.slice().sort(compareBytes);
  while (level.length > 1) {
    /** @type {Uint8Array[]} */
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) {
        next.push(level[i]);
      } else {
        next.push(await sha256(concatBytes(level[i], level[i + 1])));
      }
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

/**
 * Parse `sha384-…` tokens from an integrity attribute value.
 * @param {string} integrityAttr
 * @param {string} url
 * @returns {IntegrityLeaf[]}
 */
export function parseIntegrityAttr(integrityAttr, url = "") {
  /** @type {IntegrityLeaf[]} */
  const out = [];
  for (const token of String(integrityAttr || "").trim().split(/\s+/)) {
    const m = token.match(/^(sha256|sha384|sha512)-([A-Za-z0-9+/]+=*)$/);
    if (m) out.push({ url: String(url || ""), alg: m[1], digest: m[2] });
  }
  return out;
}

/**
 * Collect SRI leaves from the document (scripts, preloads, import map entries).
 * @param {Document} [doc]
 * @returns {Promise<IntegrityLeaf[]>}
 */
export async function collectSriLeaves(doc = globalThis.document) {
  /** @type {IntegrityLeaf[]} */
  const leaves = [];
  if (!doc?.querySelectorAll) return leaves;

  doc.querySelectorAll("[integrity]").forEach((el) => {
    const integrity = el.getAttribute("integrity") || "";
    const url =
      el.getAttribute("src") ||
      el.getAttribute("href") ||
      (el instanceof HTMLScriptElement && el.type === "importmap" ? "importmap" : "") ||
      "";
    leaves.push(...parseIntegrityAttr(integrity, url));
  });

  // Import map body may list per-module integrity digests.
  const mapEl = doc.querySelector('script[type="importmap"]');
  if (mapEl) {
    try {
      let raw = mapEl.textContent || "";
      if (!raw && mapEl.getAttribute("src")) {
        const src = mapEl.getAttribute("src") || "";
        const res = await fetch(src, {
          cache: "force-cache",
          credentials: "same-origin",
        });
        if (res.ok) raw = await res.text();
      }
      if (raw.trim()) {
        const map = JSON.parse(raw);
        const integrity = map?.integrity;
        if (integrity && typeof integrity === "object") {
          for (const [url, token] of Object.entries(integrity)) {
            leaves.push(...parseIntegrityAttr(String(token), String(url)));
          }
        }
      }
    } catch (_) {
      /* ignore malformed / unreachable import maps */
    }
  }

  // De-dupe by url+alg+digest
  const seen = new Set();
  return leaves.filter((l) => {
    const k = `${l.url}|${l.alg}|${l.digest}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Hash the bytes at ``url`` (same-origin module chunk).
 * @param {string} url
 * @returns {Promise<IntegrityLeaf|null>}
 */
async function leafFromModuleFetch(url) {
  try {
    const res = await fetch(url, {
      cache: "force-cache",
      credentials: "same-origin",
    });
    if (!res.ok) return null;
    const buf = new Uint8Array(await res.arrayBuffer());
    const dig = await sha256(buf);
    return {
      url,
      alg: "sha256",
      digest: bytesToBase64(dig),
    };
  } catch (_) {
    return null;
  }
}

/**
 * Compute a Merkle root over loaded / pinned module integrity digests.
 * @param {{ selfModuleUrl?: string, document?: Document|null }} [opts]
 * @returns {Promise<ModuleIntegrity>}
 */
export async function computeLoadedModulesRoot(opts = {}) {
  const doc = opts.document === null ? null : opts.document ?? globalThis.document;
  const selfUrl = opts.selfModuleUrl || import.meta.url;

  let leaves = doc ? await collectSriLeaves(doc) : [];
  let source = /** @type {ModuleIntegrity["source"]} */ ("sri");

  if (!leaves.length) {
    source = "self";
    const selfLeaf = await leafFromModuleFetch(selfUrl);
    if (selfLeaf) leaves = [selfLeaf];
  }

  if (!leaves.length) {
    return { root: "", leafCount: 0, source: "none" };
  }

  const { root, leafCount } = await rootFromLeaves(leaves);
  return { root, leafCount, source };
}

/**
 * Short hex prefix for UI banners.
 * @param {string} root
 * @param {number} [n]
 * @returns {string}
 */
export function shortModuleRoot(root, n = 16) {
  const hex = String(root || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
  return hex.slice(0, n);
}

/**
 * Fold leaves into a Merkle root (shared by browser + build pin writer).
 * @param {IntegrityLeaf[]} leaves
 * @returns {Promise<{ root: string, leafCount: number }>}
 */
export async function rootFromLeaves(leaves) {
  if (!leaves.length) return { root: "", leafCount: 0 };
  const hashes = [];
  for (const leaf of leaves) {
    hashes.push(await hashIntegrityLeaf(leaf));
  }
  return { root: (await merkleRootHex(hashes)) || "", leafCount: leaves.length };
}

/**
 * Collect SRI leaves from raw HTML + optional import-map JSON text.
 * Mirrors browser ``collectSriLeaves`` for build-time pinning.
 * @param {string} html
 * @param {(src: string) => string|null|Promise<string|null>} [loadImportMap]
 * @returns {Promise<IntegrityLeaf[]>}
 */
export async function collectSriLeavesFromHtml(html, loadImportMap) {
  /** @type {IntegrityLeaf[]} */
  const leaves = [];
  const tagRe =
    /<(script|link)\b([^>]*?)\bintegrity\s*=\s*["']([^"']+)["']([^>]*)>/gi;
  let m;
  while ((m = tagRe.exec(html))) {
    const before = m[2] || "";
    const integrity = m[3] || "";
    const after = m[4] || "";
    const attrs = `${before} ${after}`;
    const src =
      /(?:src|href)\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1] || "";
    leaves.push(...parseIntegrityAttr(integrity, src));
  }

  const mapSrc = /<script\b[^>]*type\s*=\s*["']importmap["'][^>]*src\s*=\s*["']([^"']+)["'][^>]*>/i.exec(
    html
  )?.[1];
  const inlineMap = /<script\b[^>]*type\s*=\s*["']importmap["'][^>]*>(\{[\s\S]*?\})<\/script>/i.exec(
    html
  )?.[1];

  let mapRaw = inlineMap || "";
  if (!mapRaw && mapSrc && loadImportMap) {
    mapRaw = (await loadImportMap(mapSrc)) || "";
  }
  if (mapRaw.trim()) {
    try {
      const map = JSON.parse(mapRaw);
      const integrity = map?.integrity;
      if (integrity && typeof integrity === "object") {
        for (const [url, token] of Object.entries(integrity)) {
          leaves.push(...parseIntegrityAttr(String(token), String(url)));
        }
      }
    } catch (_) {
      /* ignore */
    }
  }

  const seen = new Set();
  return leaves.filter((l) => {
    const k = `${l.url}|${l.alg}|${l.digest}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Map location pathname → pin page key (e.g. /encrypt → encrypt.html).
 * @param {string} [pathname]
 * @param {string} [explicitPage]
 * @returns {string}
 */
export function pageKeyFromPath(pathname = "", explicitPage = "") {
  if (explicitPage) return explicitPage.replace(/^\//, "");
  let p = String(pathname || "/").split("?")[0].split("#")[0];
  if (p.endsWith("/")) p = p.slice(0, -1) || "/";
  if (p === "/" || p === "/index" || p === "/search") return "index.html";
  const base = p.replace(/^\//, "");
  if (base.endsWith(".html")) return base;
  return `${base}.html`;
}

/**
 * Resolve pin URLs from document meta + optional Vite-injected mirrors.
 * @param {Document|null|undefined} doc
 * @param {string[]} [extraUrls]
 * @returns {string[]}
 */
export function resolveIntegrityPinUrls(doc = globalThis.document, extraUrls = []) {
  /** @type {string[]} */
  const urls = [];
  const meta = doc?.querySelector?.('meta[name="basilisk-integrity-pins"]');
  const content = meta?.getAttribute?.("content") || "";
  for (const part of content.trim().split(/\s+/)) {
    if (part) urls.push(part);
  }
  for (const u of extraUrls) {
    if (u && !urls.includes(u)) urls.push(u);
  }
  // Default same-origin pin when meta omitted but callers pass requireDefault.
  return urls;
}

/**
 * Fetch and parse module-roots pin documents.
 * @param {string[]} urls
 * @returns {Promise<{ url: string, pin: ModuleRootsPin|null, error: string }[]>}
 */
export async function fetchIntegrityPins(urls) {
  const out = [];
  for (const url of urls) {
    try {
      const abs =
        typeof url === "string" && url.startsWith("http")
          ? url
          : new URL(url, globalThis.location?.href || "http://localhost/").href;
      const res = await fetch(abs, {
        cache: "no-store",
        credentials: "omit",
      });
      if (!res.ok) {
        out.push({ url, pin: null, error: `HTTP ${res.status}` });
        continue;
      }
      const pin = /** @type {ModuleRootsPin} */ (await res.json());
      if (!pin?.pages || typeof pin.pages !== "object") {
        out.push({ url, pin: null, error: "invalid pin document" });
        continue;
      }
      out.push({ url, pin, error: "" });
    } catch (err) {
      out.push({
        url,
        pin: null,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return out;
}

/**
 * Compare the live Merkle root to independently fetched pin document(s).
 * All successful pin fetches must agree with ``computedRoot`` (and each other).
 *
 * @param {string} computedRoot
 * @param {object} [opts]
 * @param {string} [opts.pageKey]
 * @param {Document|null} [opts.document]
 * @param {string[]} [opts.pinUrls]
 * @param {boolean} [opts.requirePins]  when true, zero successful fetches ⇒ fail
 * @returns {Promise<PinCheckResult>}
 */
export async function verifyModuleRootAgainstPins(computedRoot, opts = {}) {
  const doc = opts.document === undefined ? globalThis.document : opts.document;
  const explicit =
    doc?.querySelector?.('meta[name="basilisk-integrity-page"]')?.getAttribute(
      "content"
    ) || "";
  const pageKey = opts.pageKey || pageKeyFromPath(globalThis.location?.pathname || "", explicit);
  const pinUrls =
    opts.pinUrls ||
    resolveIntegrityPinUrls(doc, []);
  const required =
    opts.requirePins === true ||
    pinUrls.length > 0 ||
    !!doc?.querySelector?.('meta[name="basilisk-integrity-pins"]');

  if (!pinUrls.length) {
    return {
      ok: true,
      required: false,
      matched: false,
      fetched: 0,
      expectedRoot: "",
      message: "No integrity pins configured (dev / unsigned build).",
    };
  }

  if (!computedRoot) {
    return {
      ok: false,
      required,
      matched: false,
      fetched: 0,
      expectedRoot: "",
      message: "Computed module Merkle root is empty — cannot verify pins.",
    };
  }

  const results = await fetchIntegrityPins(pinUrls);
  const okFetches = results.filter((r) => r.pin);
  if (!okFetches.length) {
    return {
      ok: !required,
      required,
      matched: false,
      fetched: 0,
      expectedRoot: "",
      message: required
        ? `Integrity pin fetch failed (${results.map((r) => r.error || "error").join("; ")}). Refusing to enable crypto.`
        : "Integrity pins unreachable; continuing without pin check.",
    };
  }

  /** @type {string[]} */
  const expectedRoots = [];
  for (const { pin } of okFetches) {
    const page = pin?.pages?.[pageKey];
    if (!page?.root) {
      return {
        ok: false,
        required,
        matched: false,
        fetched: okFetches.length,
        expectedRoot: "",
        message: `Integrity pin missing page entry for ${pageKey}.`,
      };
    }
    expectedRoots.push(String(page.root).toLowerCase());
  }

  const unique = [...new Set(expectedRoots)];
  if (unique.length !== 1) {
    return {
      ok: false,
      required,
      matched: false,
      fetched: okFetches.length,
      expectedRoot: "",
      message: `Integrity pin mirrors disagree (${unique.map((r) => r.slice(0, 16)).join(" vs ")}). Possible CDN split-brain.`,
    };
  }

  const expectedRoot = unique[0];
  if (expectedRoot !== computedRoot.toLowerCase()) {
    return {
      ok: false,
      required,
      matched: false,
      fetched: okFetches.length,
      expectedRoot,
      message: `Module Merkle root mismatch (live ${computedRoot.slice(0, 16)}… ≠ pin ${expectedRoot.slice(0, 16)}…). Possible CDN tampering or cache skew.`,
    };
  }

  return {
    ok: true,
    required,
    matched: true,
    fetched: okFetches.length,
    expectedRoot,
    message: `Integrity pin matched (${okFetches.length} source${okFetches.length === 1 ? "" : "s"}).`,
  };
}
