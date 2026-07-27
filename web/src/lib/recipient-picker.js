/**
 * Shared recipient loading + lightweight picker UI for Encrypt and Toolkit.
 * Identities are never serialized into toolkit recipes — only bound at run time.
 *
 * Resolve order: IndexedDB pubkey cache → This site HKP (/pks/lookup) →
 * optional explicit allowlisted upstream (never silent preferred fallback).
 */

import { readKey } from "openpgp";
import { keyHitHtml, keyPillExtrasHtml } from "./key-hit.js";
import { supportsSeipdV2 } from "./pgp/capabilities.js";
import { normalizeSearchQuery } from "./pgp/verify-fpr.js";
import {
  cacheGet,
  cachePut,
  cacheRecordToSearchHit,
  cacheSearch,
  cacheTouch,
  isPubkeyCacheStale,
} from "./pubkey-cache.js";
import {
  getTrust,
  listTrusted,
  sortByTrustAndOrigin,
  trustBadgeHtml,
} from "./trust.js";
import {
  toolkitKeyserverSelectHtml,
  readKeyserverSelectValue,
} from "./keyserver-select.js";
import {
  canUseUpstream,
  getUpstreamConfig,
  isKeyserverAllowed,
  normalizeKeyserverHost,
} from "./upstream-config.js";
import { hkpLookupUrl, pageKeyserverOrigin, upstreamFetchKey } from "./upstream-hkp.js";
import {
  escapeHtml,
  fetchJson,
  fetchText,
  formatFingerprint,
  uidEmail,
} from "./utils.js";

/**
 * Explicit upstream host only — empty/undefined means This site (no preferred fallback).
 * @param {string|undefined|null} keyserver
 * @returns {string}
 */
function explicitUpstreamHost(keyserver) {
  return normalizeKeyserverHost(keyserver) || "";
}

/**
 * Same-origin HKP get URL (wire-compatible with well-known keyservers).
 * @param {string} search
 * @returns {string}
 */
function thisSiteLookupGetUrl(search) {
  const origin = pageKeyserverOrigin();
  if (origin) return hkpLookupUrl(origin, search, { op: "get" });
  const q = new URLSearchParams({
    op: "get",
    options: "mr",
    search: String(search || "").trim(),
  });
  return `/pks/lookup?${q}`;
}

const ENCRYPT_FLAG = 0x04 | 0x08;

/**
 * @typedef {{
 *   fingerprint: string,
 *   keyId: string,
 *   label: string,
 *   email: string,
 *   userLabel: string,
 *   keyExpiration: string|null,
 *   approvalState: string,
 *   revoked: boolean,
 *   valid: boolean,
 *   error: string,
 *   pgpKey: import("openpgp").Key | null,
 *   modernCapable: boolean,
 *   armoredKey: string,
 *   origin?: string,
 *   sourceKeyserver?: string,
 * }} Recipient
 */

function uidLabel(uids) {
  const list = uids || [];
  if (!list.length) return "";
  const uid = list[0];
  if (uid && typeof uid === "object") {
    const email = uid.email || "";
    const name = (uid.name || "").trim();
    if (name && email) return `${name} <${email}>`;
    return email || uid.raw || "";
  }
  return typeof uid === "string" ? uid : "";
}

function hasEncryptCapability(pgpKey) {
  try {
    const keys = [pgpKey, ...(pgpKey.subkeys || []).map((s) => s)];
    for (const k of keys) {
      const pkt = k.keyPacket || k;
      if (pkt && pkt.flags != null && pkt.flags & ENCRYPT_FLAG) return true;
    }
  } catch (_) {
    /* fall through */
  }
  return false;
}

/**
 * @param {import("openpgp").Key} pgpKey
 * @param {object} meta
 * @param {{ origin?: string, sourceKeyserver?: string }} [prov]
 * @returns {Promise<Recipient>}
 */
async function buildRecipient(pgpKey, meta, prov = {}) {
  const clean = String(meta.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const uids = meta.approved_uids || meta.pending_uids || meta.uids || [];
  const label = uidLabel(uids) || formatFingerprint(clean);
  const email = uidEmail(uids[0]) || meta.email || "";
  const origin = prov.origin || meta.origin || "basilisk";
  const sourceKeyserver = prov.sourceKeyserver || meta.source_keyserver || "";
  const approvalState = meta.approval_state || meta.approvalState || "";
  const revoked = !!meta.revoked;
  let valid = true;
  let err = "";
  if (revoked) {
    valid = false;
    err = "Key is revoked";
  } else if (origin === "basilisk" && approvalState && approvalState !== "approved") {
    valid = false;
    err = `Key is ${approvalState}`;
  } else if (!hasEncryptCapability(pgpKey)) {
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  if (valid) {
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  const modernCapable = valid ? await supportsSeipdV2(pgpKey) : false;
  return {
    fingerprint: clean,
    keyId: meta.key_id || meta.keyId || clean.slice(-16),
    label,
    email,
    userLabel: String(meta.label || meta.userLabel || "").trim(),
    keyExpiration: meta.key_expiration || meta.keyExpiration || null,
    approvalState,
    revoked,
    valid,
    error: err,
    pgpKey: valid ? pgpKey : null,
    modernCapable,
    armoredKey: pgpKey.armor(),
    origin,
    sourceKeyserver,
  };
}

/**
 * @param {Recipient} recipient
 * @param {string} armored
 */
async function putRecipientInCache(recipient, armored) {
  const origin =
    recipient.origin === "upstream" || recipient.origin === "import"
      ? recipient.origin
      : "basilisk";
  await cachePut({
    fingerprint: recipient.fingerprint,
    armored,
    uids: recipient.label ? [recipient.label] : [],
    email: recipient.email,
    name: "",
    origin,
    sourceKeyserver: recipient.sourceKeyserver || undefined,
    approvalState: recipient.approvalState || undefined,
    revoked: recipient.revoked,
    keyId: recipient.keyId,
    keyExpiration: recipient.keyExpiration || undefined,
    userLabel: recipient.userLabel || undefined,
  });
}

/**
 * Soft-revalidate a cache entry from Basilisk (fire-and-forget).
 * @param {string} fingerprint
 */
function revalidateBasiliskInBackground(fingerprint) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  void (async () => {
    try {
      const [meta, armored] = await Promise.all([
        fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`),
        fetchText(`/pks/lookup?op=get&search=${encodeURIComponent(`0x${clean}`)}`),
      ]);
      if (!String(armored).includes("BEGIN PGP")) return;
      const pgpKey = await readKey({ armoredKey: armored });
      const recipient = await buildRecipient(pgpKey, { ...meta, fingerprint: clean }, {
        origin: "basilisk",
      });
      await putRecipientInCache(recipient, armored);
    } catch (_) {
      /* ignore background failures */
    }
  })();
}

/**
 * @param {string} fingerprint
 * @param {{ forceRefresh?: boolean, keyserver?: string, allowUpstream?: boolean }} [opts]
 * @returns {Promise<Recipient>}
 */
export async function loadRecipientKey(fingerprint, opts = {}) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (clean.length < 16) {
    throw new Error("Invalid fingerprint");
  }

  if (!opts.forceRefresh) {
    const cached = await cacheGet(clean);
    if (cached?.armored) {
      await cacheTouch(clean);
      try {
        const pgpKey = await readKey({ armoredKey: cached.armored });
        const recipient = await buildRecipient(
          pgpKey,
          {
            fingerprint: clean,
            key_id: cached.keyId,
            approval_state: cached.approvalState || "",
            revoked: cached.revoked,
            key_expiration: cached.keyExpiration,
            label: cached.userLabel,
            approved_uids: (cached.uids || []).map((raw) => {
              const s = String(raw);
              const m = s.match(/<([^>]+)>/);
              return {
                raw: s,
                email: m ? m[1] : s.includes("@") ? s : cached.email || "",
                name: m ? s.slice(0, m.index).trim() : cached.name || "",
              };
            }),
            email: cached.email,
            origin: cached.origin,
            source_keyserver: cached.sourceKeyserver,
          },
          { origin: cached.origin, sourceKeyserver: cached.sourceKeyserver }
        );
        if (isPubkeyCacheStale(cached) && cached.origin === "basilisk") {
          revalidateBasiliskInBackground(clean);
        }
        return recipient;
      } catch (_) {
        /* fall through to network */
      }
    }
  }

  try {
    const [meta, armored] = await Promise.all([
      fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`),
      fetchText(thisSiteLookupGetUrl(`0x${clean}`)),
    ]);
    if (!String(armored).includes("BEGIN PGP")) {
      throw new Error("Could not fetch public key");
    }
    const pgpKey = await readKey({ armoredKey: armored });
    const recipient = await buildRecipient(
      pgpKey,
      { ...meta, fingerprint: clean },
      { origin: "basilisk" }
    );
    await putRecipientInCache(recipient, armored);
    return recipient;
  } catch (basiliskErr) {
    const host = explicitUpstreamHost(opts.keyserver);
    const allowUpstream =
      opts.allowUpstream !== false && !!host && (await canUseUpstream());
    if (!allowUpstream) throw basiliskErr;

    const cfg = await getUpstreamConfig();
    if (!isKeyserverAllowed(host, cfg.allowlist)) throw basiliskErr;
    const fetched = await upstreamFetchKey(host, `0x${clean}`, {
      allowlist: cfg.allowlist,
    });
    if (!fetched) throw basiliskErr;
    const pgpKey = await readKey({ armoredKey: fetched.armored });
    const recipient = await buildRecipient(
      pgpKey,
      {
        fingerprint: fetched.fingerprint,
        key_id: fetched.keyId,
        approval_state: "",
        revoked: false,
        approved_uids: fetched.uids.map((raw) => {
          const m = String(raw).match(/<([^>]+)>/);
          return {
            raw,
            email: m ? m[1] : raw.includes("@") ? raw : fetched.email,
            name: m ? String(raw).slice(0, m.index).trim() : fetched.name,
          };
        }),
        email: fetched.email,
      },
      { origin: "upstream", sourceKeyserver: fetched.host }
    );
    await putRecipientInCache(recipient, fetched.armored);
    return recipient;
  }
}

/**
 * Merge search hits by fingerprint (prefer basilisk over upstream; keep armor).
 * @param {...object[]} lists
 * @returns {object[]}
 */
export function mergeSearchHits(...lists) {
  /** @type {Map<string, object>} */
  const byFpr = new Map();
  for (const list of lists) {
    for (const row of list || []) {
      const fpr = String(row?.fingerprint || "")
        .toUpperCase()
        .replace(/[^0-9A-F]/g, "");
      if (fpr.length < 16) continue;
      const prev = byFpr.get(fpr);
      if (!prev) {
        byFpr.set(fpr, { ...row, fingerprint: fpr });
        continue;
      }
      const prevOrigin = originRank(prev.origin);
      const nextOrigin = originRank(row.origin);
      if (nextOrigin < prevOrigin) {
        byFpr.set(fpr, { ...prev, ...row, fingerprint: fpr });
      } else if (!prev.armoredKey && (row.armoredKey || row.armoredPublic)) {
        byFpr.set(fpr, {
          ...prev,
          armoredKey: row.armoredKey || row.armoredPublic,
        });
      }
    }
  }
  return sortByTrustAndOrigin([...byFpr.values()]);
}

function originRank(origin) {
  const o = String(origin || "").toLowerCase();
  if (o === "basilisk") return 0;
  if (o === "import") return 1;
  if (o === "upstream") return 2;
  return 3;
}

/**
 * Locally trusted (then marginal) keys from the device pubkey cache.
 * @returns {Promise<object[]>}
 */
export async function listTrustedRecipientSuggestions() {
  const marks = listTrusted().filter(
    (t) => t.level === "trusted" || t.level === "marginal"
  );
  /** @type {object[]} */
  const hits = [];
  for (const mark of marks) {
    const rec = await cacheGet(mark.fingerprint);
    if (rec) hits.push(cacheRecordToSearchHit(rec));
  }
  return sortByTrustAndOrigin(hits);
}

/**
 * Search keys by query (email / fpr / key id).
 * @param {string} q
 * @param {{ keyserver?: string, allowUpstream?: boolean }} [opts]
 * @returns {Promise<{ results: object[], warning: string, reason: string }>}
 */
export async function searchRecipientsPayload(q, opts = {}) {
  const query = normalizeSearchQuery(q);
  if (query.length < 2) {
    const suggestions = await listTrustedRecipientSuggestions();
    return {
      results: suggestions,
      warning: "",
      reason: suggestions.length ? "trusted_local" : "empty",
    };
  }

  const idbHits = (await cacheSearch(query)).map(cacheRecordToSearchHit);

  /** @type {object[]} */
  let basiliskHits = [];
  let warning = "";
  let reason = "not_found";
  try {
    const payload = await fetchJson(
      `/api/v1/search?q=${encodeURIComponent(query)}`
    );
    basiliskHits = (payload.results || payload.keys || []).map((r) => ({
      ...r,
      origin: r.origin || "basilisk",
    }));
    warning = String(payload.warning || "");
    reason = String(payload.reason || (basiliskHits.length ? "ok" : "not_found"));
  } catch (_) {
    reason = "error";
  }

  /** @type {object[]} */
  let upstreamHits = [];
  const host = explicitUpstreamHost(opts.keyserver);
  const allowUpstream =
    opts.allowUpstream !== false && !!host && (await canUseUpstream());
  if (allowUpstream && !basiliskHits.length) {
    try {
      const cfg = await getUpstreamConfig();
      if (isKeyserverAllowed(host, cfg.allowlist)) {
        const fetched = await upstreamFetchKey(host, query, {
          allowlist: cfg.allowlist,
        });
        if (fetched) {
          await cachePut({
            fingerprint: fetched.fingerprint,
            armored: fetched.armored,
            uids: fetched.uids,
            email: fetched.email,
            name: fetched.name,
            origin: "upstream",
            sourceKeyserver: fetched.host,
          });
          upstreamHits = [
            {
              fingerprint: fetched.fingerprint,
              key_id: fetched.keyId,
              approval_state: "",
              revoked: false,
              approved_uids: fetched.uids.map((raw) => {
                const m = String(raw).match(/<([^>]+)>/);
                return {
                  raw,
                  email: m ? m[1] : raw.includes("@") ? raw : fetched.email,
                  name: m ? String(raw).slice(0, m.index).trim() : fetched.name,
                };
              }),
              email: fetched.email,
              origin: "upstream",
              source_keyserver: fetched.host,
            },
          ];
          reason = "upstream";
        }
      }
    } catch (_) {
      /* ignore upstream failures */
    }
  }

  const results = mergeSearchHits(idbHits, basiliskHits, upstreamHits);
  if (results.length && reason === "not_found") reason = "ok";
  return { results, warning, reason };
}

/**
 * Search keys by query (email / fpr / key id).
 * @param {string} q
 * @returns {Promise<object[]>}
 */
export async function searchRecipients(q) {
  return (await searchRecipientsPayload(q)).results;
}

/**
 * Render hit list into a container and wire pick handlers.
 * @param {HTMLElement} hitsEl
 * @param {object[]} results
 * @param {string} warning
 * @param {(fpr: string) => void|Promise<void>} onPick
 * @param {{ alreadyFprs?: Set<string>, slot?: number }} [opts]
 */
export function renderRecipientHits(hitsEl, results, warning, onPick, opts = {}) {
  const sorted = sortByTrustAndOrigin(results || []);
  if (!sorted.length) {
    hitsEl.innerHTML = `<p class="muted">No keys found.</p>`;
    return;
  }
  const caution = warning
    ? `<p class="name-search-caution" role="status"><strong>Short key ID.</strong> ${escapeHtml(warning)}</p>`
    : "";
  const already = opts.alreadyFprs || new Set();
  hitsEl.innerHTML =
    caution +
    sorted
      .slice(0, 12)
      .map((k) => {
        const fpr = String(k.fingerprint || "").toUpperCase();
        const trustLevel = getTrust(fpr)?.level;
        return keyHitHtml(k, {
          already: already.has(fpr),
          className: trustLevel === "trusted" ? "key-hit-trusted" : "",
          dataAttrs: {
            "data-pick": fpr,
            ...(opts.slot != null ? { "data-slot": String(opts.slot) } : {}),
          },
        });
      })
      .join("");
  hitsEl.querySelectorAll("[data-pick]").forEach((el) => {
    el.addEventListener("click", async () => {
      const fpr = el.getAttribute("data-pick") || "";
      await onPick(fpr);
    });
  });
}

/**
 * Mount a multi-slot recipient binder for toolkit Run.
 *
 * @param {HTMLElement} host
 * @param {object} opts
 * @param {number} opts.slots
 * @param {boolean} [opts.foreach]
 * @param {(recipients: Recipient[]) => void} opts.onChange
 */
export function mountRecipientBinder(host, opts) {
  const slots = Math.max(1, Number(opts.slots) || 1);
  const foreach = !!opts.foreach;
  /** @type {(Recipient|null)[]} */
  const bound = Array.from({ length: slots }, () => null);
  let sameForAll = false;
  /** Session override for the binder select ("" = This site). */
  let sessionKeyserver = "";

  function currentKeyserver() {
    return readKeyserverSelectValue("binder-keyserver") || sessionKeyserver || "";
  }

  async function binderKeyserverRowHtml() {
    const select = await toolkitKeyserverSelectHtml({
      id: "binder-keyserver",
      selected: sessionKeyserver,
    });
    const ok = await canUseUpstream();
    const hint = ok
      ? "This site by default; pick an upstream only to override on miss."
      : "This site keyserver. Sign in to search allowlisted upstreams.";
    return `<div class="keyserver-control mb-md" data-upstream-ready="${ok ? "1" : "0"}">
      <label class="field-label" for="binder-keyserver">Keyserver</label>
      <div class="btn-row wrap items-center gap-sm">
        ${select}
        <a class="text-link fs-sm" href="/preferences">Preferences</a>
      </div>
      <p class="muted fs-sm mt-xs mb-0">${escapeHtml(hint)}</p>
    </div>`;
  }

  const render = () => {
    void renderAsync();
  };

  const renderAsync = async () => {
    const ksRow = await binderKeyserverRowHtml();
    host.innerHTML = `
      <div class="recipient-binder">
        <p class="muted m-0-b-md fs-md">
          Choose GPG recipients and confirm fingerprints before running.
          Identities are not stored in the recipe.
        </p>
        ${ksRow}
        ${
          foreach && slots > 1
            ? `<label class="radio-row mb-md">
                <input type="checkbox" id="binder-same-all" ${sameForAll ? "checked" : ""}>
                Same recipient for all shares
              </label>`
            : ""
        }
        <div class="binder-slots">
          ${bound
            .map((r, i) => {
              if (sameForAll && i > 0) return "";
              const title = foreach ? `Share ${i + 1} of ${slots}` : "Recipient";
              const extras = r
                ? keyPillExtrasHtml({
                    fingerprint: r.fingerprint,
                    userLabel: r.userLabel,
                    label: r.userLabel,
                    keyExpiration: r.keyExpiration,
                    key_id: r.keyId,
                    origin: r.origin,
                    source_keyserver: r.sourceKeyserver,
                  })
                : "";
              const trust = r ? trustBadgeHtml(r.fingerprint) : "";
              const pill = r
                ? `<span class="recipient-pill${getTrust(r.fingerprint)?.level === "trusted" ? " recipient-pill-trusted" : ""}">
                     <span class="pill-body">
                       <span class="pill-label">${escapeHtml(r.label)}</span>
                       <a class="text-link fpr pill-fpr" href="/key?fpr=${escapeHtml(r.fingerprint)}" target="_blank" rel="noopener">
                         ${escapeHtml(formatFingerprint(r.fingerprint))}
                       </a>
                       ${extras ? `<span class="pill-extras">${extras}</span>` : ""}
                     </span>
                     ${trust}
                     <button type="button" class="pill-remove" data-clear="${i}" aria-label="Clear">×</button>
                   </span>`
                : `<span class="muted">Not selected</span>`;
              return `
                <div class="binder-slot" data-slot="${i}">
                  <p class="field-label">${escapeHtml(title)}</p>
                  <div class="btn-row wrap items-center">
                    <input type="search" class="text-input binder-search flex-1 minw-180" data-slot="${i}"
                           placeholder="Email, fingerprint, or key ID"
                           autocomplete="off">
                    <button type="button" class="btn btn-ghost btn-compact binder-go" data-slot="${i}">Look up</button>
                  </div>
                  <div class="binder-hits" data-slot="${i}"></div>
                  <div class="binder-current mt-xs">${pill}</div>
                </div>`;
            })
            .join("")}
        </div>
      </div>`;

    host.querySelector("#binder-same-all")?.addEventListener("change", (e) => {
      sameForAll = !!/** @type {HTMLInputElement} */ (e.target).checked;
      if (sameForAll && bound[0]) {
        for (let i = 1; i < slots; i++) bound[i] = bound[0];
      }
      render();
      emit();
    });

    host.querySelector("#binder-keyserver")?.addEventListener("change", (e) => {
      const el = /** @type {HTMLSelectElement} */ (e.target);
      sessionKeyserver = normalizeKeyserverHost(el.value) || "";
    });

    host.querySelectorAll(".binder-search").forEach((input) => {
      input.addEventListener("focus", async () => {
        const i = Number(input.getAttribute("data-slot"));
        const hitsEl = host.querySelector(`.binder-hits[data-slot="${i}"]`);
        if (!(input instanceof HTMLInputElement) || !hitsEl) return;
        if (input.value.trim()) return;
        const suggestions = await listTrustedRecipientSuggestions();
        if (!suggestions.length) return;
        const ks = await currentKeyserver();
        renderRecipientHits(hitsEl, suggestions, "", async (fpr) => {
          const r = await loadRecipientKey(fpr, { keyserver: ks });
          await select(i, r);
        }, { slot: i });
      });
    });

    host.querySelectorAll(".binder-go").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const i = Number(btn.getAttribute("data-slot"));
        const input = host.querySelector(`.binder-search[data-slot="${i}"]`);
        const q = input instanceof HTMLInputElement ? input.value.trim() : "";
        const hitsEl = host.querySelector(`.binder-hits[data-slot="${i}"]`);
        if (!hitsEl) return;
        hitsEl.innerHTML = `<p class="muted">Searching…</p>`;
        const ks = await currentKeyserver();
        try {
          if (!q) {
            const suggestions = await listTrustedRecipientSuggestions();
            renderRecipientHits(hitsEl, suggestions, "", async (fpr) => {
              const r = await loadRecipientKey(fpr, { keyserver: ks });
              await select(i, r);
            }, { slot: i });
            if (!suggestions.length) {
              hitsEl.innerHTML = `<p class="muted">No trusted local keys yet. Search by email or fingerprint.</p>`;
            }
            return;
          }
          const hex = q.replace(/[^0-9A-Fa-f]/g, "");
          if (hex.length >= 16) {
            const r = await loadRecipientKey(
              hex.length >= 40 ? hex.slice(-40) : hex,
              { keyserver: ks }
            );
            await select(i, r);
            return;
          }
          const { results, warning } = await searchRecipientsPayload(q, {
            keyserver: ks,
          });
          renderRecipientHits(hitsEl, results, warning, async (fpr) => {
            const r = await loadRecipientKey(fpr, { keyserver: ks });
            await select(i, r);
          }, { slot: i });
        } catch (err) {
          hitsEl.innerHTML = `<p class="status-row err">${escapeHtml(err?.message || "Lookup failed")}</p>`;
        }
      });
    });

    host.querySelectorAll("[data-clear]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.getAttribute("data-clear"));
        bound[i] = null;
        if (sameForAll) for (let j = 0; j < slots; j++) bound[j] = null;
        render();
        emit();
      });
    });
  };

  /**
   * @param {number} i
   * @param {Recipient} r
   */
  async function select(i, r) {
    if (!r.valid) throw new Error(r.error || "Invalid recipient key");
    bound[i] = r;
    if (sameForAll) for (let j = 0; j < slots; j++) bound[j] = r;
    render();
    emit();
  }

  function emit() {
    const list = sameForAll
      ? Array.from({ length: slots }, () => bound[0]).filter(Boolean)
      : bound.filter(Boolean);
    if (foreach && !sameForAll) {
      opts.onChange(bound.every(Boolean) ? /** @type {Recipient[]} */ (bound.slice()) : []);
    } else {
      opts.onChange(/** @type {Recipient[]} */ (list));
    }
  }

  render();
  return {
    getRecipients: () =>
      sameForAll
        ? Array.from({ length: slots }, () => bound[0]).filter(Boolean)
        : bound.filter(Boolean),
    destroy: () => {
      host.innerHTML = "";
    },
  };
}
