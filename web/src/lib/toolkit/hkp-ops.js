/**
 * Toolkit HKP ops — device cache → This site `/pks/lookup` → optional explicit upstream.
 */

import { Auth } from "../auth.js";
import { fetchJson } from "../utils.js";
import {
  cacheClear,
  cacheList,
  cacheRecordToSearchHit,
} from "../pubkey-cache.js";
import {
  loadRecipientKey,
  searchRecipientsPayload,
} from "../recipient-picker.js";
import { sortByTrustAndOrigin } from "../trust.js";
import { normalizeVaultFingerprint } from "../vault-session.js";
import {
  filterRecipients,
  openPgpKeyPipelineValue,
  pipelineValueToRecipients,
  recipientFromSearchHit,
  recipientsPipelineValue,
} from "./recipients-ops.js";

/**
 * Publish an armored public key to This site's directory (design v2 §21b) —
 * the same `/pks/add` / `/api/v1/me/keys` write path `keys.js`'s upload form
 * uses, factored out so `useNotebook().publishArtifact` can call it headlessly.
 * @param {string} armoredKey
 * @returns {Promise<{ fingerprint: string, directoryUrl: string }>}
 */
export async function publishArmoredKey(armoredKey) {
  const keytext = String(armoredKey || "").trim();
  if (!keytext.includes("BEGIN PGP")) {
    throw new Error("publishArtifact: not an armored public key");
  }
  const user = await Auth.getUser();
  if (user && user.authenticated) {
    const result = await fetchJson("/api/v1/me/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: keytext }),
    });
    const fpr = String(result?.fingerprint || "").toUpperCase();
    return {
      fingerprint: fpr,
      directoryUrl: fpr
        ? `${location.origin}/pks/lookup?op=get&search=0x${fpr}`
        : `${location.origin}/pks/lookup`,
    };
  }
  const r = await fetch("/pks/add", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `keytext=${encodeURIComponent(keytext)}`,
  });
  const body = await r.text();
  if (!r.ok) {
    throw Object.assign(new Error(body.trim() || `Request failed (${r.status})`), {
      status: r.status,
    });
  }
  const fprMatch = body.match(/[Ff]ingerprint:\s*([0-9A-Fa-f]{16,64})/);
  const fpr = fprMatch ? fprMatch[1].toUpperCase() : "";
  return {
    fingerprint: fpr,
    directoryUrl: fpr
      ? `${location.origin}/pks/lookup?op=get&search=0x${fpr}`
      : `${location.origin}/pks/lookup`,
  };
}

/**
 * @param {Record<string, *>} params
 */
export async function execHkpGet(params = {}) {
  const fpr = normalizeVaultFingerprint(params.fpr);
  if (fpr.length < 40) {
    throw new Error("hkp.get requires fpr= (40+ hex fingerprint)");
  }
  const recipient = await loadRecipientKey(fpr, {
    keyserver: params.keyserver,
    forceRefresh: params.refresh === true || params.refresh === "true",
  });
  const armored = String(recipient?.armoredKey || "").trim();
  if (!armored.includes("BEGIN PGP")) {
    throw new Error(recipient?.error || "Could not fetch public key");
  }
  return openPgpKeyPipelineValue(armored, {
    which: "public",
    fingerprint: recipient.fingerprint || fpr,
    label: recipient.label || "",
    email: recipient.email || "",
    valid: !!recipient.valid,
    encryptCapable: !!recipient.valid,
    approvalState: recipient.approvalState || "",
    origin: recipient.origin || "",
    sourceKeyserver: recipient.sourceKeyserver || "",
    err: recipient.error || "",
  });
}

/**
 * @param {Record<string, *>} params
 */
export async function execHkpSearch(params = {}) {
  const query = String(params.query || "").trim();
  if (!query) throw new Error("hkp.search requires query=");
  const payload = await searchRecipientsPayload(query, {
    keyserver: params.keyserver,
  });
  const format = String(params.format || "recipients").toLowerCase();
  if (format === "json") {
    return {
      type: "text",
      data: JSON.stringify(
        {
          query,
          warning: payload.warning || "",
          reason: payload.reason || "",
          results: payload.results || [],
        },
        null,
        2
      ),
      meta: { sensitive: false, kind: "opaque", hkpSearch: true },
    };
  }
  const list = (payload.results || [])
    .map(recipientFromSearchHit)
    .filter(Boolean)
    .map((r) => ({
      ...r,
      approvalState: r.approvalState || (r.origin === "basilisk" ? "approved" : r.approvalState),
      valid: r.valid !== false,
      encryptCapable: r.encryptCapable !== false,
    }));
  return recipientsPipelineValue(list, {
    query,
    warning: payload.warning || "",
    reason: payload.reason || "",
  });
}

/**
 * @param {{ type?: string, data?: * }|null} value
 * @param {Record<string, *>} params
 */
export async function execHkpFilter(value, params = {}) {
  const list = pipelineValueToRecipients(value);
  const origin = String(params.origin || "").toLowerCase();
  const filtered = filterRecipients(list, {
    approved: params.approved !== false && params.approved !== "false",
    encrypt: params.encrypt !== false && params.encrypt !== "false",
    origin: origin || undefined,
  });
  return recipientsPipelineValue(filtered, {
    ...(value?.meta || {}),
    filtered: true,
  });
}

/**
 * List or clear the device IndexedDB pubkey cache.
 * @param {Record<string, *>} params
 */
export async function execHkpCache(params = {}) {
  const action = String(params.action || "list").toLowerCase();
  if (action === "clear") {
    await cacheClear();
    return {
      type: "text",
      data: "Pubkey cache cleared",
      meta: { sensitive: false, kind: "opaque", hkpCache: true },
    };
  }
  const rows = sortByTrustAndOrigin(
    (await cacheList()).map((r) => ({
      ...cacheRecordToSearchHit(r),
      lastUsedAt: r.lastUsedAt,
      fetchedAt: r.fetchedAt,
    }))
  );
  const format = String(params.format || "recipients").toLowerCase();
  if (format === "json") {
    return {
      type: "text",
      data: JSON.stringify({ count: rows.length, results: rows }, null, 2),
      meta: { sensitive: false, kind: "opaque", hkpCache: true },
    };
  }
  const list = rows
    .map(recipientFromSearchHit)
    .filter(Boolean)
    .map((r) => ({
      ...r,
      valid: r.valid !== false,
      encryptCapable: r.encryptCapable !== false,
    }));
  return recipientsPipelineValue(list, { hkpCache: true, count: list.length });
}
