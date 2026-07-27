/**
 * Toolkit HKP ops — public key fetch via portal, device cache, and optional upstream.
 */

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
