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
 * The fingerprint out of a `/pks/add` reply.
 *
 * Basilisk answers `Ok\nClaim: <base>/claim/<fpr>` — the fingerprint is in the
 * claim URL's last segment, and there is no `Fingerprint:` line anywhere in the
 * body. This used to look for that label, matched nothing, and handed back an
 * empty string, which `directoryUrl` degraded into the bare lookup endpoint and
 * `useNotebook.publishArtifact` wrote to `tile.publishedAs` as `$pub` — a
 * person who had just published a key was shown no link to it.
 *
 * The client is what was wrong, not the server: `keys.js` reads the same reply
 * with `/^Claim:\s*(.+)$/m` and has always read it correctly, so this file was
 * the only end of the repo that disagreed with a format its own upload form
 * already parses.
 *
 * Sixty-four hex is tried before forty so a v6 fingerprint is never sliced down
 * to a v4-length prefix; a 16-hex long key id is deliberately not matched at
 * all, because a key id is not a fingerprint and `search=0x<keyid>` is a
 * different, ambiguous query.
 *
 * @param {string} body
 * @returns {string} uppercase fingerprint, or "" when the reply carries none
 */
function fingerprintFromAddReply(body) {
  const claim = String(body).match(
    /^Claim:\s*\S*\/claim\/([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40})\b/m
  );
  return claim ? claim[1].toUpperCase() : "";
}

/**
 * The handle an artifact tile shows once its key is in the directory.
 *
 * It lives here, beside the call that produces the fingerprint, rather than in
 * `useNotebook.publishArtifact` where it was written inline, for two reasons.
 * A tile whose handle read `$pub` was reporting the *parse* failure above and
 * not anything about the key, and nothing could see that from the hook; and the
 * rule for turning a fingerprint into a handle is now stated once, where the
 * fingerprint comes from, instead of at the one call site that happened to need
 * it. `$pub` remains the reading for "published, but the directory did not name
 * what it took" — an honest placeholder, not a fingerprint.
 *
 * @param {string} fingerprint
 * @returns {string}
 */
export function publishedHandle(fingerprint) {
  const fpr = String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return fpr ? `@${fpr.slice(-8)}` : "$pub";
}

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
  const fpr = fingerprintFromAddReply(body);
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
