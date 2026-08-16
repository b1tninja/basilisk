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
  encryptUnverifiedCount,
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
 * What an artifact tile shows once its key is in the directory: the whole
 * fingerprint, or `$pub` when the directory named nothing.
 *
 * It lives here, beside the call that produces the fingerprint, rather than in
 * `useNotebook.publishArtifact` where it was written inline, for two reasons.
 * A tile whose handle read `$pub` was reporting the *parse* failure above and
 * not anything about the key, and nothing could see that from the hook; and the
 * rule is now stated once, where the fingerprint comes from, instead of at the
 * one call site that happened to need it. `$pub` remains the reading for
 * "published, but the directory did not name what it took" — an honest
 * placeholder, not a fingerprint.
 *
 * **It used to return `@` and the last eight hex characters.** That is a short
 * key id wearing a different sigil: eight hex is 32 bits, the width that was
 * forged wholesale in 2016, and it names more than one key. The objection is
 * not that eight is too few — `components/ui/fingerprint.tsx` sets out at
 * length why raising the number is not the fix — it is that a form built out of
 * the fingerprint's own characters *will* be compared, and the reader comparing
 * it cannot tell that they compared a part. So this publishes no number of
 * characters: it publishes all of them, and `ArtifactTile` renders the result
 * through `<Fingerprint>` like every other fingerprint on the site, so the
 * value is grouped, reachable and copied whole.
 *
 * Nothing is fetched to do it. `publishArmoredKey` already answers with the
 * full fingerprint, and this was throwing thirty-two of its characters away.
 *
 * @param {string} fingerprint
 * @returns {string} the whole uppercase fingerprint, or `$pub`
 */
export function publishedHandle(fingerprint) {
  const fpr = String(fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return fpr || "$pub";
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
  // `valid` and `encryptCapable` are no longer re-stated here. Both were
  // `x !== false`, which is the identity on a boolean and a *promotion* on
  // anything else: `recipientFromSearchHit` now answers `null` for a capability
  // the directory cannot decide, and this line turned every one of those into
  // `true` before the value left the op. Whatever it decided is what ships.
  const list = (payload.results || [])
    .map(recipientFromSearchHit)
    .filter(Boolean)
    .map((r) => ({
      ...r,
      approvalState: r.approvalState || (r.origin === "basilisk" ? "approved" : r.approvalState),
    }));
  return recipientsPipelineValue(list, {
    query,
    warning: payload.warning || "",
    reason: payload.reason || "",
  });
}

/**
 * Narrow a recipients list.
 *
 * The result carries `encryptUnverified` whenever `encrypt=true` was in force,
 * because that switch can only do half of what its name says: it drops the keys
 * the directory *proves* cannot encrypt — revoked, expired — and it has nothing
 * to judge the rest by, since capability is a fact about a certificate's
 * packets and the portal's JSON carries no column for it (see
 * `recipientFromSearchHit`). A count of what went unjudged is how the answer
 * stops presenting itself as complete. Zero is stamped too, and deliberately:
 * "nothing here is unverified" is a different statement from a field that is
 * simply absent, and only the first of them can be relied on.
 *
 * @param {{ type?: string, data?: * }|null} value
 * @param {Record<string, *>} params
 */
export async function execHkpFilter(value, params = {}) {
  const list = pipelineValueToRecipients(value);
  const origin = String(params.origin || "").toLowerCase();
  const wantEncrypt = params.encrypt !== false && params.encrypt !== "false";
  const filtered = filterRecipients(list, {
    approved: params.approved !== false && params.approved !== "false",
    encrypt: wantEncrypt,
    origin: origin || undefined,
  });
  return recipientsPipelineValue(filtered, {
    ...(value?.meta || {}),
    filtered: true,
    ...(wantEncrypt ? { encryptUnverified: encryptUnverifiedCount(filtered) } : {}),
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
  // Same as `execHkpSearch`: a cache record holds no capability verdict either,
  // and `x !== false` would invent one. The cache stores armor, so a caller
  // that wants the answer can get it — from `hkp.get`, which asks.
  const list = rows.map(recipientFromSearchHit).filter(Boolean);
  return recipientsPipelineValue(list, { hkpCache: true, count: list.length });
}
