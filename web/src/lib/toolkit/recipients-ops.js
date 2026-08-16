/**
 * Toolkit recipients helpers — directory picks for gpg.encrypt to=
 */

import { SLOT_SIGIL } from "./recipe-parse.js";

/**
 * @typedef {object} ToolkitRecipient
 * @property {string} fingerprint
 * @property {string} armoredPublic
 * @property {string} [label]
 * @property {string} [email]
 * @property {string} [approvalState]
 * @property {string} [origin]
 * @property {string} [sourceKeyserver]
 * @property {boolean} [valid]
 * @property {boolean|null} [encryptCapable]
 *   Three states, not two. `true` when something asked the certificate and it
 *   answered; `false` when it is *proven* unable to encrypt; `null` when nobody
 *   has been able to ask. See `recipientFromSearchHit`.
 */

/**
 * Has the directory's stated expiry already passed?
 *
 * `key_expiration` is the one capability fact besides revocation that the
 * portal's JSON carries, and until `fa76818` nothing on this path read it. It
 * is the server's copy of what the certificate says, taken at ingest — good
 * enough to *drop* a key on, which is the only direction it is used in here,
 * and never good enough to overrule armor (`recipient-picker.js`'s `hasExpired`
 * is where that precedence is settled, and it settles it the other way).
 *
 * A row with no expiration, or one that will not parse, is not expired: it is
 * a row that did not say. Guessing "expired" from silence would drop live keys.
 *
 * @param {object} row
 * @returns {boolean}
 */
function statedExpiryPassed(row) {
  const at = Date.parse(row.key_expiration || row.keyExpiration || "");
  return Number.isFinite(at) && at <= Date.now();
}

/**
 * The first user id of a row, as a display label and an address.
 *
 * Every producer of a row here sends the directory's structured shape —
 * `approved_uids: [{ raw, name, email }]` — because both of them are that
 * shape: `key_summary(include_uids=True)` builds it on the server, and
 * `cacheRecordToSearchHit` rebuilds it from the device cache. Reading it is
 * what makes the two paths agree.
 *
 * @param {object} row
 * @returns {{ label: string, email: string }}
 */
function uidOf(row) {
  const uid = (row.approved_uids || row.pending_uids || row.uids || [])[0];
  if (!uid) return { label: "", email: "" };
  if (typeof uid === "string") {
    const m = uid.match(/<([^>]+)>/);
    return { label: uid, email: m ? m[1].toLowerCase() : "" };
  }
  const email = String(uid.email || "").toLowerCase();
  const name = String(uid.name || "").trim();
  return {
    label: name && email ? `${name} <${email}>` : email || String(uid.raw || ""),
    email,
  };
}

/**
 * A directory row, read as a recipient — including how much of it is *known*.
 *
 * ## Capability has three states here, and it used to have two
 *
 * `encryptCapable` was `validResolved`: approved and unrevoked meant capable.
 * That is not a capability check, it is an approval check wearing its name, and
 * the two facts are unrelated — a signing-only certificate is approved, live,
 * and cannot receive a message. So `hkp.filter encrypt=true`, whose control
 * reads "Keep only encrypt-capable keys", kept exactly the keys that cannot
 * encrypt, and the cost of that is choosing a recipient who will never be able
 * to read what you sent them.
 *
 * The honest reading of the portal's JSON is that it decides capability
 * *sometimes*:
 *
 * - **revoked** — decided, `false`. A revoked key encrypts to nobody.
 * - **expired**, per `key_expiration` — decided, `false`. This is new: the
 *   field has always been in the payload and nothing read it, so the one
 *   genuinely expired key in this repo's own corpus sailed through the filter.
 * - **anything else** — *not decided*, `null`. Whether a certificate has an
 *   encryption-capable subkey is a fact about its packets, and the directory
 *   stores no column for it: not the algorithm, not the key flags, not a
 *   derived capability bit. `key_summary` cannot report what `CertRecord` does
 *   not hold.
 *
 * `null` is not `false` and is not `true`. It is what makes the filter able to
 * drop what it can prove while saying that the survivors are unverified,
 * instead of quietly promoting "I did not check" to "I checked and it passed".
 * A row that *has* been asked — `hkp.get`, the device cache, anything holding
 * armor — arrives with an explicit boolean and keeps it.
 *
 * ## Why this does not simply fetch the armor
 *
 * Because this is not a place that can fetch. `filterRecipients` is a
 * synchronous predicate, and `recipient-resolve-ui.js` calls it from inside
 * `render()` and again from `paintHits()` — a modal repaint. Making capability
 * decidable here means making both async and issuing two requests per candidate
 * from a render path, for a search that routinely returns tens of rows. A
 * recipe's `hkp.get` is where a key is asked, it is one step away, and it is
 * declared as the op that reaches the network. This one is declared
 * `entropy: "none"`, `kind: "transform"` — a narrowing of a value already in
 * hand — and it stays that.
 *
 * @param {object} row  portal search hit or loadRecipientKey result
 * @returns {ToolkitRecipient|null}
 */
export function recipientFromSearchHit(row) {
  if (!row || typeof row !== "object") return null;
  const fpr = String(row.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (fpr.length < 40) return null;
  const approvalState = String(row.approval_state || row.approvalState || "");
  const origin = String(row.origin || "").toLowerCase();
  const expired = statedExpiryPassed(row);
  // Upstream / import keys are usable without Basilisk approval when encrypt-capable.
  // An expired key is not usable on any origin: `buildRecipient` refuses one
  // outright when it has the armor, and a row that reads "valid" here while the
  // same key reads "Key is expired" one op along is the two paths disagreeing
  // about one certificate.
  const validResolved =
    row.valid != null
      ? !!row.valid
      : origin === "upstream" || origin === "import"
        ? !row.revoked && !expired
        : approvalState === "approved" && !row.revoked && !expired;
  // The user id, after any friendly label someone set and before the last
  // resort of showing a fingerprint where a name belongs. `row.email` used to
  // be the only address this read, and only the device cache sends one — so a
  // key looked anonymous the first time it was searched for and correct the
  // second, once it was cached, with the address it should have shown sitting
  // unread in the same payload both times.
  const uid = uidOf(row);
  return {
    fingerprint: fpr,
    armoredPublic: String(row.armoredKey || row.armoredPublic || row.public || ""),
    label: String(row.label || row.uid || row.userLabel || uid.label || fpr),
    email: String(row.email || uid.email || ""),
    approvalState,
    origin,
    sourceKeyserver: String(row.source_keyserver || row.sourceKeyserver || ""),
    valid: validResolved,
    encryptCapable:
      row.encryptCapable != null
        ? !!row.encryptCapable
        : row.revoked || expired
          ? false
          : null,
  };
}

/**
 * Narrow a recipient list, dropping only what the rows can be shown to fail.
 *
 * `encrypt` drops the **proven** incapable — revoked, expired — and keeps rows
 * whose capability is `null`, because a filter cannot drop a key for a fact it
 * does not have. That is a deliberate half-answer and it is why the copy on
 * this switch no longer promises a whole one: it used to read "Keep only
 * encrypt-capable keys" while keeping a signing-only key, which is a control
 * lying about its own name. `encryptUnverifiedCount` below is how a caller says
 * out loud how much of its result is unjudged.
 *
 * @param {ToolkitRecipient[]} list
 * @param {{ approved?: boolean, encrypt?: boolean, origin?: string }} [opts]
 * @returns {ToolkitRecipient[]}
 */
export function filterRecipients(list, opts = {}) {
  const wantApproved = opts.approved !== false;
  const wantEncrypt = opts.encrypt !== false;
  const wantOrigin = String(opts.origin || "").toLowerCase();
  return (list || []).filter((r) => {
    if (!r?.fingerprint) return false;
    if (wantOrigin && String(r.origin || "").toLowerCase() !== wantOrigin) {
      return false;
    }
    if (wantApproved) {
      const origin = String(r.origin || "").toLowerCase();
      if (origin === "upstream" || origin === "import") {
        // Keep non-org keys unless explicitly invalid.
        if (r.valid === false) return false;
      } else if (r.approvalState) {
        if (r.approvalState !== "approved") return false;
      } else if (r.valid === false) {
        return false;
      }
    }
    if (wantEncrypt && r.encryptCapable === false) return false;
    return true;
  });
}

/**
 * How many rows nobody has been able to ask about encryption capability.
 *
 * Exported because the number is the honest half of `encrypt=true`'s answer,
 * and it has to be sayable by whoever presents the result — the op's meta, a
 * modal's status line. A count computed twice would eventually be two counts.
 *
 * @param {ToolkitRecipient[]} list
 * @returns {number}
 */
export function encryptUnverifiedCount(list) {
  return (list || []).filter((r) => r && r.encryptCapable == null).length;
}

/**
 * @param {ToolkitRecipient[][]} lists
 * @returns {ToolkitRecipient[]}
 */
export function mergeRecipients(...lists) {
  /** @type {Map<string, ToolkitRecipient>} */
  const byFpr = new Map();
  for (const list of lists) {
    for (const r of list || []) {
      if (!r?.fingerprint) continue;
      const prev = byFpr.get(r.fingerprint);
      if (!prev) {
        byFpr.set(r.fingerprint, { ...r });
      } else if (!prev.armoredPublic && r.armoredPublic) {
        byFpr.set(r.fingerprint, { ...prev, ...r });
      }
    }
  }
  return [...byFpr.values()];
}

/**
 * Coerce a pipeline value into a recipients list.
 * @param {{ type?: string, data?: *, meta?: object }|null|undefined} value
 * @returns {ToolkitRecipient[]}
 */
export function pipelineValueToRecipients(value) {
  if (!value) return [];
  if (value.type === "recipients" && Array.isArray(value.data)) {
    return value.data.map((r) => ({ ...r }));
  }
  if (value.type === "openpgp-key" && value.meta?.which !== "private") {
    const armored = String(value.data || "");
    const fpr = String(value.meta?.fingerprint || "")
      .toUpperCase()
      .replace(/[^0-9A-F]/g, "");
    if (!armored.includes("BEGIN PGP")) return [];
    return [
      {
        fingerprint: fpr || "UNKNOWN",
        armoredPublic: armored,
        label: value.meta?.label || fpr,
        email: value.meta?.email || "",
        approvalState: value.meta?.approvalState || "",
        valid: value.meta?.valid !== false,
        // `hkp.get` asks the certificate and states the answer, so it is read
        // rather than defaulted. A value that carries armor but no verdict has
        // not been asked, and `null` says so — `!== false` used to read the
        // absence of an answer as a pass.
        encryptCapable:
          value.meta?.encryptCapable == null ? null : !!value.meta.encryptCapable,
      },
    ];
  }
  if (value.type === "text") {
    const text = String(value.data || "").trim();
    if (text.includes("BEGIN PGP")) {
      return [
        {
          fingerprint: String(value.meta?.fingerprint || "UNKNOWN"),
          armoredPublic: text,
          label: value.meta?.label || "",
          email: value.meta?.email || "",
          approvalState: "",
          valid: true,
          // Armor pasted into the pipeline: the key is in hand, and nothing has
          // read it. Unverified, not capable.
          encryptCapable: null,
        },
      ];
    }
    try {
      const parsed = JSON.parse(text);
      const rows = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed?.results)
          ? parsed.results
          : [];
      return rows.map(recipientFromSearchHit).filter(Boolean);
    } catch (_) {
      return [];
    }
  }
  return [];
}

/**
 * @param {ToolkitRecipient[]} list
 * @param {object} [meta]
 * @returns {{ type: "recipients", data: ToolkitRecipient[], meta: object }}
 */
export function recipientsPipelineValue(list, meta = {}) {
  return {
    type: "recipients",
    data: list || [],
    meta: { sensitive: false, ...meta },
  };
}

/**
 * @param {string} armored
 * @param {{ which: "public"|"private", fingerprint?: string, sensitive?: boolean } & Record<string, *>} meta
 */
export function openPgpKeyPipelineValue(armored, meta) {
  return {
    type: "openpgp-key",
    data: String(armored || ""),
    meta: {
      sensitive: meta.which === "private",
      ...meta,
    },
  };
}

/**
 * Parse `gpg.encrypt to=` token.
 * @param {string|undefined|null} raw
 * @returns {{ kind: "empty" } | { kind: "slot", ref: string } | { kind: "fpr", fingerprint: string } | { kind: "email", query: string }}
 */
export function parseEncryptToToken(raw) {
  const s = String(raw || "").trim();
  if (!s) return { kind: "empty" };

  const emailPref = s.match(/^email:(.+)$/i);
  if (emailPref) {
    return { kind: "email", query: emailPref[1].trim() };
  }

  const fprPref = s.match(/^(?:fpr:|0x)([0-9A-Fa-f\s]+)$/i);
  if (fprPref) {
    const fingerprint = fprPref[1].toUpperCase().replace(/[^0-9A-F]/g, "");
    if (fingerprint.length >= 40) return { kind: "fpr", fingerprint };
  }

  const compact = s.replace(/\s+/g, "");
  if (/^[0-9A-Fa-f]{40,}$/i.test(compact)) {
    return { kind: "fpr", fingerprint: compact.toUpperCase() };
  }

  if (s.startsWith(SLOT_SIGIL)) {
    return { kind: "slot", ref: s };
  }

  // Email / name fragment (contains @ but not as leading slot marker)
  if (s.includes("@")) {
    return { kind: "email", query: s };
  }

  // Bare slot label (no @)
  return { kind: "slot", ref: `@${s}` };
}

/**
 * True when encrypt has an explicit `to=` (binder not required).
 * @param {{ name?: string, params?: Record<string, *> }|null|undefined} step
 */
export function stepEncryptToBound(step) {
  if (!step || step.name !== "gpg.encrypt") return false;
  return String(step.params?.to || "").trim() !== "";
}

/**
 * Normalize email/query key for recipientResolutions map.
 * @param {string} query
 */
export function recipientResolutionKey(query) {
  return String(query || "").trim().toLowerCase();
}
