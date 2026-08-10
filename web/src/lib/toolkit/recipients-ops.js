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
 * @property {boolean} [encryptCapable]
 */

/**
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
  // Upstream / import keys are usable without Basilisk approval when encrypt-capable.
  const validResolved =
    row.valid != null
      ? !!row.valid
      : origin === "upstream" || origin === "import"
        ? !row.revoked
        : approvalState === "approved" && !row.revoked;
  return {
    fingerprint: fpr,
    armoredPublic: String(row.armoredKey || row.armoredPublic || row.public || ""),
    label: String(row.label || row.uid || row.userLabel || fpr),
    email: String(row.email || ""),
    approvalState,
    origin,
    sourceKeyserver: String(row.source_keyserver || row.sourceKeyserver || ""),
    valid: validResolved,
    encryptCapable: row.encryptCapable != null ? !!row.encryptCapable : validResolved,
  };
}

/**
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
        encryptCapable: value.meta?.encryptCapable !== false,
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
          encryptCapable: true,
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
