/**
 * Shared rich key-hit rendering for search results and recipient pickers.
 * Surfaces label, trust, expiry, key ID so similar keys can be told apart.
 * @module lib/key-hit
 */

import { trustBadgeHtml } from "./trust.js";
import {
  describeExpiry,
  escapeHtml,
  formatFingerprint,
  uidEmail,
} from "./utils.js";

/**
 * @typedef {{
 *   fingerprint?: string,
 *   key_id?: string,
 *   keyId?: string,
 *   label?: string|null,
 *   userLabel?: string|null,
 *   approval_state?: string,
 *   approvalState?: string,
 *   revoked?: boolean,
 *   key_expiration?: string|null|Date,
 *   keyExpiration?: string|null|Date,
 *   approved_uids?: unknown[],
 *   pending_uids?: unknown[],
 *   uids?: unknown[],
 *   email?: string,
 * }} KeyHitItem
 */

/**
 * Primary display label from UIDs (name <email> or email or fingerprint).
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function primaryUidLabel(item) {
  const list = item.approved_uids || item.uids || item.pending_uids || [];
  if (list.length) {
    const uid = list[0];
    if (uid && typeof uid === "object") {
      const email = /** @type {{ email?: string, name?: string, raw?: string }} */ (uid)
        .email || "";
      const name = String(
        /** @type {{ name?: string }} */ (uid).name || ""
      ).trim();
      if (name && email) return `${name} <${email}>`;
      if (email) return email;
      const raw = /** @type {{ raw?: string }} */ (uid).raw;
      if (raw) return String(raw);
    } else if (typeof uid === "string" && uid.trim()) {
      return uid.trim();
    }
  }
  if (item.email) return String(item.email);
  const fp = String(item.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return fp ? formatFingerprint(fp) : "Unknown key";
}

/**
 * User-assigned friendly label (keyserver), if any.
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function userLabelOf(item) {
  const raw = item.userLabel ?? item.label;
  if (raw == null) return "";
  return String(raw).trim();
}

/**
 * Short key ID for differentiation (last 8 hex of fingerprint / key_id).
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function shortKeyId(item) {
  const kid = String(item.key_id || item.keyId || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (kid.length >= 8) return kid.slice(-8);
  const fp = String(item.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return fp.length >= 8 ? fp.slice(-8) : kid || fp;
}

/**
 * @param {KeyHitItem} item
 * @returns {string|null|Date|undefined}
 */
function expirationOf(item) {
  return item.key_expiration ?? item.keyExpiration;
}

/**
 * Compact meta chips: user label, trust, approval/revoked, expires, key ID.
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function keyMetaChipsHtml(item) {
  const fp = String(item.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  /** @type {string[]} */
  const chips = [];

  const userLabel = userLabelOf(item);
  if (userLabel) {
    chips.push(
      `<span class="key-chip key-chip-label" title="Friendly label (claimer-set)">${escapeHtml(
        userLabel
      )}</span>`
    );
  }

  const trust = trustBadgeHtml(fp);
  if (trust) chips.push(trust);

  if (item.revoked) {
    chips.push(
      `<span class="key-chip key-chip-revoked" title="Key is revoked">revoked</span>`
    );
  } else {
    const state = item.approval_state || item.approvalState || "";
    if (state && state !== "approved") {
      chips.push(
        `<span class="key-chip key-chip-state">${escapeHtml(state)}</span>`
      );
    }
  }

  const exp = describeExpiry(expirationOf(item) || null);
  if (exp.tone === "expired") {
    chips.push(
      `<span class="key-chip key-chip-expiry expired" title="${escapeHtml(
        exp.absolute
      )}">${escapeHtml(exp.relative || "Expired")}</span>`
    );
  } else if (exp.tone === "warn") {
    chips.push(
      `<span class="key-chip key-chip-expiry warn" title="${escapeHtml(
        exp.absolute
      )}">${escapeHtml(exp.relative)}</span>`
    );
  } else if (expirationOf(item)) {
    chips.push(
      `<span class="key-chip key-chip-expiry" title="${escapeHtml(
        exp.absolute
      )}">${escapeHtml(exp.relative || exp.absolute)}</span>`
    );
  } else {
    chips.push(
      `<span class="key-chip key-chip-expiry none" title="Does not expire">no expiry</span>`
    );
  }

  const kid = shortKeyId(item);
  if (kid) {
    chips.push(
      `<span class="key-chip key-chip-kid mono" title="Key ID">…${escapeHtml(
        kid
      )}</span>`
    );
  }

  if (!chips.length) return "";
  return `<span class="hit-meta">${chips.join("")}</span>`;
}

/**
 * Full dropdown / list-row markup for a search hit.
 * @param {KeyHitItem} item
 * @param {{
 *   already?: boolean,
 *   disabled?: boolean,
 *   dataAttrs?: Record<string, string>,
 *   showApprovalBadge?: boolean,
 *   className?: string,
 * }} [opts]
 * @returns {string}
 */
export function keyHitHtml(item, opts = {}) {
  const fp = String(item.fingerprint || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const label = primaryUidLabel(item);
  const already = !!opts.already;
  const disabled = !!opts.disabled || already;
  const showApproval = opts.showApprovalBadge !== false;
  const state = item.approval_state || item.approvalState || "";
  const data = opts.dataAttrs || {};
  const dataStr = Object.entries(data)
    .map(([k, v]) => `${k}="${escapeHtml(v)}"`)
    .join(" ");
  const cls = ["recipient-hit", opts.className || ""].filter(Boolean).join(" ");

  let approvalBadge = "";
  if (showApproval && state) {
    const badgeCls =
      state === "approved"
        ? "badge approved"
        : state === "pending" || state === "expired"
          ? "badge pending"
          : "badge";
    approvalBadge = `<span class="${badgeCls}">${escapeHtml(state)}</span>`;
  }

  return `<button type="button" class="${cls}" ${dataStr} ${
    disabled ? "disabled" : ""
  }>
    <span class="hit-main">
      <span class="hit-label">${escapeHtml(label)}</span>
      <code class="hit-fpr muted">${escapeHtml(formatFingerprint(fp))}</code>
      ${keyMetaChipsHtml(item)}
    </span>
    ${approvalBadge}
    ${already ? `<span class="muted">Added</span>` : ""}
  </button>`;
}

/**
 * Extra chips for selected recipient pills (user label + expiry).
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function keyPillExtrasHtml(item) {
  /** @type {string[]} */
  const parts = [];
  const userLabel = userLabelOf(item);
  if (userLabel) {
    parts.push(
      `<span class="key-chip key-chip-label" title="Friendly label">${escapeHtml(
        userLabel
      )}</span>`
    );
  }
  const exp = describeExpiry(expirationOf(item) || null);
  if (exp.tone === "expired" || exp.tone === "warn") {
    parts.push(
      `<span class="key-chip key-chip-expiry ${exp.tone}" title="${escapeHtml(
        exp.absolute
      )}">${escapeHtml(exp.relative)}</span>`
    );
  } else if (expirationOf(item) && exp.relative) {
    parts.push(
      `<span class="key-chip key-chip-expiry" title="${escapeHtml(
        exp.absolute
      )}">${escapeHtml(exp.relative)}</span>`
    );
  }
  const kid = shortKeyId(item);
  if (kid) {
    parts.push(
      `<span class="key-chip key-chip-kid mono" title="Key ID">…${escapeHtml(
        kid
      )}</span>`
    );
  }
  return parts.join("");
}

/**
 * Short expiry cell text for tables.
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function expiryCellText(item) {
  const raw = expirationOf(item);
  if (!raw) return "—";
  const exp = describeExpiry(raw);
  if (exp.tone === "expired") return exp.relative || "Expired";
  if (exp.relative) return exp.relative;
  return exp.absolute;
}

export { uidEmail };
