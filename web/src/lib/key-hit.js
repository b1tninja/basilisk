/**
 * Shared rich key-hit rendering for search results and recipient pickers.
 * Surfaces label, trust, origin and expiry so similar keys can be told apart.
 *
 * **The chips tell keys apart by facts about them, never by part of one.** A
 * `shortKeyId` used to sit here printing `…6AD01388` under the caption "Key ID",
 * in the search results of the page whose own copy reads "Short (8-character)
 * key IDs are collision-prone. Confirm the full fingerprint out of band before
 * trusting a key" — the contradiction `components/ui/fingerprint.tsx` was built
 * to end, arriving from a second direction. Thirty-two bits is the length that
 * was forged wholesale in 2016, and it was the one string on the row short
 * enough to read aloud, so it is the one a reader would have compared.
 *
 * Nothing replaced it, because nothing needed to: all three consumers —
 * `keyHitHtml` below, the pills in `recipient-picker.js` and the table in
 * `keys.js` — already print `formatFingerprint` of the whole value on the same
 * row. The chip was a shorter, checkable-looking spelling of the value directly
 * beside it. The 64-bit `key_id` these records carry is still derived and still
 * correct; it indexes vault entries and HKP lookups, and it is not an identity
 * to put in front of a person.
 * @module lib/key-hit
 */

import { getTrust, trustBadgeHtml } from "./trust.js";
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
 *   origin?: string,
 *   source_keyserver?: string,
 *   sourceKeyserver?: string,
 *   cached?: boolean,
 * }} KeyHitItem
 */

/**
 * Origin chip when the key is not from the org Basilisk directory alone.
 * @param {KeyHitItem} item
 * @returns {string}
 */
export function originChipHtml(item) {
  const origin = String(item.origin || "").toLowerCase();
  const host = String(
    item.source_keyserver || item.sourceKeyserver || ""
  ).toLowerCase();
  if (origin === "upstream" || (host && origin !== "basilisk")) {
    const label = host || "upstream";
    return `<span class="key-chip key-chip-origin" title="Fetched from external keyserver (not org-approved)">${escapeHtml(
      label
    )}</span>`;
  }
  if (origin === "import") {
    return `<span class="key-chip key-chip-origin" title="Imported locally">local import</span>`;
  }
  return "";
}

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
 * @param {KeyHitItem} item
 * @returns {string|null|Date|undefined}
 */
function expirationOf(item) {
  return item.key_expiration ?? item.keyExpiration;
}

/**
 * Compact meta chips: user label, trust, origin, approval/revoked, expires.
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

  const origin = originChipHtml(item);
  if (origin) chips.push(origin);

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
  const trustLevel = getTrust(fp)?.level;
  const trustedCls = trustLevel === "trusted" ? "key-hit-trusted" : "";
  const cls = ["recipient-hit", trustedCls, opts.className || ""]
    .filter(Boolean)
    .join(" ");

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
  const origin = originChipHtml(item);
  if (origin) parts.push(origin);
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
