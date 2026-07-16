/**
 * Non-sensitive UI preferences (localStorage).
 *
 * Two separate labelling concepts:
 *   - Key label  : public, owner-settable, stored server-side.
 *   - Device label: private, owner-settable, stored in localStorage only.
 *     Keyed by fingerprint + optional card key-ref so multiple physical
 *     hardware tokens holding the same key can be distinguished without
 *     exposing the card serial number to the keyserver.
 */

const EXPERT_KEY = "basilisk.expertMode";
const DEVICE_LABEL_PREFIX = "basilisk.deviceLabel.";

/**
 * @returns {boolean}
 */
export function getExpertMode() {
  try {
    return localStorage.getItem(EXPERT_KEY) === "1";
  } catch (_) {
    return false;
  }
}

/**
 * @param {boolean} on
 */
export function setExpertMode(on) {
  try {
    localStorage.setItem(EXPERT_KEY, on ? "1" : "0");
  } catch (_) {
    /* private mode / quota — ignore */
  }
}

// ---------------------------------------------------------------------------
// Device labels — client-side only, never sent to the server.
// ---------------------------------------------------------------------------

/**
 * Build the localStorage key for a device label.
 * @param {string} fpr  - Full 40-char fingerprint (case-insensitive).
 * @param {string} [keyref] - Card key-ref slot, e.g. "OPENPGP.1" (optional).
 * @returns {string}
 */
function deviceLabelKey(fpr, keyref = "") {
  const base = `${DEVICE_LABEL_PREFIX}${fpr.toUpperCase()}`;
  return keyref ? `${base}.${keyref}` : base;
}

/**
 * Retrieve the device label for a fingerprint / card slot.
 * Returns an empty string if none is set.
 * @param {string} fpr
 * @param {string} [keyref]
 * @returns {string}
 */
export function getDeviceLabel(fpr, keyref = "") {
  try {
    return localStorage.getItem(deviceLabelKey(fpr, keyref)) || "";
  } catch (_) {
    return "";
  }
}

/**
 * Persist a device label for a fingerprint / card slot.
 * Pass an empty string or null to clear the label.
 * @param {string} fpr
 * @param {string} [keyref]
 * @param {string|null} label
 */
export function setDeviceLabel(fpr, keyref = "", label) {
  try {
    const k = deviceLabelKey(fpr, keyref);
    if (label && label.trim()) {
      localStorage.setItem(k, label.trim().slice(0, 200));
    } else {
      localStorage.removeItem(k);
    }
  } catch (_) {
    /* private mode / storage quota — ignore */
  }
}

/**
 * Return all stored device labels as an array of { fpr, keyref, label } objects.
 * Useful for displaying a summary of all labelled devices.
 * @returns {{ fpr: string, keyref: string, label: string }[]}
 */
export function listDeviceLabels() {
  const out = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k || !k.startsWith(DEVICE_LABEL_PREFIX)) continue;
      const rest = k.slice(DEVICE_LABEL_PREFIX.length);
      const dotIdx = rest.indexOf(".");
      const fpr = dotIdx >= 0 ? rest.slice(0, dotIdx) : rest;
      const keyref = dotIdx >= 0 ? rest.slice(dotIdx + 1) : "";
      const label = localStorage.getItem(k) || "";
      if (label) out.push({ fpr, keyref, label });
    }
  } catch (_) {
    /* private mode */
  }
  return out;
}
