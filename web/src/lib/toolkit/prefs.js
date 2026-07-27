/**
 * Toolkit UI preferences (localStorage). Separate from FIPS mode key.
 */

export const TOOLKIT_PREFS_KEY = "basilisk.toolkit.prefs";

/**
 * @typedef {object} ToolkitPrefs
 * @property {number} idleClearMinutes  0 = never; else minutes until Clear sensitive
 * @property {"separate"|"combined"} defaultEncryptMode
 * @property {"ask"|"one"|"all"} defaultEncryptPolicy
 * @property {boolean} collapseAdvanced  collapse Cipher/Wrap/WebAuthn by default
 * @property {boolean} sessionOff  unlock without writing vault-session (per-run only)
 */

/** @type {ToolkitPrefs} */
export const DEFAULT_TOOLKIT_PREFS = {
  idleClearMinutes: 5,
  defaultEncryptMode: "separate",
  defaultEncryptPolicy: "ask",
  collapseAdvanced: true,
  sessionOff: false,
};

/** @type {ToolkitPrefs|null} */
let _memory = null;

/**
 * @param {Partial<ToolkitPrefs>|null|undefined} raw
 * @returns {ToolkitPrefs}
 */
export function normalizeToolkitPrefs(raw) {
  const base = { ...DEFAULT_TOOLKIT_PREFS, ...(raw || {}) };
  const idle = Number(base.idleClearMinutes);
  base.idleClearMinutes = [0, 1, 5, 15, 60].includes(idle) ? idle : 5;
  base.defaultEncryptMode =
    base.defaultEncryptMode === "combined" ? "combined" : "separate";
  base.defaultEncryptPolicy = ["ask", "one", "all"].includes(
    String(base.defaultEncryptPolicy)
  )
    ? /** @type {"ask"|"one"|"all"} */ (base.defaultEncryptPolicy)
    : "ask";
  base.collapseAdvanced = !!base.collapseAdvanced;
  base.sessionOff = !!base.sessionOff;
  return base;
}

/**
 * @returns {ToolkitPrefs}
 */
export function getToolkitPrefs() {
  if (_memory) return { ..._memory };
  try {
    if (typeof localStorage === "undefined") {
      return { ...DEFAULT_TOOLKIT_PREFS };
    }
    const raw = localStorage.getItem(TOOLKIT_PREFS_KEY);
    if (!raw) return { ...DEFAULT_TOOLKIT_PREFS };
    _memory = normalizeToolkitPrefs(JSON.parse(raw));
    return { ..._memory };
  } catch {
    return { ...DEFAULT_TOOLKIT_PREFS };
  }
}

/**
 * @param {Partial<ToolkitPrefs>} patch
 * @returns {ToolkitPrefs}
 */
export function setToolkitPrefs(patch) {
  const next = normalizeToolkitPrefs({ ...getToolkitPrefs(), ...patch });
  _memory = next;
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(TOOLKIT_PREFS_KEY, JSON.stringify(next));
    }
  } catch {
    /* private mode */
  }
  return { ...next };
}

/** Idle clear delay in ms (0 = disabled). */
export function getIdleClearMs() {
  const mins = getToolkitPrefs().idleClearMinutes;
  return mins > 0 ? mins * 60 * 1000 : 0;
}
