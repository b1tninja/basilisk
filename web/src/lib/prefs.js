/**
 * Non-sensitive UI preferences (localStorage).
 */

const EXPERT_KEY = "basilisk.expertMode";

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
