/**
 * Map toolkit toolboxes → CAST verification suites and enforce FIPS mode.
 */

import { getStep } from "./registry.js";

/** @typedef {'openpgp'|'webcrypto'|'sss'} CryptoSuite */
/** @typedef {'verified'|'unverified'|'error'} SuiteState */
/** @typedef {{ openpgp: SuiteState, webcrypto: SuiteState, sss: SuiteState }} SuiteStatusMap */

/**
 * @param {string|undefined|null} toolbox
 * @returns {CryptoSuite|null}  null = non-crypto toolbox (no CAST claim)
 */
export function toolboxToSuite(toolbox) {
  const tb = String(toolbox || "");
  if (tb === "openpgp") return "openpgp";
  if (tb === "webcrypto") return "webcrypto";
  // SSH's math is SubtleCrypto/@noble — the suite the self-test actually
  // qualifies. The encodings are not CAST's job; they get interop fixtures
  // and verb smoke instead (§29g).
  if (tb === "ssh") return "webcrypto";
  if (tb === "sss") return "sss";
  // `webauthn` falls through here on purpose, and the fall-through is the
  // whole of FIPS mode's position on it: there is no suite to name, so
  // `suitesUsedBySteps` never reports one, so nothing this file does can
  // block a webauthn op. Nor could it honestly — a passkey's keypair lives
  // inside an authenticator this page cannot address, so there is no vector
  // to run and no result to gate on. Anything upstream that shows WebAuthn
  // beside the three suites above is showing a capability, not a
  // verification, and must not say "verified" or add it to their count.
  return null;
}

/**
 * @param {string} stepName
 * @returns {CryptoSuite|null}
 */
export function stepNameToSuite(stepName) {
  const spec = getStep(stepName);
  return toolboxToSuite(spec?.toolbox);
}

/**
 * @param {import("./recipe.js").RecipeStep[]|undefined} steps
 * @returns {CryptoSuite[]}
 */
export function suitesUsedBySteps(steps) {
  /** @type {Set<CryptoSuite>} */
  const used = new Set();
  for (const step of steps || []) {
    const suite = stepNameToSuite(step.name);
    if (suite) used.add(suite);
    if (step.body?.length) {
      for (const s of suitesUsedBySteps(step.body)) used.add(s);
    }
  }
  return [...used];
}

/**
 * @param {import("./recipe.js").RecipeAst|null|undefined} ast
 * @returns {CryptoSuite[]}
 */
export function suitesUsedByAst(ast) {
  const steps = (ast?.chains || []).flatMap((c) => c.steps || []);
  return suitesUsedBySteps(steps.length ? steps : ast?.steps);
}

/**
 * @param {SuiteStatusMap} status
 * @param {CryptoSuite[]} suites
 * @returns {CryptoSuite[]}
 */
export function unverifiedSuitesAmong(status, suites) {
  return suites.filter((s) => status[s] !== "verified");
}

/**
 * Human list of step names blocked by FIPS for an unverified suite.
 * @param {import("./recipe.js").RecipeStep[]} steps
 * @param {CryptoSuite[]} blockedSuites
 * @returns {string[]}
 */
export function stepNamesInSuites(steps, blockedSuites) {
  const block = new Set(blockedSuites);
  /** @type {string[]} */
  const names = [];
  for (const step of steps || []) {
    const suite = stepNameToSuite(step.name);
    if (suite && block.has(suite)) names.push(step.name);
    if (step.body?.length) {
      names.push(...stepNamesInSuites(step.body, blockedSuites));
    }
  }
  return [...new Set(names)];
}

/**
 * When FIPS mode is on, throw if the recipe uses any unverified suite.
 * @param {import("./recipe.js").RecipeAst|null|undefined} ast
 * @param {SuiteStatusMap} status
 * @param {boolean} fipsMode
 */
export function assertRecipeAllowedUnderFips(ast, status, fipsMode) {
  if (!fipsMode) return;
  const used = suitesUsedByAst(ast);
  const bad = unverifiedSuitesAmong(status, used);
  if (!bad.length) return;
  const allSteps = (ast?.chains || []).flatMap((c) => c.steps || []);
  const ops = stepNamesInSuites(allSteps.length ? allSteps : ast?.steps || [], bad);
  const suiteList = bad.join(", ");
  const opList = ops.length ? ops.join(", ") : "(unknown)";
  throw new Error(
    `FIPS mode: recipe uses unverified ${suiteList} ops (${opList})`
  );
}

/**
 * @param {string|undefined|null} toolbox
 * @param {SuiteStatusMap} status
 * @returns {'verified'|'unverified'|'none'|'error'}
 */
export function toolboxVerification(toolbox, status) {
  const suite = toolboxToSuite(toolbox);
  if (!suite) return "none";
  return status[suite] || "unverified";
}
