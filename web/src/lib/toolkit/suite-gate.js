/**
 * Map toolkit toolboxes → CAST verification suites and enforce FIPS mode.
 */

import { getStep } from "./registry.js";

/** @typedef {'openpgp'|'webcrypto'|'sss'|'age'} CryptoSuite */
/** @typedef {'verified'|'unverified'|'error'} SuiteState */
/**
 * `age` is optional, and deliberately so. It arrived after the other three, and
 * callers that build a status map by hand — `engine.js`'s
 * `unverifiedSuiteStatus()`, the fixtures in the test suite — still write three
 * keys. Requiring a fourth would not make those callers more honest, it would
 * only make them not compile.
 *
 * The omission is safe because every read below is a `!== "verified"` or a
 * `|| "unverified"`: an absent `age` reads as unverified, so a caller that has
 * not been taught about the suite refuses age ops rather than admitting them.
 * `getSuiteStatus()` in `crypto-self-test.js` always sets it.
 * @typedef {{ openpgp: SuiteState, webcrypto: SuiteState, sss: SuiteState, age?: SuiteState }} SuiteStatusMap
 */

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
  // `jose` and `otp` for the same reason, and they were missing it. A JOSE op
  // reaches SubtleCrypto through `webcrypto-ops.js` twelve times over and
  // touches OpenPGP not at all; HOTP's counter is `crypto.subtle.sign("HMAC")`
  // in `lib/otp/hotp.js`. Both are the WebCrypto suite doing WebCrypto's work
  // under another toolbox's name — so with the switch on and `webcrypto`
  // unverified, a JWT or a TOTP ran while an `aes-gcm` cell beside it was
  // refused. `suitesUsedBySteps` reported nothing for them, so nothing this
  // file does could reach them.
  if (tb === "jose") return "webcrypto";
  if (tb === "otp") return "webcrypto";
  if (tb === "sss") return "sss";
  // `age` is its own suite, not `webcrypto`. It used to fall through below with
  // a note saying it was a real gap that only a CAST could close, and that note
  // was right: its math is the third-party `age-encryption` package, so naming
  // `webcrypto` here would have had the self-test vouch for primitives it never
  // ran. The CAST now exists — CAST-15 in `crypto-self-test.js`, a decrypt
  // known-answer test against the age project's published testkit vector plus
  // the spec's recipient-derivation pair — so there is something qualifying the
  // toolbox and this entry names it. The suite is `age` rather than a borrowed
  // name precisely so the claim stays the size of the evidence.
  if (tb === "age") return "age";
  // ── The fall-throughs, each on purpose and each for a different reason ──
  //
  // `agent` is polymorphic and cannot honestly name one suite: `agent.sign`
  // emits an OpenPGP signature for a PGP key and an sshsig for an SSH key, so
  // either answer is false on one branch. The suite is a property of the key
  // the vault hands back, not of the op.
  //
  // `quorum`'s session crypto — ECDH, HKDF, AES-GCM in `lib/notebook/crypto.js`
  // — is not CAST-gated today, which `docs/CRYPTOGRAPHY.md` states outright.
  //
  // `webauthn` falls through here on purpose, and the fall-through is the
  // whole of FIPS mode's position on it: there is no suite to name, so
  // `suitesUsedBySteps` never reports one, so nothing this file does can
  // block a webauthn op. Nor could it honestly — a passkey's keypair lives
  // inside an authenticator this page cannot address, so there is no vector
  // to run and no result to gate on. Anything upstream that shows WebAuthn
  // beside the four suites above is showing a capability, not a
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
