/**
 * "Is the code in this tab the code it should be?" — the verdict model.
 *
 * `docs/THREAT-MODEL.md` opens with the problem this addresses and then tells
 * the reader to check `/integrity/module-roots.json` against the SRI hashes in
 * the HTML by hand. `lib/module-integrity.js` has done that check on every page
 * load for some time; what did not exist was anywhere for a person to *see* the
 * answer. This module is that answer, in words.
 *
 * ## It does not re-implement the check
 *
 * The comparison is `verifyModuleRootAgainstPins`, unchanged — the same
 * function the boot path gates on. Two implementations of a security check
 * drift, and the one that drifts is always the one people read. Everything
 * here is presentation: mapping one result onto the state a person is actually
 * in, and saying what that state does and does not prove.
 *
 * ## The state that matters is "cannot verify", not "verified"
 *
 * Four of the six states are some flavour of *no answer*: no SRI on the page
 * at all (the dev server), no pin document configured (an unsigned build),
 * pins configured but unreachable (offline, or a blocked fetch), and mirrors
 * that disagree with each other. Those are the common cases and they are the
 * ones a green tick would misrepresent, so each gets its own wording and none
 * of them is `ok`.
 *
 * ## And the honest limit, stated on the surface
 *
 * This check runs in the page it is checking. A server that served tampered
 * code can serve a tampered checker, and it will report success. The check has
 * real value against a *partial* compromise — a swapped chunk, a poisoned CDN
 * edge, a stale cache — and no value against a coherent one. `LIMIT_NOTE` is
 * that sentence, kept here beside the verdicts so it cannot be quietly dropped
 * from the UI while the verdicts stay confident.
 *
 * @module lib/toolkit/deployment-check
 */

import {
  computeLoadedModulesRoot,
  pageKeyFromPath,
  resolveIntegrityPinUrls,
  verifyModuleRootAgainstPins,
} from "../module-integrity.js";

/**
 * @typedef {"checking"|"verified"|"mismatch"|"disagree"|"unreachable"|"unpinned"|"no-sri"}
 *   DeploymentStatus
 */

/**
 * @typedef {object} DeploymentVerdict
 * @property {DeploymentStatus} status
 * @property {"ok"|"error"|"warn"|"pending"} tone
 * @property {string} headline
 * @property {string} detail
 * @property {string} root         Merkle root computed from what this page loaded
 * @property {string} expectedRoot root the pin document claims, "" when unknown
 * @property {number} leafCount
 * @property {string} pageKey
 * @property {string[]} pinUrls
 * @property {number} fetched      how many pin documents were read
 * @property {string} raw          the underlying check's own message
 */

/**
 * The sentence that must appear wherever a verdict does.
 *
 * Deliberately not softened. A person deciding whether to do something
 * irreversible in a browser needs to know that a green result here is evidence,
 * not proof, and that the only check with no served-code question in it is the
 * one they run outside the browser.
 */
export const LIMIT_NOTE =
  "This check runs inside the page it is checking. It catches a swapped module, a " +
  "poisoned cache, or one CDN edge out of step — it cannot catch a server that " +
  "served you a tampered checker along with tampered code. For anything " +
  "unrecoverable, verify outside the browser: fetch the pin document yourself, or " +
  "run the recipe through the CLI, where there is no served-code question at all.";

/**
 * @param {string} root
 * @returns {string}
 */
export function shortRoot(root) {
  const hex = String(root || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
  return hex ? `${hex.slice(0, 16)}…` : "—";
}

/**
 * Run the check and turn the result into something a person can act on.
 *
 * @param {{ document?: Document|null, pinUrls?: string[] }} [opts]
 * @returns {Promise<DeploymentVerdict>}
 */
export async function checkDeployment(opts = {}) {
  const doc = opts.document === undefined ? globalThis.document : opts.document;
  const integrity = await computeLoadedModulesRoot({ document: doc });
  const explicit =
    doc?.querySelector?.('meta[name="basilisk-integrity-page"]')?.getAttribute("content") ||
    "";
  const pageKey = pageKeyFromPath(globalThis.location?.pathname || "", explicit);
  const pinUrls = opts.pinUrls || resolveIntegrityPinUrls(doc, []);

  /** @type {DeploymentVerdict} */
  const base = {
    status: "no-sri",
    tone: "warn",
    headline: "",
    detail: "",
    root: integrity.root,
    expectedRoot: "",
    leafCount: integrity.leafCount,
    pageKey,
    pinUrls,
    fetched: 0,
    raw: "",
  };

  // No SRI on the page means there is nothing to fold into a root, so a pin
  // comparison would be comparing a fallback digest of one module against a
  // build artifact. Stop before that produces a confident-looking answer.
  if (integrity.source !== "sri") {
    return {
      ...base,
      // Blanked deliberately. With no SRI on the page `computeLoadedModulesRoot`
      // falls back to hashing its *own* module bytes, which produces a
      // perfectly well-formed 64-hex root over exactly one file. Rendered in a
      // row labelled "Loaded root" beside a verdict saying nothing could be
      // checked, that number is worse than useless: it looks like the thing a
      // careful reader is supposed to compare against another machine, and it
      // is not. Caught in the widget catalog on the live dev server, which is
      // the only place this combination occurs.
      root: "",
      leafCount: 0,
      status: "no-sri",
      tone: "warn",
      headline: "Cannot verify — this page carries no integrity hashes.",
      detail:
        "Nothing on it declares an SRI digest, so there is no set of module hashes to " +
        "check. That is normal on the dev server, which serves unhashed modules and a " +
        "looser Content-Security-Policy than production. If you are seeing this on a " +
        "deployed origin, the build that produced it did not run the integrity step, " +
        "and none of the guarantees in the threat model's first section apply to it.",
    };
  }

  const pin = await verifyModuleRootAgainstPins(integrity.root, {
    document: doc,
    pageKey,
    pinUrls,
  });
  const out = {
    ...base,
    expectedRoot: pin.expectedRoot,
    fetched: pin.fetched,
    raw: pin.message,
  };

  if (!pinUrls.length) {
    return {
      ...out,
      status: "unpinned",
      tone: "warn",
      headline: "Cannot verify — no pin document is configured.",
      detail:
        `The ${integrity.leafCount} modules this page loaded fold to root ${shortRoot(integrity.root)}, ` +
        "and the browser did enforce their individual SRI hashes — a modified module would " +
        "have failed to execute. What is missing is anything independent to compare the " +
        "root against, so this number attests to nothing but itself. Write it down and " +
        "compare it with another machine, or another person, if that matters to you.",
    };
  }

  if (!pin.fetched) {
    return {
      ...out,
      status: "unreachable",
      tone: "error",
      headline: "Cannot verify — the pin document could not be read.",
      detail:
        `${pin.message} A blocked or offline fetch looks exactly like a suppressed one. ` +
        "Treat this as unverified rather than as fine: the check that would have caught " +
        "tampering is the check that did not run.",
    };
  }

  if (/disagree/i.test(pin.message)) {
    return {
      ...out,
      status: "disagree",
      tone: "error",
      headline: "The pin mirrors do not agree with each other.",
      detail:
        `${pin.message} Mirrors exist so that subverting one host is not enough; two ` +
        "answers means either a deploy caught mid-flight or one of them is lying, and " +
        "from here those look identical. Do not use this tab for anything sensitive " +
        "until the mirrors converge.",
    };
  }

  if (!pin.ok || !pin.matched) {
    return {
      ...out,
      status: "mismatch",
      tone: "error",
      headline: "The code in this tab is not the code the pin describes.",
      detail:
        `${pin.message} This is the failure the whole mechanism exists to make visible. ` +
        "It can be a stale cache or a half-finished deploy — those are the boring " +
        "explanations and they are the common ones — but it is indistinguishable from " +
        "the interesting one. Close the tab, clear the cache, and load it again; if the " +
        "root still differs, do not enter key material into this page.",
    };
  }

  return {
    ...out,
    status: "verified",
    tone: "ok",
    headline: `Matches the published pin for ${pageKey}.`,
    detail:
      `${integrity.leafCount} modules loaded, folding to root ${shortRoot(integrity.root)}, and ` +
      `${pin.fetched} pin ${pin.fetched === 1 ? "document agrees" : "documents agree"}. ` +
      "The browser separately enforced each module's own SRI hash on load, so nothing " +
      "outside this set executed.",
  };
}
