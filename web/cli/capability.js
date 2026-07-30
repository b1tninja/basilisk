/**
 * Capability honesty for the headless CLI.
 *
 * Basilisk is a browser notebook. Node ships WebCrypto, so the crypto core of
 * the registry runs headlessly unchanged — but a sizeable minority of ops are
 * bound to browser surfaces that Node simply does not have (RTCPeerConnection,
 * navigator.credentials, navigator.clipboard, the IndexedDB vault). Those must
 * fail saying *which step* and *what is missing*, never as a bare
 * `ReferenceError: RTCPeerConnection is not defined` three frames deep.
 *
 * Two mechanisms, in this order:
 *
 *  1. **Pre-flight, registry-derived.** The only static rule is the `webrtc`
 *     toolbox, read off `getStep().toolbox` — every op in it is documented
 *     main-thread-only in `quorum-ops.js` / `rtc-ops.js`, and any op added to
 *     that toolbox later is covered without editing this file. There is no
 *     hand-maintained list of op names anywhere here.
 *
 *  2. **Dispatch-time interception.** Everything else is caught by *running*
 *     it and classifying the failure against a vocabulary of browser globals.
 *     That vocabulary is small and stable; the set of ops it covers is not
 *     enumerated at all, so it cannot go stale. `clipboard.write` already
 *     throws "Clipboard API unavailable in this context"; `agent.unlock`
 *     reaches IndexedDB and dies on `indexedDB is not defined`. Both come out
 *     of here as the same shaped message.
 *
 * Probes are evaluated live rather than cached, so a host that *does* provide
 * a surface (jsdom, Electron, a polyfill) is believed instead of second-guessed.
 * @module cli/capability
 */

import { getStep } from "../src/lib/toolkit/registry.js";

/**
 * @typedef {object} BrowserCapability
 * @property {string} id
 * @property {string} label     human name shown in the error
 * @property {() => boolean} probe  live check against the current global scope
 */

/** @type {Record<string, BrowserCapability>} */
export const BROWSER_CAPABILITIES = {
  webrtc: {
    id: "webrtc",
    label: "WebRTC (RTCPeerConnection)",
    probe: () => typeof RTCPeerConnection === "function",
  },
  credentials: {
    id: "credentials",
    label: "WebAuthn (navigator.credentials)",
    probe: () =>
      typeof navigator !== "undefined" && !!(/** @type {*} */ (navigator).credentials),
  },
  clipboard: {
    id: "clipboard",
    label: "Clipboard API (navigator.clipboard)",
    probe: () =>
      typeof navigator !== "undefined" &&
      !!(/** @type {*} */ (navigator).clipboard?.writeText),
  },
  storage: {
    id: "storage",
    label: "IndexedDB key vault",
    probe: () => typeof indexedDB !== "undefined",
  },
  dom: {
    id: "dom",
    label: "DOM (window / document)",
    probe: () => typeof window !== "undefined" && typeof document !== "undefined",
  },
};

/**
 * Toolbox → capability. Derived attribution, registry-keyed: any op that lands
 * in one of these toolboxes inherits the requirement without an edit here.
 *
 * Only toolboxes that are *uniformly* browser-bound qualify. `webrtc` is (all
 * of it is documented main-thread-only in `quorum-ops.js` / `rtc-ops.js`), and
 * `agent` is (every op reads or writes the IndexedDB key vault). `webauthn` is
 * deliberately absent: it also holds pure parsers — `webauthn.attest` decodes
 * pasted attestation bytes and works fine headlessly — so blocking the whole
 * toolbox on a family resemblance would be a lie in the other direction. The
 * ceremony ops in it are caught by dispatch interception instead, which is
 * exact by construction.
 * @type {Record<string, string>}
 */
const TOOLBOX_CAPABILITY = {
  webrtc: "webrtc",
  agent: "storage",
};

/**
 * Browser globals whose absence means "this op wanted a browser".
 * A vocabulary of surfaces, not a list of ops.
 * @type {Record<string, string>}
 */
const GLOBAL_TO_CAPABILITY = {
  RTCPeerConnection: "webrtc",
  RTCCertificate: "webrtc",
  RTCDataChannel: "webrtc",
  navigator: "dom",
  window: "dom",
  document: "dom",
  indexedDB: "storage",
  localStorage: "storage",
  sessionStorage: "storage",
  PublicKeyCredential: "credentials",
  CredentialsContainer: "credentials",
};

/** Phrases the ops themselves use when they detect their surface is missing. */
const MESSAGE_SIGNATURES = [
  { re: /WebRTC unavailable in this context/i, cap: "webrtc" },
  { re: /RTCPeerConnection/i, cap: "webrtc" },
  { re: /Clipboard API unavailable/i, cap: "clipboard" },
  { re: /no permission surface registered/i, cap: "clipboard" },
  { re: /navigator\.credentials/i, cap: "credentials" },
  { re: /indexedDB|IDBFactory/i, cap: "storage" },
];

/**
 * @param {string} id
 * @returns {BrowserCapability|null}
 */
function capability(id) {
  return BROWSER_CAPABILITIES[id] || null;
}

/**
 * Static, registry-derived pre-flight: which steps of this chain need a
 * browser surface the current host does not have.
 *
 * @param {{ name?: string }[]} steps
 * @param {number} [cellIndex] 0-based cell, for the message
 * @returns {{ stepIndex: number, step: string, capability: BrowserCapability, cellIndex: number }[]}
 */
export function browserOnlySteps(steps, cellIndex = 0) {
  /** @type {{ stepIndex: number, step: string, capability: BrowserCapability, cellIndex: number }[]} */
  const found = [];
  const walk = (/** @type {*[]} */ list) => {
    list.forEach((step, i) => {
      if (!step?.name) return;
      const spec = getStep(step.name);
      const capId = spec ? TOOLBOX_CAPABILITY[String(spec.toolbox || "")] : null;
      if (capId) {
        const cap = capability(capId);
        if (cap && !cap.probe()) {
          found.push({ stepIndex: i, step: String(step.name), capability: cap, cellIndex });
        }
      }
      // Blocks carry bodies/branches; a browser-only op hides in them too.
      if (Array.isArray(step.body)) walk(step.body);
      for (const br of step.branches || []) {
        if (Array.isArray(br?.body)) walk(br.body);
      }
    });
  };
  walk(steps || []);
  return found;
}

/**
 * Classify a thrown error as a missing browser surface, or null when it is an
 * ordinary failure (bad passphrase, wrong key, empty input).
 * @param {unknown} err
 * @returns {BrowserCapability|null}
 */
export function classifyBrowserFailure(err) {
  const message = String(/** @type {*} */ (err)?.message ?? err ?? "");
  if (!message) return null;

  // `ReferenceError: X is not defined` — the raw shape we exist to replace.
  const ref = /(?:^|\s)(\w+) is not defined/.exec(message);
  if (ref && GLOBAL_TO_CAPABILITY[ref[1]]) {
    return capability(GLOBAL_TO_CAPABILITY[ref[1]]);
  }
  // `Cannot read properties of undefined (reading 'credentials')` and friends.
  const prop = /reading '(\w+)'/.exec(message);
  if (prop && GLOBAL_TO_CAPABILITY[prop[1]]) {
    return capability(GLOBAL_TO_CAPABILITY[prop[1]]);
  }
  for (const sig of MESSAGE_SIGNATURES) {
    if (sig.re.test(message)) {
      const cap = capability(sig.cap);
      // Believe the probe over the phrase: if the surface is actually present,
      // the failure was about something else.
      if (cap && !cap.probe()) return cap;
    }
  }
  return null;
}

/**
 * The one message shape. Always names the step; never a bare stack.
 * @param {{ step: string, capability: BrowserCapability, cellIndex?: number, stepIndex?: number }} hit
 */
export function browserOnlyMessage(hit) {
  const where =
    hit.stepIndex != null && hit.stepIndex >= 0
      ? ` (cell ${(hit.cellIndex ?? 0) + 1}, step ${hit.stepIndex + 1})`
      : ` (cell ${(hit.cellIndex ?? 0) + 1})`;
  return (
    `browser-only op: "${hit.step}"${where} needs ${hit.capability.label}, ` +
    `which this Node process does not provide. Run this recipe in the Basilisk toolkit page instead.`
  );
}

/** Error carrying a browser-only diagnosis, so the CLI can exit distinctly. */
export class BrowserOnlyError extends Error {
  /**
   * @param {{ step: string, capability: BrowserCapability, cellIndex?: number, stepIndex?: number }} hit
   * @param {unknown} [cause]
   */
  constructor(hit, cause) {
    super(browserOnlyMessage(hit));
    this.name = "BrowserOnlyError";
    this.step = hit.step;
    this.capability = hit.capability.id;
    this.cause = cause;
  }
}
