/**
 * Toolkit step registry — single source of truth for steps, params, docs, and
 * input/output types. Drives the parser, builder, autocomplete, and Reference panel.
 *
 * Modeled on CyberChef's Operation metadata (name / description / inputType /
 * outputType / typed args / flowControl).
 */

/** @typedef {"none"|"bytes"|"text"|"key"|"keypair"|"shares"|"artifact"|"bundle"} IoType */
/** @typedef {"source"|"transform"|"sink"|"flow"} StepKind */
/** @typedef {"enum"|"int"|"string"|"bool"} ParamType */

/**
 * @typedef {object} ParamSpec
 * @property {string} name
 * @property {ParamType} type
 * @property {string} [doc]
 * @property {*} [default]
 * @property {string[]} [enum]  allowed values when type === "enum"
 * @property {number} [min]
 * @property {number} [max]
 * @property {boolean} [positional]  first bare token binds to this param
 */

/**
 * @typedef {object} StepSpec
 * @property {string} name
 * @property {StepKind} kind
 * @property {string} doc
 * @property {IoType} input
 * @property {IoType} output
 * @property {ParamSpec[]} [params]
 * @property {boolean} [flowControl]
 * @property {boolean} [unresolvedRecipients]  needs runtime recipient binding
 * @property {string[]} [aliases]
 */

/** @type {StepSpec[]} */
export const STEPS = [
  {
    name: "genkey",
    kind: "source",
    doc: "Generate a cryptographic key with WebCrypto. Common secure algorithms only.",
    input: "none",
    output: "keypair",
    params: [
      {
        name: "alg",
        type: "enum",
        positional: true,
        default: "ec/p256",
        enum: [
          "ec/p256",
          "ec/p384",
          "ec/p521",
          "ed25519",
          "x25519",
          "rsa/2048",
          "rsa/3072",
          "rsa/4096",
          "aes/128",
          "aes/256",
          "hmac/sha256",
          "hmac/sha512",
        ],
        doc: "Algorithm family and size/curve",
      },
      {
        name: "usage",
        type: "enum",
        default: "auto",
        enum: ["auto", "sign", "derive", "encrypt"],
        doc: "Key usage flavor (auto picks a secure default for the algorithm)",
      },
    ],
  },
  {
    name: "random",
    kind: "source",
    doc: "Cryptographically random bytes from crypto.getRandomValues.",
    input: "none",
    output: "bytes",
    params: [
      {
        name: "length",
        type: "int",
        positional: true,
        default: 32,
        min: 1,
        max: 1024,
        doc: "Number of bytes (1–1024)",
      },
    ],
  },
  {
    name: "passphrase",
    kind: "source",
    doc: "EFF Large Wordlist diceware passphrase (≈12.9 bits/word).",
    input: "none",
    output: "text",
    params: [
      {
        name: "words",
        type: "int",
        positional: true,
        default: 6,
        min: 4,
        max: 12,
        doc: "Word count (EFF recommends ≥6)",
      },
    ],
  },
  {
    name: "export",
    kind: "transform",
    doc: "Export a key to a binary encoding (PKCS#8 private, SPKI public, JWK, or raw).",
    input: "keypair",
    output: "bytes",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "pkcs8",
        enum: ["pkcs8", "spki", "jwk", "raw"],
        doc: "Export format (pkcs8 = private key DER)",
      },
      {
        name: "which",
        type: "enum",
        default: "private",
        enum: ["private", "public", "both"],
        doc: "Which half to export (jwk/raw may differ by algorithm)",
      },
    ],
  },
  {
    name: "pem",
    kind: "transform",
    doc: "Wrap DER bytes as PEM (BEGIN/END headers).",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "label",
        type: "enum",
        default: "auto",
        enum: ["auto", "PRIVATE KEY", "PUBLIC KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"],
        doc: "PEM label (auto infers from prior export format)",
      },
    ],
  },
  {
    name: "der",
    kind: "transform",
    doc: "Pass DER/binary bytes through unchanged (identity).",
    input: "bytes",
    output: "bytes",
    params: [],
  },
  {
    name: "base64",
    kind: "transform",
    doc: "Encode bytes as standard Base64 (with padding).",
    input: "bytes",
    output: "text",
    params: [],
  },
  {
    name: "base64url",
    kind: "transform",
    doc: "Encode bytes as URL-safe Base64 without padding (websafe).",
    input: "bytes",
    output: "text",
    params: [],
  },
  {
    name: "hex",
    kind: "transform",
    doc: "Encode bytes as lowercase hexadecimal.",
    input: "bytes",
    output: "text",
    params: [],
  },
  {
    name: "slip39",
    kind: "transform",
    doc: "Split a secret into SLIP-39 mnemonic shares (K-of-N). Payloads larger than 256 bits use envelope encryption (AES-256-GCM + split master secret).",
    input: "bytes",
    output: "shares",
    params: [
      {
        name: "threshold",
        type: "int",
        default: 2,
        min: 1,
        max: 16,
        doc: "Shares required to recover (K)",
      },
      {
        name: "shares",
        type: "int",
        default: 3,
        min: 1,
        max: 16,
        doc: "Total shares to produce (N)",
      },
      {
        name: "passphrase",
        type: "string",
        default: "",
        doc: "Optional SLIP-39 passphrase (empty = none)",
      },
    ],
  },
  {
    name: "foreach",
    kind: "flow",
    flowControl: true,
    doc: "Unpack a collection and run every following step once per item until merge (CyberChef Fork / Python *args / functional map).",
    input: "shares",
    output: "shares",
    params: [],
    aliases: ["map", "each", "fork"],
  },
  {
    name: "merge",
    kind: "flow",
    flowControl: true,
    doc: "Close a foreach scope and collect per-item results into a bundle.",
    input: "artifact",
    output: "bundle",
    params: [],
    aliases: ["collect"],
  },
  {
    name: "gpg",
    kind: "sink",
    unresolvedRecipients: true,
    doc: "Encrypt the current value to GPG recipients chosen at run time (fingerprint-verified). Identities are never stored in the recipe.",
    input: "text",
    output: "artifact",
    params: [
      {
        name: "mode",
        type: "enum",
        default: "separate",
        enum: ["separate", "combined"],
        doc: "separate = one ciphertext per share; combined = single bundle",
      },
    ],
  },
  {
    name: "qr",
    kind: "sink",
    doc: "Render the current text as a QR code SVG artifact.",
    input: "text",
    output: "artifact",
    params: [],
  },
  {
    name: "out",
    kind: "sink",
    doc: "Emit the current value as a downloadable/copyable artifact.",
    input: "text",
    output: "artifact",
    params: [
      {
        name: "name",
        type: "string",
        default: "artifact",
        doc: "Filename stem for downloads",
      },
    ],
  },
];

/** @type {Map<string, StepSpec>} */
const BY_NAME = new Map();
/** @type {Map<string, string>} */
const ALIAS_TO_CANONICAL = new Map();

for (const step of STEPS) {
  BY_NAME.set(step.name, step);
  ALIAS_TO_CANONICAL.set(step.name, step.name);
  for (const a of step.aliases || []) {
    ALIAS_TO_CANONICAL.set(a, step.name);
    BY_NAME.set(a, step);
  }
}

/**
 * Resolve a step name or alias to its canonical StepSpec.
 * @param {string} name
 * @returns {StepSpec|null}
 */
export function getStep(name) {
  return BY_NAME.get(String(name || "").toLowerCase()) || null;
}

/**
 * Canonical step name (aliases → primary).
 * @param {string} name
 * @returns {string|null}
 */
export function canonicalName(name) {
  return ALIAS_TO_CANONICAL.get(String(name || "").toLowerCase()) || null;
}

/**
 * All steps for the Reference panel (canonical only, no aliases as separate entries).
 * @returns {StepSpec[]}
 */
export function listSteps() {
  return STEPS.slice();
}

/**
 * Steps whose input is compatible with `from` (or source steps when from is none/null).
 * @param {IoType|null} from
 * @returns {StepSpec[]}
 */
export function stepsAccepting(from) {
  if (!from || from === "none") {
    return STEPS.filter((s) => s.kind === "source" || s.input === "none");
  }
  return STEPS.filter((s) => {
    if (s.kind === "flow") {
      if (s.name === "foreach") return from === "shares";
      if (s.name === "merge") return true;
    }
    if (s.input === from) return true;
    // text sinks accept bytes via implicit utf-8? no — require explicit encode
    if (s.input === "text" && from === "text") return true;
    if (s.input === "bytes" && from === "bytes") return true;
    // artifact sinks also accept text
    if (s.input === "text" && (from === "text" || from === "artifact")) return true;
    // after foreach, items are text-like shares
    if (from === "shares" && s.name === "foreach") return true;
    return false;
  });
}

/**
 * Whether a value type can feed a step's declared input.
 * @param {IoType} from
 * @param {IoType} to
 * @param {string} [stepName]
 * @returns {boolean}
 */
export function ioCompatible(from, to, stepName) {
  if (to === "none") return from === "none" || !from;
  if (from === to) return true;
  if (stepName === "merge") return true;
  if (stepName === "foreach" && from === "shares") return true;
  // shares items inside foreach behave as text
  if (from === "shares" && to === "text") return false; // need foreach
  if (from === "text" && to === "artifact") return true;
  if (from === "artifact" && to === "bundle") return true;
  return false;
}
