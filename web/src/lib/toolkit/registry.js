/**
 * Toolkit step registry — single source of truth for steps, params, docs, and
 * input/output types. Drives the parser, builder, autocomplete, and Reference panel.
 *
 * Modeled on CyberChef's Operation metadata (name / description / inputType /
 * outputType / typed args / flowControl). Verbs mirror shell commands they replace
 * (gpg --encrypt/--decrypt, base64 -d, ssss-split/combine, openssl pkey).
 */

/** @typedef {"none"|"bytes"|"text"|"key"|"keypair"|"shares"|"artifact"|"bundle"} IoType */
/** @typedef {"source"|"transform"|"sink"|"flow"} StepKind */
/** @typedef {"enum"|"int"|"string"|"bool"|"flag"} ParamType */

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
 * @property {string} [flag]  bare CLI flag (e.g. "-d") that sets this bool to true
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
 * @property {"shares"|"gpg"|null} [unresolvedInputs]  needs runtime input panel
 * @property {string[]} [aliases]
 * @property {(params: Record<string, *>) => { input: IoType, output: IoType }} [effectiveIo]
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
    name: "input",
    kind: "source",
    doc: "Read runtime input (SLIP-39 share mnemonics or free text). Like cat — data is never stored in the recipe.",
    input: "none",
    output: "shares",
    unresolvedInputs: "shares",
    aliases: ["read", "paste"],
    params: [
      {
        name: "kind",
        type: "enum",
        positional: true,
        default: "shares",
        enum: ["shares", "text"],
        doc: "shares = mnemonic lines (+ optional envelope); text = free-form paste",
      },
    ],
    effectiveIo(params) {
      const kind = String(params?.kind || "shares");
      return { input: "none", output: kind === "text" ? "text" : "shares" };
    },
  },
  {
    name: "decrypt",
    kind: "source",
    doc: "Decrypt OpenPGP ciphertext supplied at run time (gpg --decrypt). Private key is unlocked ephemerally and scrubbed.",
    input: "none",
    output: "shares",
    unresolvedInputs: "gpg",
    aliases: ["gpgdecrypt"],
    params: [
      {
        name: "with",
        type: "enum",
        positional: true,
        default: "gpg",
        enum: ["gpg"],
        doc: "Decryption backend (gpg = OpenPGP)",
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
    effectiveIo(params) {
      const format = String(params?.format || "pkcs8");
      return {
        input: "keypair",
        output: format === "jwk" ? "text" : "bytes",
      };
    },
  },
  {
    name: "import",
    kind: "transform",
    doc: "Import DER/raw key bytes into a WebCrypto keypair (openssl pkey -in / gpg --import).",
    input: "bytes",
    output: "keypair",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "pkcs8",
        enum: ["pkcs8", "spki", "raw"],
        doc: "Import format",
      },
      {
        name: "alg",
        type: "enum",
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
          "aes/256",
          "hmac/sha256",
        ],
        doc: "Algorithm to import as",
      },
      {
        name: "usage",
        type: "enum",
        default: "auto",
        enum: ["auto", "sign", "derive", "encrypt"],
        doc: "Key usage flavor",
      },
    ],
  },
  {
    name: "pem",
    kind: "transform",
    doc: "Wrap DER as PEM (default) or strip PEM armor with -d (like openssl).",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decode (dearmor) PEM → DER bytes",
      },
      {
        name: "label",
        type: "enum",
        default: "auto",
        enum: ["auto", "PRIVATE KEY", "PUBLIC KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"],
        doc: "PEM label when encoding (auto infers from prior export format)",
      },
    ],
    effectiveIo(params) {
      if (params?.decode) return { input: "text", output: "bytes" };
      return { input: "bytes", output: "text" };
    },
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
    doc: "Encode bytes as Base64, or decode with -d (like base64 / base64 -d).",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decode Base64/Base64url text → bytes",
      },
    ],
    effectiveIo(params) {
      if (params?.decode) return { input: "text", output: "bytes" };
      return { input: "bytes", output: "text" };
    },
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
    doc: "Encode bytes as lowercase hex, or decode with -d (like xxd -p / xxd -r -p).",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decode hex text → bytes",
      },
    ],
    effectiveIo(params) {
      if (params?.decode) return { input: "text", output: "bytes" };
      return { input: "bytes", output: "text" };
    },
  },
  {
    name: "utf8",
    kind: "transform",
    doc: "Decode UTF-8 bytes to text (or encode text to bytes when input is text).",
    input: "bytes",
    output: "text",
    params: [],
    effectiveIo(params) {
      void params;
      // Engine accepts either direction; validation prefers bytes→text.
      return { input: "bytes", output: "text" };
    },
  },
  {
    name: "slip39",
    kind: "transform",
    doc: "Split a secret into SLIP-39 mnemonic shares (K-of-N), like ssss-split. Payloads larger than 256 bits use envelope encryption.",
    input: "bytes",
    output: "shares",
    aliases: ["split"],
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
    name: "combine",
    kind: "transform",
    doc: "Combine SLIP-39 mnemonic shares to recover the secret (ssss-combine). Envelope ciphertext is taken from runtime input when required.",
    input: "shares",
    output: "bytes",
    aliases: ["recover"],
    params: [
      {
        name: "passphrase",
        type: "string",
        default: "",
        doc: "Optional SLIP-39 passphrase used at split time",
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
    name: "encrypt",
    kind: "sink",
    unresolvedRecipients: true,
    doc: "Encrypt the current value (gpg --encrypt). Recipients are chosen at run time — never stored in the recipe.",
    input: "text",
    output: "artifact",
    aliases: ["gpg"],
    params: [
      {
        name: "with",
        type: "enum",
        positional: true,
        default: "gpg",
        enum: ["gpg"],
        doc: "Encryption backend (gpg = OpenPGP)",
      },
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
    doc: "Render the current text as a QR code SVG artifact (qrencode).",
    input: "text",
    output: "artifact",
    params: [],
  },
  {
    name: "out",
    kind: "sink",
    doc: "Emit the current value as a downloadable/copyable artifact (> file).",
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
 * Effective input/output for a step given its params (handles -d decode flags).
 * @param {StepSpec} spec
 * @param {Record<string, *>} [params]
 * @returns {{ input: IoType, output: IoType }}
 */
export function effectiveIo(spec, params = {}) {
  if (spec.effectiveIo) return spec.effectiveIo(params);
  return { input: spec.input, output: spec.output };
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
    if (s.name === "combine") return from === "shares";
    // Prefer encode direction for suggestions; decode variants still listed via name.
    const io = effectiveIo(s, {});
    if (io.input === from) return true;
    // Also suggest decode variants when current is text
    if (from === "text" && s.params?.some((p) => p.flag === "-d")) return true;
    if (s.input === from) return true;
    if (s.input === "text" && (from === "text" || from === "artifact")) return true;
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
  if (stepName === "combine" && from === "shares") return true;
  if (from === "shares" && to === "text") return false; // need foreach
  if (from === "text" && to === "artifact") return true;
  if (from === "artifact" && to === "bundle") return true;
  // utf8 accepts text (encode) as well as bytes (decode) — engine handles both
  if (stepName === "utf8" && (from === "bytes" || from === "text")) return true;
  // slip39 accepts text (UTF-8) or bytes
  if (stepName === "slip39" && (from === "text" || from === "bytes")) return true;
  return false;
}
