/**
 * Toolkit step registry — single source of truth for steps, params, docs, and
 * input/output types. Drives the parser, builder, autocomplete, and Reference panel.
 *
 * Normative recipe grammar: docs/RECIPE.md
 * Modeled on CyberChef Operation metadata (name / description / inputType /
 * outputType / typed args / flowControl). Verbs mirror shell commands they replace
 * (gpg --encrypt/--decrypt, base64 -d, ssss-split/combine, openssl pkey).
 *
 * Prefer positional short form in docs (`genkey ec/p256`, `out @public`, `in @kp`).
 */

import { BASE_ENCODINGS, CIPHER_DISPATCH_TARGETS } from "./step-names.js";
import { POLYMORPHIC_STEPS, stepAcceptsRefined, typeOf } from "./types.js";

/**
 * Pipeline value types.
 *
 * The `host`…`stats` tail is the network/WebRTC vocabulary (design v2 §25a).
 * These are real types, not JSON-text-with-a-badge: `rtc.answer` accepts
 * only an `sdp`, a live `session` handle can never be piped into a crypto op,
 * and the caret's fit check narrows on them like any other base.
 *
 * `any` is a signature marker, not a value: no step ever *produces* one. It
 * means "this step accepts whatever the tip holds" — see POLYMORPHIC_STEPS.
 * @typedef {"none"|"any"|"bytes"|"text"|"int"|"bool"|"key"|"keypair"|"shares"|"artifact"|"bundle"|"item"|"recipients"|"openpgp-key"
 *   |"host"|"endpoint"|"candidate"|"sdp"|"certificate"|"session"|"channel"|"peer"|"connstate"|"stats"} IoType
 */
/** @typedef {"source"|"transform"|"sink"|"flow"} StepKind */
/** @typedef {"enum"|"int"|"string"|"bool"|"flag"|"slot"} ParamType */
/** @typedef {"webcrypto"|"openpgp"|"sss"|"webauthn"|"encoding"|"flow"|"io"|"agent"|"hkp"|"webrtc"|"jose"} Toolbox */
/** @typedef {string} Shelf */
/** @typedef {import("./types.js").StepOverload} StepOverload */
/** @typedef {import("./types.js").RefinedType} RefinedType */

/**
 * Parameter declaration for a step. Registry is the SSOT — parser, serialize,
 * Reference, and toolcards all read these fields. Unknown `name=` kwargs are
 * rejected at parse (see recipe-parse `parseApply`). Convention: at most one
 * `positional: true` param per step (enforced by `registryIssues`).
 *
 * CLI flags use `type: "bool"` + `flag: "-d"` (not a separate apply form).
 * `type: "flag"` is reserved / unused in the current registry.
 *
 * @typedef {object} ParamSpec
 * @property {string} name  kwarg key (`key=…`) and AST `params` key
 * @property {ParamType} type  enum | int | string | bool | flag | slot
 * @property {string} [doc]
 * @property {*} [default]  filled when omitted; omitted from serialize unless serialize:"always"
 * @property {string[]} [enum]  allowed values when type === "enum"
 * @property {number} [min]  int lower bound (docs / UI; validate may enforce)
 * @property {number} [max]  int upper bound
 * @property {boolean} [positional]  first bare token binds here (≤1 per step)
 * @property {string} [flag]  bare CLI flag (e.g. "-d") that sets this bool to true
 * @property {boolean} [allowIndex]  for type "slot": allow 1-based index refs (default false)
 * @property {"always"} [serialize]  always emit `name=value` even when equal to default
 * @property {boolean} [secret]  UI-only: locked to a bound `@slot` ref, never free text; the
 *   literal value is still whatever the AST carries (recipe text, Publish share links, and
 *   plain copy/export must redact it to the `@slotRef` string — see design v2 §22a)
 */

/**
 * Step declaration — SSOT for ops drawer, Reference, parse, and serialize.
 * UI toolcards are views of `getStep()` / `listSteps()`, not a parallel schema.
 *
 * @typedef {object} StepSpec
 * @property {string} name
 * @property {StepKind} kind
 * @property {Toolbox} toolbox
 * @property {Shelf} [shelf]  optional sub-group within a toolbox (ops drawer)
 * @property {"exports-secret"} [exposure]  Declares that this step hands private key material to the pipeline (§26d) — drives the ToolCard warn chip and the data-key-exposed trace
 * @property {string} [label]  optional UI verb (recipe name stays unique)
 * @property {string} [conjugate]  sibling inverse step name (drawer pair row)
 * @property {string} [conjugateOf]  forward partner — omitted from solo drawer list
 * @property {boolean} [decodeTwin]  drawer shows encode | encode -d pair
 * @property {boolean} [kitOnly]  omit from shelf grids — discover via a meta kit (format/cipher/collection)
 * @property {string} [pairCaption]  optional family label above a conjugate row
 * @property {{ forward: string, reverse: string }} [pairLabels]  friendly tile verbs (Encrypt/Decrypt, Encode/Decode) — UX only
 * @property {string} [glyph]  key into generated glyphs.js (overrides shelf/toolbox)
 * @property {string} doc
 * @property {IoType} input
 * @property {IoType} output
 * @property {ParamSpec[]} [params]
 * @property {boolean} [flowControl]
 * @property {boolean} [unresolvedRecipients]  needs runtime recipient binding
 * @property {"shares"|"gpg"|"text"|"envelope"|"key"|"peer"|"keypair"|null} [unresolvedInputs]  needs runtime input panel
 * @property {IoType} [instantiates]  §31a — a type constructor: this source *is* how you write that type down
 * @property {string[]} [aliases]
 * @property {(params: Record<string, *>) => { input: IoType, output: IoType }} [effectiveIo]
 * @property {StepOverload[]} [overloads]  refined-type overloads (compile-time dispatch)
 */

/**
 * @typedef {object} ToolboxMeta
 * @property {string} label
 * @property {string} badge
 * @property {number} order
 * @property {string} [glyph]  key into generated glyphs.js (web/glyphs/)
 */

/**
 * @typedef {object} ShelfMeta
 * @property {string} label
 * @property {number} order
 * @property {boolean} [defaultCollapsed]
 * @property {string} [glyph]
 */

/**
 * @typedef {object} DrawerRow
 * @property {"pair"|"solo"} type
 * @property {string} [caption]
 * @property {StepSpec} [step]
 * @property {StepSpec} [forward]
 * @property {StepSpec} [reverse]
 * @property {boolean} [decodeTwin]
 */

/** @type {Record<Toolbox, ToolboxMeta>} */
export const TOOLBOX_META = {
  webcrypto: { label: "WebCrypto", badge: "WebCrypto", order: 0, glyph: "webcrypto", color: "#4cde82" },
  encoding: { label: "Encoding", badge: "Encode", order: 1, glyph: "encoding", color: "#58a6ff" }, // pem, base64, base64url, base32, hex, utf8
  io: { label: "Input / output", badge: "I/O", order: 2, glyph: "io", color: "#8b949e" },
  flow: { label: "Flow", badge: "Flow", order: 3, glyph: "flow", color: "#8b949e" },
  openpgp: { label: "OpenPGP", badge: "OpenPGP", order: 4, glyph: "openpgp", color: "#d2a8ff" },
  // A peer of OpenPGP, not a sub-shelf of it: age is a different file format
  // with a different key type, and filing it under `openpgp` would make
  // `age.encrypt to=` look like it accepts a PGP fingerprint. It sits next to
  // OpenPGP because that is what a user comparing the two expects.
  age: { label: "age", badge: "age", order: 5, glyph: "age", color: "#ff7b72" },
  // SSH is its own toolbox for the age reason: a different wire format with a
  // different key container. Filing ssh.sign under WebCrypto's Sign shelf
  // would imply sign and ssh.sign are variants of one thing when they share
  // nothing but a verb (§29b, design_handoff_agent_ssh).
  ssh: { label: "SSH", badge: "SSH", order: 6, glyph: "ssh", color: "#39c5cf" },
  agent: { label: "Agent", badge: "Agent", order: 7, glyph: "agent", color: "#4cde82" },
  hkp: { label: "HKP", badge: "HKP", order: 8, glyph: "hkp", color: "#f0883e" },
  sss: { label: "SSS / BLIP39", badge: "SSS", order: 9, glyph: "sss", color: "#e3b341" },
  webauthn: { label: "WebAuthn", badge: "WebAuthn", order: 10, glyph: "webauthn", color: "#79c0ff" },
  webrtc: { label: "WebRTC", badge: "WebRTC", order: 11, glyph: "agent", color: "#58a6ff" },
  jose: { label: "JOSE", badge: "JOSE", order: 12, glyph: "jose", color: "#ffa657" },
};

/**
 * Shelves (taxonomy sub-groups) inside a toolbox for the ops drawer.
 * @type {Record<string, ShelfMeta>}
 */
/** Symmetric / HMAC / KW targets for genkey, import, unwrap, and KDF `as=`. */
const AES_HMAC_ALGS = [
  "aes/128",
  "aes/192",
  "aes/256",
  "hmac/sha256",
  "hmac/sha384",
  "hmac/sha512",
];

const DERIVE_AS_ENUM = [
  "bytes",
  ...AES_HMAC_ALGS,
  "aes-kw/128",
  "aes-kw/256",
];

const UNWRAP_ALG_ENUM = [...AES_HMAC_ALGS, "aes-kw/128", "aes-kw/256"];

const RSA_HASH_ENUM = ["sha-256", "sha-384", "sha-512"];

/**
 * Shared by every step that emits OpenPGP ciphertext (`gpg.encrypt`,
 * `gpg.symencrypt`). `profile` defaults to "auto" — the session default set
 * in Preferences → Cryptographic parameters; picking modern/compatible/custom
 * here overrides it for this step only. The four `custom` sub-fields only
 * apply when `profile=custom` (see CryptoProfileControl, which renders these
 * inline instead of the generic param editor).
 * @type {ParamSpec[]}
 */
const CRYPTO_PROFILE_PARAMS = [
  {
    name: "profile",
    type: "enum",
    default: "auto",
    enum: ["auto", "modern", "compatible", "custom"],
    doc: "Crypto profile for this step. Auto follows the session default; Modern/Compatible/Custom override it here only.",
  },
  {
    name: "cipher",
    type: "enum",
    default: "aes256",
    enum: ["aes128", "aes192", "aes256"],
    doc: "Custom profile: symmetric cipher.",
  },
  {
    name: "aead",
    type: "enum",
    default: "ocb",
    enum: ["off", "ocb", "gcm", "eax"],
    doc: "Custom profile: AEAD mode. off = legacy SEIPD v1 (CFB+MDC), no AEAD.",
  },
  {
    name: "s2k",
    type: "enum",
    default: "argon2",
    enum: ["argon2", "iterated"],
    doc: "Custom profile: password → key derivation (only matters with a passphrase).",
  },
  {
    name: "compression",
    type: "enum",
    default: "off",
    enum: ["off", "zlib", "zip"],
    doc: "Custom profile: compression applied before encryption.",
  },
];

export const SHELF_META = {
  keys: { label: "Keys", order: 0, glyph: "keys" },
  digest: { label: "Digest", order: 1, glyph: "digest" },
  sign: { label: "Sign", order: 2, glyph: "sign" },
  aead: { label: "AEAD", order: 3, glyph: "aead" },
  cipher: { label: "Cipher", order: 4, defaultCollapsed: true, glyph: "cipher" },
  rsa: { label: "RSA", order: 5, glyph: "rsa" },
  kdf: { label: "KDF", order: 6, glyph: "kdf" },
  agreement: { label: "Agreement", order: 7, glyph: "agreement" },
  wrap: { label: "Wrap", order: 8, defaultCollapsed: true, glyph: "wrap" },
  sshwire: { label: "Keys & wire", order: 0, glyph: "ssh-key" },
  sshsig: { label: "Sign", order: 1, glyph: "sign" },
  pubkey: { label: "Public key", order: 0, glyph: "pubkey" },
  gpgsign: { label: "Sign", order: 1, glyph: "sign" },
  password: { label: "Password", order: 2, glyph: "password" },
  split: { label: "Split", order: 0, glyph: "split" },
  recover: { label: "Combine", order: 1, glyph: "recover" },
  binary: { label: "Binary", order: 0, glyph: "binary" },
  text: { label: "Text", order: 1, glyph: "text" },
  ports: { label: "Ports", order: 0, glyph: "ports" },
  /**
   * Run receipts — the audit surface for a key ceremony. Its own shelf rather
   * than another entry under Ports because these two ops are about the *run*,
   * not about moving a value in or out of one.
   */
  receipt: { label: "Receipt", order: 2, glyph: "ports" },
  /**
   * Whole-file operations — `age.encrypt` and the chunked `stream.seal`. Not
   * folded into `aead`: those ops take a message that fits in memory and hand
   * back one tag, while these produce a framed file with many.
   */
  files: { label: "Files", order: 3, glyph: "file" },
  /**
   * §31a — type constructors, grouped so a typed value can be *instantiated*
   * instead of entered as free text and cast downstream. A sub-shelf of I/O
   * rather than a replacement for it: the design's "Input / output" category
   * was 7 generic input ops, but this registry's is mostly real ops
   * (`random`, `passphrase`, `qr`, `out`) that are not types and must stay.
   */
  types: { label: "Types", order: 1, glyph: "ports" },
  control: { label: "Control", order: 0, glyph: "control" },
  essentials: { label: "Essentials", order: 0, defaultCollapsed: false, glyph: "essentials" },
  attestation: { label: "Attestation / MDS", order: 1, defaultCollapsed: true, glyph: "attestation" },
  // §26b: the shelf order is the steer — a user opening the Agent toolbox
  // meets the ops that keep the key inside before the one that exports it.
  boundary: { label: "Boundary", order: 0, glyph: "agent-boundary" },
  vault: { label: "Vault", order: 1, glyph: "agent" },
  directory: { label: "Directory", order: 1, glyph: "recipients" },
  lookup: { label: "Lookup", order: 0, glyph: "hkp" },
  recipients: { label: "Recipients", order: 2, glyph: "recipients" },
  // WebRTC category groups (design v2 §25b) — the one category deep enough to
  // need sub-headers: ICE/STUN, Peer & signaling, Data channel, Stats.
  // JOSE splits the way the RFCs do: a signed token and an encrypted one are
  // different objects with different failure modes, not two directions of one.
  token: { label: "Token (JWS / JWT)", order: 0, glyph: "jose" },
  envelope: { label: "Envelope (JWE)", order: 1, glyph: "jose-jwe" },
  ice: { label: "ICE / STUN", order: 0, glyph: "ports" },
  peer: { label: "Peer & signaling", order: 1, glyph: "agent" },
  channel: { label: "Data channel", order: 2, glyph: "agent" },
  rtcstats: { label: "Stats", order: 3, glyph: "ports" },
};

/** @type {StepSpec[]} */
export const STEPS = [
  {
    name: "genkey",
    kind: "source",
    toolbox: "webcrypto",
    shelf: "keys",
    doc: "Generate a WebCrypto keypair/key. Curves: `ec/p256`…`p521`, `ed25519`, `x25519` (ECDH). Symmetric: `aes/128|192|256`, `hmac/sha256|384|512`. RSA `hash=` for hashed RSA. Example: `genkey x25519 | out @local` then `ecdh private=@local peer=@peer`.",
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
          ...AES_HMAC_ALGS,
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
      {
        name: "padding",
        type: "enum",
        default: "pss",
        enum: ["pss", "pkcs1"],
        doc: "RSA signature padding when usage=sign (pss default; pkcs1 = RSASSA-PKCS1-v1_5, discouraged)",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha-256",
        enum: RSA_HASH_ENUM,
        doc: "Hash for RSA-OAEP / RSA-PSS / RSASSA (ignored for EC/OKP/AES/HMAC)",
      },
    ],
  },
  {
    name: "random",
    kind: "source",
    toolbox: "io",
    shelf: "ports",
    doc: "Cryptographically random bytes (`crypto.getRandomValues`). Example: `random 32 | base64url | out @secret`.",
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
    // A written-down byte string. `bytes` is by far the most consumed type in
    // the registry, yet until this step the only way to supply one literally
    // was `input | hex -d` — an interactive prompt plus a cast, re-asked on
    // every run. This is the source form of that pipeline.
    name: "bytes",
    kind: "source",
    toolbox: "io",
    shelf: "types",
    instantiates: "bytes",
    doc: "A literal byte string. Example: `bytes deadbeef | aes-gcm @key | out @ct`. Also accepts base64 (`encoding=base64`) or plain text (`encoding=utf8`); a leading `0x` on hex is optional. Quote the value if it contains a space or `=` — base64 padding needs `bytes \"aGVsbG8=\" encoding=base64`.",
    input: "none",
    output: "bytes",
    params: [
      {
        name: "value",
        type: "string",
        positional: true,
        default: "",
        doc: "The value, in the chosen encoding",
      },
      {
        name: "encoding",
        type: "enum",
        default: "hex",
        enum: ["hex", "base64", "utf8"],
        doc: "How to read `value`",
      },
    ],
  },
  {
    // §31c — the *import* origin for a keypair. `genkey` remains the way most
    // keypairs get made, and the Types entry's Generate mode inserts genkey
    // itself rather than reimplementing it; this step covers the other origin,
    // a keypair the user already has.
    //
    // The material is a runtime input, not a param, for the same reason
    // `input` is: a pasted private key must never reach the recipe text, and
    // therefore never reach a share link, Copy recipe, or a saved workspace.
    name: "keypair",
    kind: "source",
    toolbox: "io",
    shelf: "types",
    instantiates: "keypair",
    unresolvedInputs: "keypair",
    doc: "Import a keypair you already have, pasted at run time (never stored in the recipe). PKCS#8 PEM or JWK yields the full pair; an SPKI PEM yields a public-key tip. Example: `keypair jwk alg=ed25519 | export spki | pem | out @pub`. To make a new one instead, use `genkey`.",
    input: "none",
    output: "keypair",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "jwk",
        enum: ["jwk", "pem"],
        doc: "How the pasted material is encoded",
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
    name: "passphrase",
    kind: "source",
    toolbox: "io",
    shelf: "ports",
    doc: "Generate a passphrase. Default EFF diceware (`mode=diceware`, ≈12.9 bits/word); `mode=char` uses a 69-char alphabet. Example: `passphrase 6 | out @passphrase` or `passphrase mode=char length=20`.",
    input: "none",
    output: "text",
    params: [
      {
        name: "mode",
        type: "enum",
        default: "diceware",
        enum: ["diceware", "char"],
        doc: "diceware = EFF wordlist; char = random characters",
      },
      {
        name: "words",
        type: "int",
        positional: true,
        default: 6,
        min: 4,
        max: 12,
        doc: "Word count for diceware (EFF recommends ≥6)",
      },
      {
        name: "length",
        type: "int",
        default: 20,
        min: 12,
        max: 64,
        doc: "Character count when mode=char",
      },
    ],
  },
  {
    name: "shares",
    kind: "source",
    toolbox: "sss",
    shelf: "split",
    doc: "Bind BLIP39 share mnemonics at run time (never stored in the recipe). Typical recover: `shares | blip39 -d | sss.combine | …`. Map each share with `foreach` / `- out @share`. For free-form text use `input`.",
    input: "none",
    output: "shares",
    unresolvedInputs: "shares",
    params: [],
  },
  {
    name: "input",
    kind: "source",
    toolbox: "io",
    shelf: "ports",
    conjugate: "out",
    pairCaption: "In / out",
    doc: "Free-form text at run time (textarea / file). Never stored in the recipe. Example: `input | utf8 | encode hex`. (Legacy aliases `paste`/`cat` migrate via Upgrade recipe.)",
    input: "none",
    output: "text",
    unresolvedInputs: "text",
    params: [],
  },
  {
    name: "gpg.decrypt",
    kind: "source",
    toolbox: "openpgp",
    shelf: "pubkey",
    conjugateOf: "gpg.encrypt",
    doc: "Decrypt OpenPGP ciphertext at run time and/or accept already-plaintext BLIP39 mnemonics. Browser vault keys only (no smartcard/YubiKey in-page). Example: `gpg.decrypt | blip39 -d | sss.combine | …`.",
    input: "none",
    output: "shares",
    unresolvedInputs: "gpg",
    params: [],
  },
  {
    name: "export",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "keys",
    conjugate: "import",
    pairCaption: "Export / import",
    kitOnly: true,
    doc: "Export a keypair or projected `key` tip (pkcs8 / spki / jwk / raw / scalar). Prefer selectors for the half: `:public | export spki`, `:private | export pkcs8` (openssl pkey -pubout style). `format=spki` implies public; `pkcs8`/`scalar` imply private. In the ops drawer, pick a format from the Keys → Formats kit (not a bare Export tile).",
    input: "keypair",
    output: "bytes",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "pkcs8",
        enum: ["pkcs8", "spki", "jwk", "raw", "scalar"],
        doc: "Export format (scalar = private key material as fixed-length bytes for sss)",
      },
      {
        name: "which",
        type: "enum",
        default: "private",
        enum: ["private", "public"],
        doc: "Deprecated — prefer `:public` / `:private` before export. Still accepted on a full keypair for jwk/raw; ignored after a selector (must not conflict).",
      },
    ],
    effectiveIo(params) {
      const format = String(params?.format || "pkcs8");
      return {
        input: "keypair", // also accepts projected `key` via refined typing
        output: format === "jwk" ? "text" : "bytes",
      };
    },
  },
  {
    name: "import",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "keys",
    conjugateOf: "export",
    kitOnly: true,
    doc: "Import DER/raw/scalar/JWK. `import spki` yields a public `key` tip; other formats yield a full keypair. Example: `… | export jwk | import jwk alg=ed25519` or `import scalar alg=ec/p256`.",
    input: "bytes",
    output: "keypair",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "pkcs8",
        enum: ["pkcs8", "spki", "raw", "scalar", "jwk"],
        doc: "Import format (jwk = JSON text; spki = public key tip; scalar = EC/OKP private bytes)",
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
          ...AES_HMAC_ALGS,
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
      {
        name: "padding",
        type: "enum",
        default: "pss",
        enum: ["pss", "pkcs1"],
        doc: "RSA signature padding when usage=sign (pkcs1 discouraged)",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha-256",
        enum: RSA_HASH_ENUM,
        doc: "Hash for RSA import (ignored for other algs)",
      },
    ],
    effectiveIo(params) {
      const format = String(params?.format || "pkcs8").toLowerCase();
      if (format === "jwk") return { input: "text", output: "keypair" };
      if (format === "spki") return { input: "bytes", output: "key" };
      return { input: "bytes", output: "keypair" };
    },
  },

  {
    name: "digest",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "digest",
    doc: "Hash bytes with SubtleCrypto.digest (SHA-256 / 384 / 512; SHA-1 available but discouraged). Example: `random 32 | digest | encode hex | out @digest`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "alg",
        type: "enum",
        positional: true,
        default: "sha-256",
        enum: ["sha-256", "sha-384", "sha-512", "sha-1"],
        doc: "Hash algorithm (sha-1 is discouraged / collision-prone)",
      },
    ],
  },
  {
    name: "sign",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "sign",
    conjugate: "verify",
    pairCaption: "Sign / verify (HMAC via hmac sugar)",
    pairLabels: { forward: "Sign", reverse: "Verify" },
    doc: "Sign pipeline bytes with a WebCrypto private/HMAC key. Prefer `sign key=@kp` (slot from `out`); else key panel. RSA-PSS `saltLength=` (default 32); ECDSA optional `hash=` override. Example: `input | utf8 | sign key=@kp | base64url`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live key slot (`@kp`); omit to use the key panel",
      },
      {
        name: "saltLength",
        type: "int",
        default: 32,
        min: 0,
        max: 512,
        doc: "RSA-PSS salt length in bytes (ignored for other algs; 0 = default 32)",
      },
      {
        name: "hash",
        type: "enum",
        default: "auto",
        enum: ["auto", ...RSA_HASH_ENUM],
        doc: "ECDSA hash override (`auto` = curve default: P-256→SHA-256, P-384→SHA-384, P-521→SHA-512)",
      },
    ],
  },
  {
    name: "verify",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "sign",
    conjugateOf: "sign",
    doc: "Verify a signature over pipeline message bytes. Prefer `verify key=@pub`; else key panel. Default fail-loud; `soft` / `-q` emits `true`/`false` instead of throwing on bad sig. Signature via `signature=` or runtime binding. Same `saltLength=` / `hash=` as sign.",
    input: "bytes",
    output: "bool",
    unresolvedInputs: "key",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live public/HMAC key slot (`@pub`); omit to use the key panel",
      },
      {
        name: "signature",
        type: "string",
        default: "",
        doc: "Base64url signature, or `@slot` of bytes/text (empty = use runtime sig binding)",
      },
      {
        name: "soft",
        type: "bool",
        flag: "-q",
        default: false,
        doc: "Soft mode: emit bool true|false (never throw on bad signature). Prefer fail-loud for auth decisions.",
      },
      {
        name: "saltLength",
        type: "int",
        default: 32,
        min: 0,
        max: 512,
        doc: "RSA-PSS salt length (must match sign)",
      },
      {
        name: "hash",
        type: "enum",
        default: "auto",
        enum: ["auto", ...RSA_HASH_ENUM],
        doc: "ECDSA hash override (`auto` = curve default; must match sign)",
      },
    ],
  },
  {
    name: "aes-gcm",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "aead",
    decodeTwin: true,
    pairCaption: "AES-GCM",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    kitOnly: true,
    doc: "AES-GCM encrypt (default) or decrypt with `-d`. Prefer `aes-gcm key=@cek`; else key panel. Optional `tagLength=` (default 128). Also accepts `aes-256-gcm` / `AES/GCM/NoPadding`. Bare `encrypt`/`decrypt` sugar is migrator-only — write the concrete op. Distinct from OpenPGP `gpg.encrypt`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decrypt AES-GCM packed ciphertext to plaintext",
      },
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live AES key slot (`@cek`); omit to use the key panel",
      },
      {
        name: "aad",
        type: "string",
        default: "",
        doc: "Optional AAD as UTF-8 string, or `@slot` of text/bytes",
      },
      {
        name: "tagLength",
        type: "enum",
        default: "128",
        enum: ["96", "104", "112", "120", "128"],
        doc: "Authentication tag length in bits (default 128)",
      },
      {
        name: "keyBits",
        type: "enum",
        enum: ["128", "192", "256"],
        doc: "Optional AES key-size check (from sized forms like `aes-256-gcm`)",
      },
    ],
    effectiveIo() {
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "aes-cbc",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "cipher",
    decodeTwin: true,
    pairCaption: "AES-CBC",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    kitOnly: true,
    doc: "AES-CBC encrypt/decrypt (`-d`). Unauthenticated — prefer `aes-gcm` for new work. Packing IV(16)||CT. Prefer `aes-cbc key=@cek`. Also accepts sized/JCE forms. Distinct from OpenPGP `gpg.encrypt`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decrypt AES-CBC packed ciphertext to plaintext",
      },
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live AES key slot (`@cek`); omit to use the key panel",
      },
      {
        name: "keyBits",
        type: "enum",
        enum: ["128", "192", "256"],
        doc: "Optional AES key-size check (from sized forms like `aes-256-cbc`)",
      },
    ],
    effectiveIo() {
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "aes-ctr",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "cipher",
    decodeTwin: true,
    pairCaption: "AES-CTR",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    kitOnly: true,
    doc: "AES-CTR encrypt/decrypt (`-d`). Unauthenticated — prefer `aes-gcm` for new work. Packing IV(16)||CT (128-bit counter block); `length=` is AesCtrParams.length (default 64), not IV size. Prefer `aes-ctr key=@cek`. Also accepts sized/JCE forms. Distinct from OpenPGP `gpg.encrypt`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decrypt AES-CTR packed ciphertext to plaintext",
      },
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live AES key slot (`@cek`); omit to use the key panel",
      },
      {
        name: "length",
        type: "int",
        default: 64,
        min: 1,
        max: 128,
        doc: "Counter bits in AesCtrParams.length (IV packing stays 16 bytes)",
      },
      {
        name: "keyBits",
        type: "enum",
        enum: ["128", "192", "256"],
        doc: "Optional AES key-size check (from sized forms like `aes-256-ctr`)",
      },
    ],
    effectiveIo() {
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "rsa-oaep",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "rsa",
    decodeTwin: true,
    pairCaption: "RSA-OAEP",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    kitOnly: true,
    doc: "RSA-OAEP encrypt (default) or decrypt with `-d`. Prefer `rsa-oaep key=@rk`; else key panel. Optional `label=` (must match on decrypt). Also accepts JCE `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. Distinct from OpenPGP `gpg.encrypt` and AES `aes-gcm`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decrypt RSA-OAEP ciphertext to plaintext",
      },
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live RSA-OAEP key slot (`@rk`); omit to use the key panel",
      },
      {
        name: "label",
        type: "string",
        default: "",
        doc: "Optional OAEP label (UTF-8; empty = omit)",
      },
      {
        name: "hash",
        type: "enum",
        enum: ["sha-1", "sha-256", "sha-384", "sha-512"],
        doc: "Optional OAEP hash check (from JCE forms like OAEPWithSHA-256…)",
      },
    ],
    effectiveIo() {
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "rsa-pkcs1",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "rsa",
    decodeTwin: true,
    pairCaption: "RSAES-PKCS1",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    kitOnly: true,
    doc: "RSAES-PKCS1-v1_5 encrypt/decrypt (`-d`). Discouraged — prefer `rsa-oaep`. Pure-JS (not SubtleCrypto). Uses any RSA key (OAEP/PSS JWK) via `key=@rk`. Also accepts `RSA/ECB/PKCS1Padding`. Outputs tagged legacy/discouraged.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decrypt RSAES-PKCS1-v1_5 ciphertext to plaintext",
      },
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live RSA key slot (`@rk`); omit to use the key panel",
      },
    ],
    effectiveIo() {
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "hkdf",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "kdf",
    doc: "HKDF-Extract/Expand. Default emits OKM bytes; `as=aes/256` / `as=aes-kw/256` / HMAC uses deriveKey → live `key` tip (`which: secret`), matching `unwrap`. Distinct from the `as master` cast stage. Example: `webauthn.prf | hkdf 32 as=aes/256 | out @cek`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "length",
        type: "int",
        positional: true,
        default: 32,
        min: 1,
        max: 1024,
        doc: "Output length in bytes (when as=bytes)",
      },
      {
        name: "as",
        type: "enum",
        default: "bytes",
        enum: DERIVE_AS_ENUM,
        doc: "bytes = deriveBits OKM; else deriveKey → key tip (AES-GCM, AES-KW, or HMAC)",
      },
      {
        name: "salt",
        type: "string",
        default: "",
        doc: "Optional salt as UTF-8 string, or `@slot` of text/bytes (empty = zero-length salt)",
      },
      {
        name: "info",
        type: "string",
        default: "",
        doc: "Optional info/context as UTF-8 string, or `@slot` of text/bytes",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha-256",
        enum: ["sha-256", "sha-384", "sha-512"],
        doc: "HKDF hash",
      },
    ],
    effectiveIo(params) {
      const as = String(params?.as || "bytes");
      if (as !== "bytes") return { input: "bytes", output: "key" };
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "pbkdf2",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "kdf",
    doc: "PBKDF2-HMAC derive. Default OKM bytes; `as=aes/256` / `as=aes-kw/256` / HMAC uses deriveKey → live `key` tip (`which: secret`). Example: `passphrase 6 | pbkdf2 32 as=aes/256 | out @cek`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "length",
        type: "int",
        positional: true,
        default: 32,
        min: 1,
        max: 1024,
        doc: "Output length in bytes (when as=bytes)",
      },
      {
        name: "as",
        type: "enum",
        default: "bytes",
        enum: DERIVE_AS_ENUM,
        doc: "bytes = deriveBits OKM; else deriveKey → key tip (AES-GCM, AES-KW, or HMAC)",
      },
      {
        name: "salt",
        type: "string",
        default: "basilisk",
        doc: "Salt as UTF-8 string, or `@slot` of text/bytes",
      },
      {
        name: "iterations",
        type: "int",
        default: 100000,
        min: 1,
        max: 10000000,
        doc: "Iteration count",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha-256",
        enum: ["sha-256", "sha-384", "sha-512"],
        doc: "PBKDF2 hash",
      },
    ],
    effectiveIo(params) {
      const as = String(params?.as || "bytes");
      if (as !== "bytes") return { input: "bytes", output: "key" };
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "ecdh",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "agreement",
    doc: "ECDH/X25519 deriveBits (default) or deriveKey via `as=aes/256` / `as=aes-kw/256` → live `key` tip (`which: secret`). Prefer `genkey x25519` then `ecdh private=@local peer=@peer`. bits=0 auto-sizes from curve.",
    input: "none",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "private",
        type: "slot",
        default: "",
        doc: "Local private key slot (`@local`); omit to use the key panel",
      },
      {
        name: "peer",
        type: "slot",
        default: "",
        doc: "Peer public key slot (`@peer`); omit to use the peer JWK panel",
      },
      {
        name: "bits",
        type: "int",
        default: 0,
        min: 0,
        max: 528,
        doc: "Shared secret bit length; 0 = auto (P-256/X25519: 256, P-384: 384, P-521: 528)",
      },
      {
        name: "as",
        type: "enum",
        default: "bytes",
        enum: DERIVE_AS_ENUM,
        doc: "bytes = deriveBits; else deriveKey → key tip (AES-GCM, AES-KW, or HMAC)",
      },
    ],
    effectiveIo(params) {
      const as = String(params?.as || "bytes");
      if (as !== "bytes") return { input: "none", output: "key" };
      return { input: "none", output: "bytes" };
    },
  },
  {
    name: "wrap",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "wrap",
    conjugate: "unwrap",
    pairCaption: "Wrap / unwrap",
    doc: "Wrap a CEK. Default AES-KW; also `mode=aes-gcm|aes-cbc|aes-ctr` (IV||wrapped) or `mode=rsa-oaep`. Optional `label=` (RSA-OAEP), `tagLength=` (AES-GCM), `length=` (AES-CTR). Prefer `wrap key=@kek target=@cek`.",
    input: "none",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Wrapping key slot (`@kek` AES or `@rk` RSA); omit to use the key panel",
      },
      {
        name: "target",
        type: "slot",
        default: "",
        doc: "Key-to-wrap slot (`@cek`); omit to use the wrap panel",
      },
      {
        name: "mode",
        type: "enum",
        default: "aes-kw",
        enum: ["aes-kw", "aes-gcm", "aes-cbc", "aes-ctr", "rsa-oaep"],
        doc: "Wrapping algorithm (AES-KW, AES content modes, or RSA-OAEP)",
      },
      {
        name: "label",
        type: "string",
        default: "",
        doc: "OAEP label when mode=rsa-oaep (UTF-8; empty = omit)",
      },
      {
        name: "tagLength",
        type: "enum",
        default: "128",
        enum: ["96", "104", "112", "120", "128"],
        doc: "GCM tag bits when mode=aes-gcm",
      },
      {
        name: "length",
        type: "int",
        default: 64,
        min: 1,
        max: 128,
        doc: "CTR counter bits when mode=aes-ctr",
      },
    ],
  },
  {
    name: "unwrap",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "wrap",
    conjugateOf: "wrap",
    doc: "Unwrap pipeline wrapped bytes into a live `key` tip (CryptoKey). Modes match `wrap`. Prefer `unwrap key=@kek`. Content modes expect IV||wrapped packing. Use `export raw` when you need bytes.",
    input: "bytes",
    output: "key",
    unresolvedInputs: "key",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Wrapping key slot (`@kek` AES or `@rk` RSA); omit to use the key panel",
      },
      {
        name: "alg",
        type: "enum",
        default: "aes/256",
        enum: UNWRAP_ALG_ENUM,
        doc: "Algorithm of the wrapped key (AES-GCM, AES-KW, or HMAC)",
      },
      {
        name: "mode",
        type: "enum",
        default: "aes-kw",
        enum: ["aes-kw", "aes-gcm", "aes-cbc", "aes-ctr", "rsa-oaep"],
        doc: "Unwrapping algorithm (must match wrap mode)",
      },
      {
        name: "label",
        type: "string",
        default: "",
        doc: "OAEP label when mode=rsa-oaep (must match wrap)",
      },
      {
        name: "tagLength",
        type: "enum",
        default: "128",
        enum: ["96", "104", "112", "120", "128"],
        doc: "GCM tag bits when mode=aes-gcm",
      },
      {
        name: "length",
        type: "int",
        default: 64,
        min: 1,
        max: 128,
        doc: "CTR counter bits when mode=aes-ctr",
      },
    ],
  },
  {
    name: "pem",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "pem",
    conjugate: "der",
    pairCaption: "PEM / DER",
    pairLabels: { forward: "Armor", reverse: "Dearmor" },
    doc: "Wrap DER bytes as PEM armor. Label auto: SPKI/`which=public` → PUBLIC KEY, PKCS#8 → PRIVATE KEY. Conjugate: `der` strips armor. Example: `:public | export spki | pem | out @public`.",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "label",
        type: "enum",
        default: "auto",
        enum: ["auto", "PRIVATE KEY", "PUBLIC KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"],
        doc: "PEM label when encoding (auto infers from prior export format)",
      },
    ],
  },
  {
    name: "der",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "pem",
    conjugateOf: "pem",
    doc: "Strip PEM armor → DER bytes. Sets format/which from the BEGIN label when known. Example: `in @pub | der | import spki` or `in @pub | der | as key`.",
    input: "text",
    output: "bytes",
    params: [],
  },
  {
    name: "base64",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "base64",
    decodeTwin: true,
    pairCaption: "Base64",
    pairLabels: { forward: "Encode", reverse: "Decode" },
    kitOnly: true,
    doc: "Encode bytes as Base64 (`base64.encode`) or decode (`base64.decode`). Example: `random 32 | base64.encode | out @secret`. Also accepts `base64 -d`.",
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
    toolbox: "encoding",
    shelf: "binary",
    glyph: "base64",
    decodeTwin: true,
    pairCaption: "Base64url",
    pairLabels: { forward: "Encode", reverse: "Decode" },
    kitOnly: true,
    doc: "Encode bytes as URL-safe Base64 without padding (`base64url.encode`) or decode (`base64url.decode`). Also accepts `base64url -d`.",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decode Base64url text → bytes",
      },
    ],
    effectiveIo(params) {
      if (params?.decode) return { input: "text", output: "bytes" };
      return { input: "bytes", output: "text" };
    },
  },
  {
    // Named `encode`/`decode` rather than `to`/`from`: the pair now takes an
    // alphabet argument, so the verb should say what it does. `from` was also
    // genuinely ambiguous — it used to be the slot-load verb, so `from base64`
    // read as "load slot base64" and had to be disambiguated by a hardcoded
    // list of known encodings. `decode base64` cannot be misread.
    name: "encode",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "hex",
    conjugate: "decode",
    pairCaption: "Encode / Decode",
    pairLabels: { forward: "Encode", reverse: "Decode" },
    doc: "Encode bytes as text in a base alphabet. Example: `… | digest | encode hex | out @digest`, or `… | encode base64url`. (`to` is the old spelling and still parses.)",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "encoding",
        type: "enum",
        positional: true,
        default: "hex",
        enum: BASE_ENCODINGS,
        doc: "Target encoding",
      },
    ],
    effectiveIo(params) {
      void params;
      return { input: "bytes", output: "text" };
    },
  },
  {
    name: "decode",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "hex",
    conjugateOf: "encode",
    doc: "Decode base-encoded text → bytes. Example: `in @digest | decode hex | …`, or `… | decode base64`. (`from` is the old spelling and still parses.)",
    input: "text",
    output: "bytes",
    params: [
      {
        name: "encoding",
        type: "enum",
        positional: true,
        default: "hex",
        enum: BASE_ENCODINGS,
        doc: "Source encoding",
      },
    ],
    effectiveIo(params) {
      void params;
      return { input: "text", output: "bytes" };
    },
  },
  {
    name: "base32",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "base32",
    decodeTwin: true,
    pairCaption: "Base32",
    pairLabels: { forward: "Encode", reverse: "Decode" },
    kitOnly: true,
    doc: "Encode bytes as RFC 4648 Base32 (`base32.encode`) or decode (`base32.decode`). Example: `random 10 | base32.encode | out @id`.",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decode Base32 text → bytes",
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
    toolbox: "encoding",
    shelf: "text",
    glyph: "text",
    doc: "Decode UTF-8 bytes → text (or encode text → bytes when holding text). Example: `… | gpg.symdecrypt | utf8 | out @pem`.",
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
    name: "vss.split",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    conjugate: "vss.combine",
    pairCaption: "Split / combine (verifiable)",
    glyph: "split",
    doc: "Split a secret (≤ 32 bytes) into **verifiable** shares — Feldman VSS over P-256. Unlike `sss.split`, the share set carries public commitments, so a custodian can check their share is genuine the moment they receive it (`vss.verify`) instead of discovering a bad one when recovery fails. Emits the same `shares` shape, so `blip39` / `foreach` / `at` work unchanged. For arbitrary-length data use `sss.split` — verifiability needs a prime-order group, which GF(256) is not. Example: `export scalar | vss.split threshold=2 shares=3 | blip39 | foreach` / `- out @share`.",
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
    ],
  },
  {
    name: "vss.verify",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    glyph: "split",
    doc: "Check shares against their Feldman commitments and pass them through — fail-loud, so `in @shares | vss.verify | vss.combine` refuses to reconstruct from a tampered share rather than returning a wrong secret. Uses the commitments carried on a `vss.split` set, or `commitments=@slot` when a custodian holds them separately. Example: `in @shares | vss.verify | out @ok`.",
    input: "shares",
    output: "shares",
    params: [
      {
        name: "commitments",
        type: "slot",
        default: "",
        doc: "Slot holding the dealer's public commitments (when not carried on the shares)",
      },
    ],
  },
  {
    name: "vss.commitments",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    glyph: "split",
    doc: "Extract a `vss.split` set's public commitments as JSON, so they can be published alongside the shares. Commitments do not survive `blip39` — words carry no commitments — and that matches reality: a custodian holds a secret share and the public commitments, arriving by different routes. Example: `… | vss.split … | tee` / `- vss.commitments | out @commitments`.",
    input: "shares",
    output: "text",
    params: [],
  },
  {
    name: "vss.combine",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    conjugateOf: "vss.split",
    glyph: "recover",
    doc: "Reconstruct the secret from a threshold of `vss.split` shares (Lagrange interpolation over P-256). Pair with `vss.verify` first if the shares came from elsewhere. Example: `shares | blip39.decode | vss.verify | vss.combine | out @secret`.",
    input: "shares",
    output: "bytes",
    params: [],
  },
  {
    name: "sss.split",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    conjugate: "sss.combine",
    pairCaption: "Split / combine",
    doc: "Split a 16/32-byte master into raw SSS shares (K-of-N). Pipe into `blip39` for mnemonics. EC: `export scalar | sss.split …`. Large PEM: `… | pem | out @pem | gpg.symencrypt mode=master | sss.split …`.",
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
        doc: "Optional share passphrase mask (Basilisk-specific; empty = none)",
      },
    ],
    overloads: [
      {
        when: { base: "bytes", kind: "master", length: 16 },
        output: { base: "shares", kind: "raw" },
      },
      {
        when: { base: "bytes", kind: "master", length: 32 },
        output: { base: "shares", kind: "raw" },
      },
      {
        when: { base: "bytes", kind: "master" },
        output: { base: "shares", kind: "raw" },
      },
      {
        when: { base: "bytes", kind: "scalar", length: 32 },
        output: { base: "shares", kind: "raw" },
      },
      {
        when: { base: "bytes", kind: "scalar", length: 16 },
        output: { base: "shares", kind: "raw" },
      },
    ],
  },
  {
    name: "blip39",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    decodeTwin: true,
    pairCaption: "BLIP39",
    pairLabels: { forward: "Encode", reverse: "Decode" },
    doc: "Encode raw SSS shares as BLIP39 mnemonics (`blip39.encode`) or decode (`blip39.decode`). Example: `… | sss.split | blip39.encode | foreach`. Recover: `shares | blip39.decode | sss.combine`. Also accepts `blip39 -d`.",
    input: "shares",
    output: "shares",
    params: [
      {
        name: "decode",
        type: "bool",
        flag: "-d",
        default: false,
        doc: "Decode BLIP39 mnemonics → raw SSS shares",
      },
    ],
    overloads: [
      {
        when: { base: "shares", kind: "raw" },
        whenParams: { decode: ["false", "undefined", ""] },
        output: { base: "shares", kind: "mnemonic" },
      },
      {
        when: { base: "shares", kind: "mnemonic" },
        whenParams: { decode: "true" },
        output: { base: "shares", kind: "raw" },
      },
      {
        when: { base: "shares" },
        whenParams: { decode: "true" },
        output: { base: "shares", kind: "raw" },
      },
    ],
    effectiveIo(params) {
      void params;
      return { input: "shares", output: "shares" };
    },
  },
  {
    name: "sss.combine",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    conjugateOf: "sss.split",
    doc: "Combine raw SSS shares into the 16/32-byte master. Decode mnemonics first: `shares | blip39 -d | sss.combine`. Unwrap envelopes with `gpg.symdecrypt` after combine.",
    input: "shares",
    output: "bytes",
    params: [
      {
        name: "passphrase",
        type: "string",
        default: "",
        doc: "Optional share passphrase used at split time",
      },
    ],
    overloads: [
      {
        when: { base: "shares", kind: "raw" },
        output: { base: "bytes", kind: "master" },
      },
    ],
  },
  {
    name: "gpg.symencrypt",
    kind: "transform",
    toolbox: "openpgp",
    shelf: "password",
    conjugate: "gpg.symdecrypt",
    pairCaption: "Symmetric",
    doc: "OpenPGP-symmetric encrypt (`gpg -c` style). Dual mode is explicit: default `mode=master` (fresh 32-byte master tip + `envelope.asc` for SSS); `mode=passphrase` + `passphrase=`/`@slot` emits armored ciphertext as the tip (no master). Passphrase alone does not flip modes. Example SSS: `… | pem | gpg.symencrypt mode=master | sss.split …`. Example password: `\"hi\" | utf8 | gpg.symencrypt mode=passphrase passphrase=@pw | out @msg`.",
    input: "text",
    output: "bytes",
    params: [
      {
        name: "mode",
        type: "enum",
        default: "master",
        enum: ["master", "passphrase"],
        serialize: "always",
        doc: "master = SSS random-master tip + envelope artifact; passphrase = gpg -c tip (requires passphrase=)",
      },
      {
        name: "name",
        type: "string",
        default: "envelope",
        doc: "Envelope / ciphertext artifact filename stem",
      },
      {
        name: "passphrase",
        type: "string",
        default: "",
        doc: "User passphrase (UTF-8) or `@slot` of text — required with mode=passphrase; forbidden with mode=master",
      },
      ...CRYPTO_PROFILE_PARAMS,
    ],
    effectiveIo(params) {
      const mode = String(params?.mode || "master").toLowerCase();
      if (mode === "passphrase") return { input: "text", output: "text" };
      return { input: "text", output: "bytes" };
    },
    // Type flow also via inferParamDrivenType.
  },
  {
    name: "gpg.symdecrypt",
    kind: "transform",
    toolbox: "openpgp",
    shelf: "password",
    conjugateOf: "gpg.symencrypt",
    doc: "Decrypt OpenPGP-symmetric ciphertext. Dual mode is explicit: default `mode=master` (tip is 16/32-byte master; bound `envelope.asc` decrypts with hex(master)); `mode=passphrase` + `passphrase=`/`@slot` (tip is armored ciphertext). Passphrase alone does not flip modes. Example: `in @msg | gpg.symdecrypt mode=passphrase passphrase=@pw | utf8`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "envelope",
    params: [
      {
        name: "mode",
        type: "enum",
        default: "master",
        enum: ["master", "passphrase"],
        serialize: "always",
        doc: "master = SSS recover path (envelope panel); passphrase = tip is armored ciphertext",
      },
      {
        name: "passphrase",
        type: "string",
        default: "",
        doc: "User passphrase (UTF-8) or `@slot` — required with mode=passphrase; forbidden with mode=master",
      },
    ],
    effectiveIo(params) {
      const mode = String(params?.mode || "master").toLowerCase();
      if (mode === "passphrase") return { input: "text", output: "bytes" };
      return { input: "bytes", output: "bytes" };
    },
    overloads: [
      {
        when: { base: "bytes", kind: "master" },
        output: { base: "bytes", kind: "opaque" },
      },
    ],
  },
  {
    name: "foreach",
    kind: "flow",
    toolbox: "flow",
    shelf: "control",
    flowControl: true,
    doc: "Map a required body over a shares collection. Indent `-` lines or `{ … }`. Optional `foreach :items` / `:values` / `:keys`. Tip is a `bundle` of per-item tips (side effects via `out` / auto-emit) — do not pipe the bundle into cipher/KDF ops; use `@slot`s from the body. Example: `… | blip39 | foreach` / `- out @share` or `- gpg.encrypt`.",
    input: "shares",
    output: "bundle",
    params: [],
  },
  {
    name: "at",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    doc: "Select from a shares collection (1-based). Same as `[1]` / `[1:2]`. Example: `… | blip39 | [1] | out @share-1`.",
    input: "shares",
    output: "shares",
    params: [
      {
        name: "selector",
        type: "string",
        positional: true,
        default: "1",
        doc: "Share index N or slice N:M (1-based, inclusive)",
      },
    ],
  },
  {
    name: "lit",
    kind: "source",
    toolbox: "flow",
    shelf: "control",
    kitOnly: true,
    doc: "Stem literal (parse/serialize as the literal itself — never written as `lit …`). Strings → text; decimal/hex ints → int; `true`/`false` → bool. Example: `\"hello\" | out @msg`, `0xff | out @n`, or `true | out @ok`.",
    input: "none",
    output: "text",
    params: [
      {
        name: "kind",
        type: "enum",
        default: "text",
        enum: ["text", "int", "bool"],
        doc: "Literal kind",
      },
      {
        name: "value",
        type: "string",
        default: "",
        doc: "Literal value (string text, decimal int, or true/false)",
      },
    ],
    effectiveIo(params) {
      const kind = String(params?.kind || "text");
      if (kind === "int") return { input: "none", output: "int" };
      if (kind === "bool") return { input: "none", output: "bool" };
      return { input: "none", output: "text" };
    },
  },
  {
    name: "in",
    kind: "source",
    toolbox: "flow",
    shelf: "control",
    doc: "Source a prior `out` slot (live typed value). Chains are blank-line separated. Forms: `in @kp`, `in kp`, `in 1`. (`decode` is the alphabet verb; `in` only loads slots.) See docs/RECIPE.md.",
    input: "none",
    output: "bytes",
    params: [
      {
        name: "ref",
        type: "string",
        positional: true,
        doc: "Slot `@label` or 1-based index (`@kp`, `kp`, or `1`)",
      },
    ],
  },
  {
    name: "select",
    kind: "transform",
    toolbox: "flow",
    shelf: "control",
    doc: "Project a member via selector. `:public` / `:private` turn a keypair tip into a `key` tip (CryptoKey half). Usually written bare: `:public | export spki | pem`. Also as a tee/foreach branch prefix: `- :public | …`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "selector",
        type: "string",
        positional: true,
        doc: "Selector text, e.g. :private or :value",
      },
    ],
  },
  {
    name: "as",
    kind: "transform",
    toolbox: "flow",
    shelf: "control",
    doc: "Cast the tip. Retag (no crypto): `as master` / `as scalar` / `as opaque` / `as public` / `as private` / `as int` / `as bool`. Materialize (WebCrypto): `as key` / `as keypair` from DER or PEM. Distinct from hkdf/pbkdf2/ecdh param `as=aes/256`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "type",
        type: "enum",
        positional: true,
        default: "opaque",
        enum: [
          "master",
          "scalar",
          "opaque",
          "public",
          "private",
          "key",
          "keypair",
          "int",
          "bool",
        ],
        doc: "Cast target (retag, coerce, or materialize — see docs)",
      },
      {
        name: "alg",
        type: "string",
        default: "ec/p256",
        doc: "Algorithm for `as key` / `as keypair` (same tokens as import; ignored for retags)",
      },
      {
        name: "usage",
        type: "string",
        default: "auto",
        doc: "Key usages hint for materializing casts (auto|sign|encrypt|derive)",
      },
      {
        name: "padding",
        type: "string",
        default: "pss",
        doc: "RSA sign padding for materializing casts (pss|pkcs1)",
      },
      {
        name: "hash",
        type: "string",
        default: "sha-256",
        doc: "Hash for RSA materializing casts",
      },
    ],
    effectiveIo(params) {
      const t = String(params?.type || "opaque").toLowerCase();
      if (t === "key") return { input: "bytes", output: "key" };
      if (t === "keypair") return { input: "bytes", output: "keypair" };
      if (t === "int") return { input: "text", output: "int" };
      if (t === "bool") return { input: "text", output: "bool" };
      if (t === "public" || t === "private") return { input: "bytes", output: "bytes" };
      return { input: "bytes", output: "bytes" };
    },
  },
  {
    name: "gpg.genkey",
    kind: "source",
    toolbox: "openpgp",
    shelf: "pubkey",
    doc: "Generate an OpenPGP Curve25519 keypair (same as My Keys). Pipeline emits `openpgp-key/private`; public key is also written as an artifact. Quote emails (`@` is slot syntax): `gpg.genkey email=\"alice@example.com\" | out @priv`.",
    input: "none",
    output: "openpgp-key",
    params: [
      {
        name: "email",
        type: "string",
        positional: true,
        default: "",
        doc: "User ID email (required)",
      },
      {
        name: "name",
        type: "string",
        default: "",
        doc: "User ID display name (defaults to email)",
      },
      {
        name: "passphrase",
        type: "string",
        default: "",
        doc: "Optional S2K passphrase protecting the private key",
      },
      {
        name: "expiry",
        type: "int",
        default: 0,
        min: 0,
        max: 630720000,
        doc: "Key expiration in seconds from now (0 = none)",
      },
    ],
  },
  {
    name: "gpg.inspect",
    kind: "transform",
    toolbox: "openpgp",
    shelf: "pubkey",
    doc: "Inspect armored OpenPGP without decrypting (type, recipients, signatures, optional packet map). Example: `input | gpg.inspect | out @report`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "format",
        type: "enum",
        default: "summary",
        enum: ["summary", "packets", "json"],
        doc: "summary = human report; packets = packet map; json = MessageAnalysis fields",
      },
    ],
  },
  {
    name: "gpg.encrypt",
    kind: "sink",
    toolbox: "openpgp",
    shelf: "pubkey",
    conjugate: "gpg.decrypt",
    pairCaption: "Encrypt / decrypt",
    unresolvedRecipients: true,
    doc: "OpenPGP-encrypt the current value. Prefer `to=@alices` (recipients slot) or `to=email` + lookup; else Run binder. `mode=separate|combined`. `-s` / `key=@me` for sign-then-encrypt.",
    input: "text",
    output: "artifact",
    params: [
      {
        name: "to",
        type: "string",
        default: "",
        doc: "`@slot`, `fpr:…`, or email (resolve via lookup). Empty = Run binder",
      },
      {
        name: "policy",
        type: "enum",
        default: "ask",
        enum: ["ask", "one", "all"],
        doc: "Email resolution: ask (modal), one (exactly one), all (every approved)",
      },
      {
        name: "mode",
        type: "enum",
        default: "separate",
        enum: ["separate", "combined"],
        doc: "separate = one ciphertext per recipient; combined = one message, N PKESKs",
      },
      {
        name: "sign",
        type: "bool",
        flag: "-s",
        default: false,
        doc: "Sign-then-encrypt with vault OpenPGP private key (same as Encrypt page)",
      },
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Signing private-key slot when `-s` (`@me`); omit to use the vault key panel",
      },
      ...CRYPTO_PROFILE_PARAMS,
    ],
  },
  {
    name: "gpg.sign",
    kind: "transform",
    toolbox: "openpgp",
    shelf: "gpgsign",
    conjugate: "gpg.verify",
    pairCaption: "Sign / verify",
    doc: "OpenPGP-sign pipeline text/bytes. Prefer `gpg.sign key=@me` (slot from `agent.unlock`); else vault key panel. Default cleartext; `format=detached` for detached sig. Distinct from WebCrypto `sign`.",
    input: "text",
    output: "text",
    unresolvedInputs: "gpg",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live private-key slot (`@me`); omit to use the vault key panel",
      },
      {
        name: "format",
        type: "enum",
        default: "cleartext",
        enum: ["cleartext", "detached"],
        doc: "cleartext = signed message; detached = signature only",
      },
    ],
    overloads: [
      { when: { base: "text" }, output: { base: "text" } },
      { when: { base: "bytes" }, output: { base: "text" } },
    ],
    effectiveIo(params) {
      void params;
      return { input: "text", output: "text" };
    },
  },
  {
    name: "gpg.verify",
    kind: "transform",
    toolbox: "openpgp",
    shelf: "gpgsign",
    conjugateOf: "gpg.sign",
    doc: "Verify an OpenPGP cleartext or detached signature. Prefer `gpg.verify key=@pub`. Detached: `signature=@slot`. Fail-loud by default; `soft`/`-q` → bool true|false. Distinct from WebCrypto `verify`.",
    input: "text",
    output: "bool",
    unresolvedInputs: "gpg",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live public (or private) key slot (`@pub`); omit to use vault key / recipients",
      },
      {
        name: "signature",
        type: "string",
        default: "",
        doc: "Detached armored signature or `@slot` (empty = cleartext on stem, or runtime sig binding)",
      },
      {
        name: "soft",
        type: "bool",
        flag: "-q",
        default: false,
        doc: "Soft mode: emit bool true|false (never throw on bad signature)",
      },
    ],
    overloads: [{ when: { base: "text" }, output: { base: "bool" } }],
  },
  // ── SSH (§29, design_handoff_agent_ssh) — OpenSSH wire formats and sshsig.
  // Pure JS end to end (@noble/curves + SubtleCrypto), so every op runs
  // headlessly in the CLI and is interop-tested against ssh-keygen fixtures.
  {
    name: "ssh.encode",
    kind: "transform",
    toolbox: "ssh",
    shelf: "sshwire",
    conjugate: "ssh.decode",
    pairCaption: "Encode / decode",
    glyph: "ssh-key",
    doc: "Encode a keypair/key as OpenSSH — `format=public` (default) emits the one-line public form (`ssh-ed25519 AAAA… comment`) for authorized_keys / GitHub; `format=private` emits an **unencrypted** openssh-key-v1 block and warns. ed25519, ec/p256|384|521, rsa. Example: `genkey ed25519 | ssh.encode comment=\"you@host\" | out @pub`.",
    input: "keypair",
    output: "text",
    params: [
      {
        name: "format",
        type: "enum",
        default: "public",
        enum: ["public", "private"],
        doc: "public = one-line public key; private = unencrypted openssh-key-v1 (explicit only, never a default)",
      },
      {
        name: "comment",
        type: "string",
        default: "",
        doc: "Trailing comment on the public line (openssh-key-v1 carries it too)",
      },
    ],
    overloads: [
      { when: { base: "keypair" }, output: { base: "text", kind: "ssh-public" } },
      { when: { base: "key" }, output: { base: "text", kind: "ssh-public" } },
    ],
  },
  {
    name: "ssh.decode",
    kind: "transform",
    toolbox: "ssh",
    shelf: "sshwire",
    conjugateOf: "ssh.encode",
    glyph: "ssh-key",
    doc: "Decode an OpenSSH public line or (unencrypted) openssh-key-v1 private block into a live key/keypair. Passphrase-protected private files are refused by name — the KDF is bcrypt, which Basilisk cannot run yet. Example: `input | ssh.decode | ssh.fingerprint | out @fp`.",
    input: "text",
    output: "keypair",
    overloads: [
      { when: { base: "text", kind: "ssh-public" }, output: { base: "key" } },
      { when: { base: "text", kind: "ssh-private" }, output: { base: "keypair" } },
      { when: { base: "text" }, output: { base: "keypair" } },
    ],
    params: [],
  },
  {
    name: "ssh.fingerprint",
    kind: "transform",
    toolbox: "ssh",
    shelf: "sshwire",
    glyph: "fingerprint",
    doc: "SHA-256 fingerprint of an SSH public key — `SHA256:` + base64, byte-identical to `ssh-keygen -lf`. Accepts a keypair, a key, or a public line. Example: `input | ssh.decode | ssh.fingerprint | out @fp`.",
    input: "keypair",
    output: "text",
    overloads: [
      { when: { base: "keypair" }, output: { base: "text" } },
      { when: { base: "key" }, output: { base: "text" } },
      { when: { base: "text", kind: "ssh-public" }, output: { base: "text" } },
    ],
    params: [],
  },
  {
    name: "ssh.sign",
    kind: "transform",
    toolbox: "ssh",
    shelf: "sshsig",
    conjugate: "ssh.verify",
    pairCaption: "Sign / verify",
    glyph: "sshsig-sign",
    doc: "Sign the payload in sshsig format (`ssh-keygen -Y sign`) — also how git signs commits with SSH keys. `namespace=` is part of what is signed: a `git` signature can never verify as a `file` signature. Key from a slot. Example: `input | utf8 | ssh.sign key=@id namespace=git | out @sig`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Private key slot — a keypair, or `ssh.decode` output",
      },
      {
        name: "namespace",
        type: "string",
        default: "file",
        doc: "Signature domain (`file`, `git`); verifier must name the same one",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha512",
        enum: ["sha512", "sha256"],
        doc: "Payload hash inside the sshsig envelope (ssh-keygen default: sha512)",
      },
    ],
    overloads: [
      { when: { base: "text" }, output: { base: "text", kind: "sshsig" } },
      { when: { base: "bytes" }, output: { base: "text", kind: "sshsig" } },
    ],
  },
  {
    name: "ssh.verify",
    kind: "transform",
    toolbox: "ssh",
    shelf: "sshsig",
    conjugateOf: "ssh.sign",
    glyph: "sshsig-sign",
    doc: "Verify an sshsig signature over the pipeline payload (`ssh-keygen -Y verify`). `signature=@slot` holds the sshsig block, `key=` the public line or a slot; `namespace=` must match the signer's. Fail-loud; `-q` emits bool false instead. Example: `in @msg | ssh.verify key=@pub signature=@sig namespace=git | out @ok`.",
    input: "text",
    output: "bool",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Signer's public key — slot, or the literal public line",
      },
      {
        name: "signature",
        type: "slot",
        default: "",
        doc: "Slot holding the sshsig block",
      },
      {
        name: "namespace",
        type: "string",
        default: "file",
        doc: "Must equal the namespace the signature was made under",
      },
      {
        name: "soft",
        type: "bool",
        flag: "-q",
        default: false,
        doc: "Soft mode: emit bool true|false (never throw on bad signature)",
      },
    ],
    overloads: [
      { when: { base: "text" }, output: { base: "bool" } },
      { when: { base: "bytes" }, output: { base: "bool" } },
    ],
  },
  // ── Boundary (§26f) — the key is used without entering the pipeline.
  {
    name: "agent.sign",
    kind: "transform",
    toolbox: "agent",
    shelf: "boundary",
    glyph: "agent-sign",
    doc: "Sign the pipeline payload with a My Keys key — the private key never enters the pipeline; the unlock happens inside the vault with per-use approval. `format=auto` follows the key's kind: PGP → OpenPGP signature, SSH → sshsig (`namespace=` names the domain, `git` for git). Prefer this over `agent.unlock | gpg.sign`. Example: `input | utf8 | agent.sign AABB… | out @sig`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "fpr",
        type: "string",
        positional: true,
        default: "",
        doc: "Vault key id — PGP hex fingerprint or SSH SHA256:… fingerprint",
      },
      {
        name: "format",
        type: "enum",
        default: "auto",
        enum: ["auto", "gpg", "ssh"],
        doc: "auto = key kind decides. gpg = OpenPGP; ssh = sshsig",
      },
      {
        name: "mode",
        type: "enum",
        default: "cleartext",
        enum: ["cleartext", "detached"],
        doc: "OpenPGP only: cleartext = signed message; detached = signature only",
      },
      {
        name: "namespace",
        type: "string",
        default: "file",
        doc: "sshsig only: signature domain (`file`, `git`) — shown verbatim in the approval prompt",
      },
    ],
    overloads: [
      { when: { base: "text" }, output: { base: "text" } },
      { when: { base: "bytes" }, output: { base: "text" } },
    ],
  },
  {
    name: "agent.decrypt",
    kind: "transform",
    toolbox: "agent",
    shelf: "boundary",
    glyph: "agent-decrypt",
    doc: "Decrypt an OpenPGP message with a My Keys key — ciphertext in, plaintext out; the private key never enters the pipeline (per-use approval). PGP-kind keys only: SSH signing keys cannot decrypt. Example: `input | agent.decrypt AABB… | out @plain`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "fpr",
        type: "string",
        positional: true,
        default: "",
        doc: "Vault key id (PGP hex fingerprint); the key's kind must be pgp",
      },
    ],
    overloads: [
      { when: { base: "text" }, output: { base: "text" } },
      { when: { base: "bytes" }, output: { base: "text" } },
    ],
  },
  {
    name: "agent.unlock",
    kind: "source",
    toolbox: "agent",
    shelf: "vault",
    // §26d: declared in the registry, not special-cased in the widget, so
    // the treatment is reusable if another exporting op ever appears.
    exposure: "exports-secret",
    doc: "Exports the private key into the run — use only when a recipe genuinely needs key material (export, transformation). For signing or decrypting, prefer `agent.sign` / `agent.decrypt`, which keep the key in the vault. pgp keys emit openpgp-key; ssh/raw keys emit a live keypair. Main-thread (passkey).",
    input: "none",
    output: "openpgp-key",
    params: [
      {
        name: "fpr",
        type: "string",
        positional: true,
        default: "",
        doc: "Vault id — hex OpenPGP fingerprint, or SHA256:… for ssh/raw kinds",
      },
    ],
  },
  {
    name: "agent.pub",
    kind: "source",
    toolbox: "agent",
    shelf: "vault",
    doc: "Emit stored `publicArmored` for a My Keys fingerprint — no unlock. Example: `agent.pub AABB… | out @pub`.",
    input: "none",
    output: "openpgp-key",
    params: [
      {
        name: "fpr",
        type: "string",
        positional: true,
        default: "",
        doc: "Vault fingerprint (hex)",
      },
    ],
  },
  {
    name: "agent.list",
    kind: "source",
    toolbox: "agent",
    shelf: "vault",
    doc: "List My Keys metadata as JSON (fingerprint, uid, protection, lastUsedAt) — no private material.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "agent.save",
    kind: "transform",
    toolbox: "agent",
    shelf: "vault",
    // §38a: the steer goes first, following `agent.unlock`'s precedent (§26f).
    // A recipe is a portable object — shared as a link, saved as a workspace,
    // re-run by someone else — and this op is the only one in the toolbox that
    // writes durable state on whoever runs it. That belongs at the top of the
    // doc rather than as a footnote nobody scrolls to. The charter's other
    // claim, that this op exists "for CLI runs", is simply false and is not
    // repeated here: `basilisk run` refuses the whole `agent` toolbox at
    // pre-flight with exit 4, verified.
    doc: "Writes to the keyring of *whoever runs the recipe* — a shared link containing `agent.save` saves into the reader's vault, and nothing in the recipe undoes it. Reach for it when the write is the point: a `foreach` over generated keys, or a workspace you re-run yourself. Not available headlessly — `basilisk run` refuses the `agent` toolbox at pre-flight (exit 4), because Node has no vault. Save the pipeline's private key into My Keys. OpenPGP armor saves as kind pgp; a WebCrypto keypair saves as kind ssh (ed25519/ec/rsa — id is the SSH SHA256 fingerprint) or raw (x25519). `protection=device|passphrase|passkey`; passphrase applies to pgp only (non-PGP payloads have no S2K yet). Example: `genkey ed25519 | agent.save | out @id`.",
    input: "openpgp-key",
    output: "openpgp-key",
    overloads: [
      { when: { base: "openpgp-key" }, output: { base: "openpgp-key" } },
      { when: { base: "keypair" }, output: { base: "keypair" } },
    ],
    params: [
      {
        name: "protection",
        type: "enum",
        default: "device",
        enum: ["device", "passphrase", "passkey"],
        doc: "Vault wrap mode",
      },
      {
        name: "email",
        type: "string",
        default: "",
        doc: "Override UID email (defaults from key)",
      },
      {
        name: "name",
        type: "string",
        default: "",
        doc: "Override UID display name",
      },
      {
        name: "expiry",
        type: "enum",
        default: "none",
        enum: ["none", "1d", "1w", "1m", "1y"],
        doc: "Vault expiry preset (metadata)",
      },
    ],
  },
  {
    name: "hkp.get",
    kind: "source",
    toolbox: "hkp",
    shelf: "lookup",
    doc: "Fetch a public key by fingerprint (device cache → This site `/pks/lookup` → optional explicit upstream). Example: `hkp.get AABB… | out @bob`.",
    input: "none",
    output: "openpgp-key",
    params: [
      {
        name: "fpr",
        type: "string",
        positional: true,
        default: "",
        doc: "Fingerprint (hex)",
      },
      {
        name: "keyserver",
        type: "string",
        default: "",
        doc: "Empty = This site (page origin `/pks/lookup`). Set to an allowlisted host to override on miss (signed-in + upstream enabled).",
      },
      {
        name: "refresh",
        type: "bool",
        default: false,
        doc: "Bypass device cache and re-fetch",
      },
    ],
  },
  {
    name: "hkp.search",
    kind: "source",
    toolbox: "hkp",
    shelf: "directory",
    doc: "Search local cache + This site directory; optional explicit upstream on miss. Filter with `hkp.filter`.",
    input: "none",
    output: "recipients",
    params: [
      {
        name: "query",
        type: "string",
        positional: true,
        default: "",
        doc: "Email, name, or fingerprint fragment",
      },
      {
        name: "format",
        type: "enum",
        default: "recipients",
        enum: ["recipients", "json"],
        doc: "recipients = typed list; json = text dump",
      },
      {
        name: "keyserver",
        type: "string",
        default: "",
        doc: "Empty = This site only (no silent upstream). Set to an allowlisted host to search upstream on miss.",
      },
    ],
    effectiveIo(params) {
      if (String(params?.format || "recipients") === "json") {
        return { input: "none", output: "text" };
      }
      return { input: "none", output: "recipients" };
    },
  },
  {
    name: "hkp.filter",
    kind: "transform",
    toolbox: "hkp",
    shelf: "directory",
    doc: "Filter a `recipients` list. Defaults: approved + encrypt-capable (upstream/import kept when valid).",
    input: "recipients",
    output: "recipients",
    params: [
      {
        name: "approved",
        type: "bool",
        default: true,
        doc: "Keep org-approved (and valid upstream/import) keys",
      },
      {
        name: "encrypt",
        type: "bool",
        default: true,
        doc: "Keep only encrypt-capable keys",
      },
      {
        name: "origin",
        type: "string",
        default: "",
        doc: "Optional origin filter: basilisk | upstream | import",
      },
    ],
  },
  {
    name: "hkp.cache",
    kind: "source",
    toolbox: "hkp",
    shelf: "lookup",
    doc: "List or clear the device IndexedDB pubkey cache (`action=list|clear`).",
    input: "none",
    output: "recipients",
    params: [
      {
        name: "action",
        type: "enum",
        default: "list",
        enum: ["list", "clear"],
        doc: "list cached pubkeys or clear the cache",
      },
      {
        name: "format",
        type: "enum",
        default: "recipients",
        enum: ["recipients", "json"],
        doc: "recipients = typed list; json = text dump",
      },
    ],
    effectiveIo(params) {
      if (String(params?.action || "list") === "clear") {
        return { input: "none", output: "text" };
      }
      if (String(params?.format || "recipients") === "json") {
        return { input: "none", output: "text" };
      }
      return { input: "none", output: "recipients" };
    },
  },
  {
    name: "recipients.merge",
    kind: "transform",
    toolbox: "hkp",
    shelf: "recipients",
    doc: "Merge pipeline recipients with `with=@slot` (dedupe by fingerprint).",
    input: "recipients",
    output: "recipients",
    params: [
      {
        name: "with",
        type: "slot",
        default: "",
        doc: "Other recipients / public key slot to merge",
      },
    ],
  },
  {
    name: "qr",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    doc: "Render the current text as a QR code SVG artifact. Example: `… | blip39 | [1] | qr`.",
    input: "text",
    output: "artifact",
    params: [],
  },
  {
    name: "run.receipt",
    kind: "source",
    toolbox: "io",
    shelf: "receipt",
    conjugate: "run.verify",
    pairCaption: "Run receipt",
    pairLabels: { forward: "Receipt", reverse: "Verify" },
    doc: "Emit a signable receipt for this run: recipe source, per-cell input/output **digests** (never the values), timestamps, and the op-registry version. Sign it with the vault key — `run.receipt | gpg.sign key=@me | out @receipt` — and check it later with `run.verify`.",
    input: "none",
    output: "text",
    params: [
      {
        name: "label",
        type: "string",
        positional: true,
        default: "",
        doc: "Ceremony label recorded in the receipt (defaults to the notebook title)",
      },
    ],
  },
  {
    name: "run.verify",
    kind: "transform",
    toolbox: "io",
    shelf: "receipt",
    conjugateOf: "run.receipt",
    doc: "Check a receipt (signed or plain JSON) against the run happening now — digests only, so neither side reveals a secret. Fail-loud by default; `run.verify -q` emits a bool instead. Example: `input | run.verify -q | out @ok`.",
    input: "text",
    output: "bool",
    params: [
      {
        name: "soft",
        type: "bool",
        flag: "-q",
        default: false,
        doc: "Emit false instead of throwing when the receipt does not match",
      },
    ],
  },
  {
    name: "qr.scan",
    kind: "transform",
    toolbox: "io",
    shelf: "ports",
    glyph: "qr",
    doc: "Read a QR code out of an image — the conjugate of `qr`. Takes image bytes (`file.read`) or SVG markup and emits the encoded text; `count=all` joins every code found, for a photo of several share cards. Needs a browser with `BarcodeDetector` (Chromium today). Example: `file.read | qr.scan | quorum.join`.",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "count",
        type: "enum",
        values: ["1", "all"],
        default: "1",
        doc: "Take the first code, or every code in the image",
      },
    ],
    effectiveIo(params) {
      // Same count-driven shape `rtc.recv` established: one code stays `text`
      // so the ordinary single-invite scan is unchanged, several become a
      // `bundle` so `foreach` can walk them. Claiming `text` for a photo of a
      // sheet of share cards would let a cipher op be appended to what is
      // really a collection.
      const count = String(params?.count ?? "1").trim().toLowerCase();
      return { input: "bytes", output: count === "1" ? "text" : "bundle" };
    },
  },
  {
    name: "clipboard.read",
    kind: "source",
    toolbox: "io",
    shelf: "ports",
    doc: "Read the system clipboard into the pipeline as text. Asks every run — never remembered, because clipboard contents change silently between runs. The out-of-band signaling source: `clipboard.read | quorum.join`.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "clipboard.write",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    doc: "Copy the current value to the system clipboard and pass it through — text verbatim, bytes as base64, structured values as JSON. Toast-weight confirm, no dialog: you just ran the recipe that produced the value. Example: `… | out @invite | clipboard.write`.",
    input: "bytes",
    output: "bytes",
    params: [],
  },
  {
    name: "stream.seal",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "files",
    conjugate: "stream.open",
    pairCaption: "Chunked AEAD (STREAM)",
    pairLabels: { forward: "Seal", reverse: "Open" },
    doc: "Chunked AES-GCM in the STREAM construction — the way to encrypt a *file*, since `SubtleCrypto.encrypt` is one-shot and its single tag only verifies after the last byte. Each 64 KiB chunk carries its own tag and its index in the nonce, so reorder, splice, and truncation are all detected. A fresh file key is wrapped under `key=@slot`, which is what makes counter nonces safe with a reused key. **Not age** — same construction, different AEAD and header (see `age.encrypt` for files the `age` CLI can read). Example: `file.read | stream.seal key=@cek | file.save name=doc.bskstrm`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live AES key slot (`@cek`) used to wrap the per-file key; omit to use the key panel",
      },
      {
        name: "chunk",
        type: "int",
        default: 65536,
        min: 1024,
        max: 4194304,
        doc: "Plaintext bytes per chunk (age uses 65536)",
      },
    ],
  },
  {
    name: "stream.open",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "files",
    conjugateOf: "stream.seal",
    doc: "Open a `stream.seal` file. Distinguishes its failures: a bad tag means the file was modified or its chunks reordered; a missing final-chunk flag means it was truncated. Chunk size is read from the header, so `chunk=` is not repeated here. Example: `file.read | stream.open key=@cek | file.save`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live AES key slot (`@cek`) the file was sealed under; omit to use the key panel",
      },
    ],
  },
  {
    name: "age.keygen",
    kind: "source",
    toolbox: "age",
    shelf: "keys",
    doc: "Generate an age X25519 identity (`AGE-SECRET-KEY-1…`) — the same thing `age-keygen` writes. Secret: the tile stays masked until you reveal it. Its public half comes from `age.recipient`. Example: `age.keygen | out @id`.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "age.recipient",
    kind: "transform",
    toolbox: "age",
    shelf: "keys",
    doc: "Identity → recipient (`age1…`): the publishable half, derived and not invertible. An `age1…` already on the stem passes through, so this is safe to write when you are unsure which half you hold. Example: `in @id | age.recipient | out @pub`.",
    input: "text",
    output: "text",
    params: [],
  },
  {
    name: "age.encrypt",
    kind: "transform",
    toolbox: "age",
    shelf: "files",
    conjugate: "age.decrypt",
    pairCaption: "age (age-encryption.org/v1)",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    doc: "Encrypt to age recipients — real `age-encryption.org/v1`, produced by typage (age's author's implementation), so `age -d` reads it. `to=` takes one or more `age1…` recipients or an `@slot`; `passphrase=` is the scrypt mode instead (never both). `armor=true` for the PEM-style text form. CLI: `age -r age1… -o doc.age doc`. Example: `file.read | age.encrypt to=@pub | file.save`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        // `string`, not `slot`, so a literal `age1…` parses — a recipient is
        // public, and `age -r age1…` is how everyone writes it. `key=` on the
        // decrypt side stays a `slot` for the opposite reason.
        name: "to",
        type: "string",
        positional: true,
        default: "",
        doc: "Recipients: `age1…` (space/comma separated) or an `@slot` holding them",
      },
      {
        name: "passphrase",
        type: "string",
        default: "",
        secret: true,
        doc: "Passphrase (scrypt) mode instead of recipients — `age -p`",
      },
      {
        name: "armor",
        type: "bool",
        default: false,
        doc: "PEM-style ASCII armor (`age -a`) — output is text, not bytes",
      },
    ],
    effectiveIo(params) {
      return { input: "bytes", output: params?.armor ? "text" : "bytes" };
    },
  },
  {
    name: "age.decrypt",
    kind: "transform",
    toolbox: "age",
    shelf: "files",
    conjugateOf: "age.encrypt",
    doc: "Decrypt an age file with `key=@identity` (or `passphrase=`). Accepts binary and armored input, including an armored file read as bytes. CLI: `age -d -i key.txt doc.age`. Example: `file.read | age.decrypt key=@id | file.save`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        // Deliberately a `slot` and not a string: a literal identity in `key=`
        // would be a private key sitting in recipe text, which is exactly what
        // Copy link, Export, and the workspace library then carry off.
        name: "key",
        type: "slot",
        positional: true,
        default: "",
        doc: "Slot holding an `AGE-SECRET-KEY-1…` identity (never write the identity inline — recipe text is shareable)",
      },
      {
        name: "passphrase",
        type: "string",
        default: "",
        secret: true,
        doc: "Passphrase, for a file encrypted with `age -p`",
      },
    ],
  },
  {
    name: "file.read",
    kind: "source",
    toolbox: "io",
    shelf: "ports",
    conjugate: "file.save",
    pairCaption: "File",
    pairLabels: { forward: "Read", reverse: "Save" },
    doc: "Open a file from disk into the pipeline. The browser's own picker is the consent — no extra prompt (unlike `clipboard.read`, where the page chooses when to look). Text-ish files arrive as `text`, everything else as `bytes`; force with `as=`. Filename and MIME ride along in meta, so `file.read | age.encrypt to=@pub | file.save` names the output for you. Main-thread only. Example: `file.read accept=.pem | inspect`.",
    input: "none",
    output: "bytes",
    params: [
      {
        name: "accept",
        type: "string",
        positional: true,
        default: "",
        doc: "Picker filter — extensions and/or MIME types (`.pem,.asc` or `text/plain`)",
      },
      {
        name: "as",
        type: "enum",
        default: "auto",
        enum: ["auto", "text", "bytes"],
        doc: "Pipeline type: auto sniffs MIME/extension; bytes never guesses an encoding",
      },
    ],
    effectiveIo(params) {
      // `auto` cannot be resolved until a file is chosen, so the declared type
      // is the safe one — bytes flows into everything text does via `utf8`,
      // and claiming `text` for an unopened picker would type-check recipes
      // that then break on a PNG.
      return { input: "none", output: String(params?.as) === "text" ? "text" : "bytes" };
    },
  },
  {
    name: "file.save",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    conjugateOf: "file.read",
    doc: "Write the current value to disk and pass it through, like `out`. Uses the File System Access API's Save dialog where present, otherwise a plain download. The name comes from `name=`, else the value's own meta (a `file.read` upstream, or `age.encrypt`), else `output.bin`. Example: `… | age.encrypt to=@pub | file.save name=doc.age`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "",
        doc: "Filename to suggest (empty = inherit from the value's meta)",
      },
      {
        name: "mime",
        type: "string",
        default: "",
        doc: "MIME type override (empty = infer from the value)",
      },
    ],
  },
  {
    name: "text",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    doc: "Emit a message tile (no filename; Encrypt compose). Prefer `out @label` when you need a file tile + reusable slot. (Legacy aliases `print`/`echo` migrate via Upgrade recipe.)",
    input: "text",
    output: "text",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "text",
        doc: "Tile label",
      },
      {
        name: "label",
        type: "string",
        default: "",
        doc: "Display label override (defaults to name)",
      },
    ],
  },
  {
    name: "out",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    conjugateOf: "input",
    doc: "Emit a file tile, register a live `@slot` for later `in`, and pass through. Prefer `out @public` (bare `out public` rewrites to `@`). File paths reserved — not supported yet.",
    input: "text",
    output: "text",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "@output",
        doc: "Slot / filename stem — `@label` (canonical); bare ident rewrites to `@ident`",
      },
      {
        name: "encoding",
        type: "enum",
        default: "auto",
        enum: ["auto", "text", "base64", "hex"],
        doc: "How pipeline bytes are shown in the tile (file handoff still uses zeroable raw bytes when available)",
      },
      {
        name: "ext",
        type: "string",
        default: "",
        doc: "File extension (e.g. pem, asc, bin) — empty = infer",
      },
      {
        name: "mime",
        type: "string",
        default: "",
        doc: "MIME type override (empty = infer)",
      },
      {
        name: "label",
        type: "string",
        default: "",
        doc: "Display label on the results tile (defaults to name)",
      },
    ],
  },
  {
    name: "webauthn.caps",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    doc: "Probe WebAuthn / PublicKeyCredential capabilities (platform UVPA, conditional UI, clientCapabilities). Output JSON text. No CAST — discovery only.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "webauthn.create",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    doc: "Create a WebAuthn credential with PRF (platform or roaming). Returns PRF IKM bytes for HKDF/`aes-gcm`. Soft MDS on attestation; does not block. Main-thread only.",
    input: "none",
    output: "bytes",
    params: [
      {
        name: "user",
        type: "string",
        positional: true,
        default: "basilisk-toolkit",
        doc: "User name shown on the authenticator prompt",
      },
    ],
  },
  {
    name: "webauthn.get",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    doc: "WebAuthn assertion ceremony; emits clientExtensionResults JSON (inspect PRF support). For pipeline PRF IKM bytes use `webauthn.prf`. Main-thread only.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "webauthn.prf",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    doc: "Unlock PRF IKM from the vault passkey (same ceremony as My Keys unlock). Pipe into `hkdf` / `aes-gcm`. Main-thread only. Example: `webauthn.prf | hkdf length=32 | …`.",
    input: "none",
    output: "bytes",
    params: [],
  },
  {
    name: "webauthn.attest",
    kind: "transform",
    toolbox: "webauthn",
    shelf: "attestation",
    doc: "Parse WebAuthn attestationObject (bytes, or base64/hex text from Inputs) → JSON (fmt, aaguid). Soft / informational — not a CAST gate. Template: Templates → WebAuthn → Attestation → MDS.",
    input: "bytes",
    output: "text",
    overloads: [
      { when: { base: "bytes" }, output: { base: "text", kind: "opaque" } },
      { when: { base: "text" }, output: { base: "text", kind: "opaque" } },
    ],
    params: [],
  },
  {
    name: "webauthn.mds",
    kind: "transform",
    toolbox: "webauthn",
    shelf: "attestation",
    doc: "Soft FIDO MDS lookup for an AAGUID (param or prior JSON aaguid from `webauthn.attest`). verified/unverified/unavailable — never blocks crypto. Same-origin MDS proxy.",
    input: "text",
    output: "text",
    params: [
      {
        name: "aaguid",
        type: "string",
        positional: true,
        default: "",
        doc: "AAGUID UUID (empty = read from prior JSON text)",
      },
    ],
  },
  // ── JOSE toolbox — JWS / JWE / JWT (RFC 7515 / 7516 / 7519) ──
  //
  // Its own toolbox rather than a shelf under WebCrypto: JOSE is a wire
  // format with its own key metadata, header parameters, and failure modes,
  // and folding it into `webcrypto` would put `jose.decode` — which does no
  // crypto at all — beside `aes-gcm`. The ops do run on WebCrypto, but so
  // does OpenPGP-adjacent work that has its own toolbox for the same reason.
  {
    name: "jose.decode",
    kind: "transform",
    toolbox: "jose",
    shelf: "token",
    doc: "Inspect a compact JWS/JWE **without verifying it** — header plus claims, marked unverified. This is the safe first move on a token you were handed: it never checks a signature, so it never implies one was valid. Example: `input | jose.decode | out @claims`. To trust the contents, use `jose.verify`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "json",
        enum: ["json", "compact"],
        doc: "Pretty-printed JSON (default) or one line",
      },
    ],
  },
  {
    name: "jose.sign",
    kind: "transform",
    toolbox: "jose",
    shelf: "token",
    conjugate: "jose.verify",
    pairCaption: "JWS (RFC 7515)",
    pairLabels: { forward: "Sign", reverse: "Verify" },
    doc: "Sign the pipeline payload into a compact JWS (a JWT when the payload is JSON claims). `alg=auto` reads the algorithm off the key; naming one is checked against the key, never trusted. Example: `input | jose.sign key=@k alg=es256 | out @token`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live signing key slot (`@k`) — private half or HMAC secret",
      },
      {
        name: "alg",
        type: "enum",
        default: "auto",
        enum: ["auto", "hs256", "hs384", "hs512", "rs256", "ps256", "es256", "es384", "es512", "eddsa"],
        doc: "JWS algorithm; `auto` derives it from the key. Serialized uppercase in the header (es256 → ES256).",
      },
      {
        name: "typ",
        type: "string",
        default: "JWT",
        doc: "Header `typ` (empty to omit)",
      },
      {
        name: "kid",
        type: "string",
        default: "",
        doc: "Optional header `kid` (key id)",
      },
    ],
  },
  {
    name: "jose.verify",
    kind: "transform",
    toolbox: "jose",
    shelf: "token",
    conjugateOf: "jose.sign",
    doc: "Verify a compact JWS and emit its payload. Fail-loud with no soft mode — an unverified payload is attacker-chosen, so there is nothing to branch on; inspect those with `jose.decode`. Refuses `alg=none` and any header that disagrees with the bound key (algorithm confusion). `exp`/`nbf` are checked unless `expiry=ignore`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live verification key slot (`@pub`) — public half or HMAC secret",
      },
      {
        name: "alg",
        type: "enum",
        default: "auto",
        enum: ["auto", "hs256", "hs384", "hs512", "rs256", "ps256", "es256", "es384", "es512", "eddsa"],
        doc: "Require this algorithm (`auto` = whatever the key supports; the header must match the key either way)",
      },
      {
        name: "expiry",
        type: "enum",
        default: "check",
        enum: ["check", "ignore"],
        doc: "Enforce `exp` / `nbf` after the signature checks out, or report them without failing",
      },
    ],
  },
  {
    name: "jose.encrypt",
    kind: "transform",
    toolbox: "jose",
    shelf: "envelope",
    conjugate: "jose.decrypt",
    pairCaption: "JWE (RFC 7516)",
    pairLabels: { forward: "Encrypt", reverse: "Decrypt" },
    doc: "Encrypt the payload into a compact JWE. AES-GCM content encryption only (`enc=a128gcm|a192gcm|a256gcm`); key management is `dir` (the slot key *is* the CEK), AES-KW, or RSA-OAEP-256. Example: `input | jose.encrypt key=@cek | out @jwe`.",
    input: "text",
    output: "text",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live key slot — the CEK for `dir`, the KEK for AES-KW, the RSA public key for RSA-OAEP-256",
      },
      {
        name: "alg",
        type: "enum",
        default: "dir",
        enum: ["dir", "a128kw", "a256kw", "rsa-oaep-256"],
        doc: "Key-management algorithm (uppercased in the header: a256kw → A256KW)",
      },
      {
        name: "enc",
        type: "enum",
        default: "a256gcm",
        enum: ["a128gcm", "a192gcm", "a256gcm"],
        doc: "Content encryption. Only the AEAD modes are implemented — A*CBC-HS* is a composite construction WebCrypto cannot do in one call.",
      },
      {
        name: "kid",
        type: "string",
        default: "",
        doc: "Optional header `kid`",
      },
    ],
  },
  {
    name: "jose.decrypt",
    kind: "transform",
    toolbox: "jose",
    shelf: "envelope",
    conjugateOf: "jose.encrypt",
    doc: "Decrypt a compact JWE and emit its plaintext. `alg` / `enc` come from the token's protected header, which is also the AEAD's additional data — tampering with either breaks the tag rather than changing how it decrypts.",
    input: "text",
    output: "text",
    params: [
      {
        name: "key",
        type: "slot",
        default: "",
        doc: "Live key slot — the CEK for `dir`, the KEK for AES-KW, the RSA private key for RSA-OAEP-256",
      },
    ],
  },
  {
    name: "inspect",
    kind: "transform",
    toolbox: "flow",
    shelf: "control",
    doc: "Human-readable dump of the current value (openssl-style / hexdump). Tile keeps a snapshot for live format switching. Example: `genkey ec/p256 | tee` / `- :private | inspect`. (Legacy aliases `dump`/`hexdump` migrate via Upgrade recipe.)",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "auto",
        enum: ["auto", "text", "hex", "hexdump", "jwk", "meta"],
        doc: "Initial dump style (`hexdump` alias forces hexdump). Changeable on the result tile without re-run.",
      },
    ],
  },
  {
    name: "tee",
    kind: "transform",
    toolbox: "flow",
    shelf: "control",
    doc: "Fork side chains on a clone (`- :public | …`); stem continues unchanged. Use `peek` for a side inspect only.",
    input: "bytes",
    output: "bytes",
    params: [],
  },
  {
    name: "peek",
    kind: "transform",
    toolbox: "flow",
    shelf: "control",
    doc: "Side inspect snapshot; stem unchanged. Use instead of an empty `tee`. Example: `genkey ec/p256 | peek keypair | export pkcs8 | pem | out @private`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "peek",
        doc: "Artifact label / filename stem (e.g. `keypair`)",
      },
      {
        name: "format",
        type: "enum",
        default: "auto",
        enum: ["auto", "text", "hex", "hexdump", "jwk", "meta"],
        doc: "Initial inspection format (changeable on the tile)",
      },
    ],
  },
  // ── Quorum toolbox (design v2 §21a) — the run boundary is the session boundary ──
  {
    name: "rtc.ice",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "ICE server config for a quorum exchange — STUN for reflexive discovery, optional TURN relay with credentials. Emits JSON consumed by `quorum.offer`/`quorum.join` via `ice=@slot`. `credential=` takes a **slot**, not a literal, so the secret never rides out through Copy link or an exported notebook. Example: `rtc.ice turn=turn:relay.example.org:3478 username=u credential=@turncred | out @ice`. Defaults: Cloudflare + Google STUN.",
    input: "none",
    output: "endpoint",
    params: [
      {
        name: "stun",
        type: "string",
        positional: true,
        default: "",
        doc: "Comma-separated stun: URLs. Empty = built-in defaults (Cloudflare + Google).",
      },
      {
        name: "turn",
        type: "string",
        default: "",
        doc: "turn:/turns: relay URL (needed when both peers are behind symmetric NAT)",
      },
      { name: "username", type: "string", default: "", doc: "TURN username" },
      {
        name: "credential",
        type: "slot",
        secret: true,
        default: "",
        doc: "TURN credential — bind an @slot from Inputs; never stored/shared as literal text",
      },
    ],
  },
  {
    name: "stun.check",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "One-shot NAT diagnostic: gathers ICE candidates against a STUN server and reports the server-reflexive (public) address, candidate mix, and gather time as JSON. Not publishable — a plain output row. Example: `stun.check | out @nat`.",
    input: "none",
    output: "endpoint",
    params: [
      {
        name: "server",
        type: "string",
        positional: true,
        default: "stun:stun.cloudflare.com:3478",
        doc: "STUN server URL",
      },
      {
        name: "timeout",
        type: "int",
        default: 4000,
        doc: "Gather timeout (ms)",
      },
    ],
  },
  {
    name: "quorum.offer",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "agent",
    doc: "Open a run-scoped p2p exchange as creator: derives the room from the audience, publishes a PGP-signed invite through the encrypted relay, then PAUSES the run at this cell until a peer meshes (or `wait` expires). Output is the session summary JSON; `rtc.send`/`rtc.recv`/`quorum.close` downstream use the live session. Example: `quorum.offer to=\"AABB…,CCDD…\" key=@me | out @session`. Main-thread (WebRTC).",
    input: "none",
    output: "session",
    params: [
      {
        name: "to",
        type: "string",
        positional: true,
        default: "",
        doc: "Audience fingerprints (comma/space separated) — must include your own",
      },
      {
        name: "key",
        type: "slot",
        secret: true,
        default: "",
        doc: "@slot holding your armored private key (`agent.unlock … | out @me`)",
      },
      {
        name: "ice",
        type: "string",
        default: "",
        doc: "@slot holding `rtc.ice` JSON; empty = default STUN",
      },
      {
        name: "wait",
        type: "int",
        default: 120000,
        doc: "How long to wait for the first peer (ms)",
      },
      {
        name: "peers",
        type: "int",
        default: 1,
        doc: "Peers that must connect before the run continues",
      },
    ],
  },
  {
    name: "quorum.join",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "agent",
    doc: "Join a run-scoped exchange as peer: verifies the creator's signed invite, then meshes with per-peer ephemeral ECDH (data-channel PFS). Pauses the run at this cell until connected. Same audience + site = same room, no code to paste. Example: `quorum.join to=\"AABB…,CCDD…\" key=@me | out @session`. Main-thread (WebRTC).",
    input: "none",
    output: "session",
    params: [
      {
        name: "to",
        type: "string",
        positional: true,
        default: "",
        doc: "Audience fingerprints (comma/space separated) — must include your own",
      },
      {
        name: "key",
        type: "slot",
        secret: true,
        default: "",
        doc: "@slot holding your armored private key",
      },
      {
        name: "ice",
        type: "string",
        default: "",
        doc: "@slot holding `rtc.ice` JSON; empty = default STUN",
      },
      {
        name: "wait",
        type: "int",
        default: 120000,
        doc: "How long to wait for invite + mesh (ms)",
      },
      {
        name: "peers",
        type: "int",
        default: 1,
        doc: "Peers that must connect before the run continues",
      },
    ],
  },
  {
    name: "rtc.send",
    kind: "transform",
    toolbox: "webrtc",
    shelf: "channel",
    glyph: "agent",
    doc: "Write the pipeline text to the live data channel (per-peer session keys; key-confirmed channels only). `to=` addresses one peer by fingerprint; empty broadcasts to every verified peer, which is the exchange's own policy. Passes the value through unchanged. Requires a `quorum.offer`/`quorum.join` earlier in this run.",
    input: "text",
    output: "text",
    params: [
      {
        name: "to",
        type: "string",
        positional: true,
        default: "",
        doc: "Recipient fingerprint (prefix ok); empty = every verified peer",
      },
    ],
  },
  {
    name: "rtc.recv",
    kind: "source",
    toolbox: "webrtc",
    shelf: "channel",
    glyph: "agent",
    doc: "Read from the live data channel. `count=1` (default) waits for one message and emits it as text (`meta.from` = sender fingerprint); `count=3` or `count=all` collects several and emits a bundle for `foreach`. Pauses the run until enough arrive or `wait` expires. Example: `rtc.recv | gpg.verify`, or `rtc.recv count=all | foreach\\n  - gpg.verify`.",
    input: "none",
    output: "text",
    params: [
      {
        name: "from",
        type: "string",
        default: "",
        doc: "Only accept from this fingerprint (prefix ok); empty = any peer",
      },
      {
        name: "count",
        type: "string",
        default: "1",
        doc: "How many to collect: 1 (text), a number, or `all` to drain the inbox (bundle)",
      },
      {
        name: "wait",
        type: "int",
        default: 120000,
        doc: "Receive timeout (ms)",
      },
    ],
    effectiveIo(params) {
      // The output *type* changes with `count`, so the caret and the type
      // checker see a bundle only when one is actually produced. Reporting
      // `text` for a multi-message read would let `gpg.verify` be appended to
      // something that is really a collection — exactly the mistake the type
      // system exists to catch.
      const count = String(params?.count ?? "1").trim().toLowerCase();
      return { input: "none", output: count === "1" ? "text" : "bundle" };
    },
  },
  {
    name: "quorum.close",
    kind: "transform",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "agent",
    doc: "End the exchange now: closes every peer connection and zeroizes session keys. Runs implicitly at Clear session — close early when the exchange is done mid-notebook. Passes the value through.",
    input: "text",
    output: "text",
    params: [],
  },

  // ── WebRTC primitives (design v2 §23a/23b/26a/26b/29a/29d/30d) ──
  // The raw layer under `quorum.*`: each wraps one browser WebRTC capability
  // so ICE/DTLS/SCTP are debuggable outside a live session.
  {
    name: "rtc.gather",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "Gather ICE candidates against the configured servers and emit one row per candidate — `host` (local NIC), `srflx` (server-reflexive, via STUN), `relay` (via TURN), plus any `prflx` peer-reflexive found by trickle. Each row carries protocol (`udp`/`tcp`). A missing `relay` row is informational, not an error — it just means no TURN is configured. This is what `quorum.offer` consumes internally; run it standalone to see why a later connection failed. Example: `rtc.ice turn=… | out @ice` then `rtc.gather ice=@ice | out @cands`.",
    input: "none",
    output: "candidate",
    params: [
      {
        name: "ice",
        type: "slot",
        default: "",
        doc: "@slot holding `rtc.ice` JSON; empty = default STUN",
      },
      {
        name: "timeout",
        type: "int",
        default: 5000,
        doc: "Gather timeout (ms) — trickle can keep finding candidates until this elapses",
      },
    ],
  },
  {
    name: "rtc.check",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "Report the ICE candidate-pair check matrix for the live exchange: one row per local×remote pair with its state (`waiting`/`in-progress`/`succeeded`/`failed`), the nominated pair flagged, plus this peer's `controlling`/`controlled` role. Needs a live `quorum.offer`/`quorum.join` — ICE only checks pairs once both sides have exchanged candidates. Example: `quorum.offer … | out @s` then `rtc.check | out @pairs`.",
    input: "none",
    output: "stats",
    params: [],
  },
  {
    name: "rtc.certificate",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "genkey",
    doc: "Generate a DTLS identity (`RTCCertificate`) — the certificate whose fingerprint the remote peer sees. Mirrors `genkey`'s shape. Most recipes never need this: `quorum.offer` mints a throwaway certificate itself. Use it when you want a stable fingerprint a peer can recognize across sessions. Example: `rtc.certificate | out @id`.",
    input: "none",
    output: "certificate",
    params: [
      {
        name: "alg",
        type: "enum",
        positional: true,
        default: "ecdsa",
        enum: ["ecdsa", "rsa"],
        doc: "Certificate key algorithm (ECDSA P-256 or RSASSA-PKCS1-v1_5 2048)",
      },
    ],
  },
  {
    name: "rtc.offer",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "agent",
    doc: "Raw SDP offer — the escape hatch below `quorum.offer` for inspecting or hand-carrying the session description. Creates a peer connection with one data channel and emits its SDP as text. Does not signal anything; pair it with your own transport. Example: `rtc.offer | out @sdp`.",
    input: "none",
    output: "sdp",
    params: [
      {
        name: "ice",
        type: "slot",
        default: "",
        doc: "@slot holding `rtc.ice` JSON; empty = default STUN",
      },
      {
        name: "label",
        type: "string",
        default: "basilisk",
        doc: "Data-channel label carried in the SDP",
      },
    ],
  },
  {
    name: "rtc.answer",
    kind: "transform",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "agent",
    doc: "Raw SDP answer for a piped offer — the `rtc.offer` conjugate. Takes the remote offer SDP as pipeline text, applies it as the remote description, and emits the local answer SDP. Example: `in @remoteOffer | rtc.answer | out @answer`.",
    input: "sdp",
    output: "sdp",
    params: [
      {
        name: "ice",
        type: "slot",
        default: "",
        doc: "@slot holding `rtc.ice` JSON; empty = default STUN",
      },
    ],
  },
  {
    name: "rtc.state",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "ports",
    doc: "Observe-only snapshot of the live exchange's `connectionState`, `iceConnectionState`, `iceGatheringState`, and `signalingState`, per peer. Diagnostic — never bind it as an input to a crypto op. Needs a live `quorum.offer`/`quorum.join`. Example: `rtc.state | out @state`.",
    input: "none",
    output: "connstate",
    params: [],
  },
  {
    name: "dkg.run",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "split",
    doc: "**Experimental.** Run a distributed key generation across the live exchange (Feldman VSS over P-256): every participant deals a contribution, verifies what they receive, and sums — so the private key is never assembled anywhere, and any `threshold` of the room can reconstruct it later. Needs a live `quorum.offer`/`quorum.join` with every participant present. There is no complaint round: a bad share aborts the run and names the dealer, and the group must restart without them. Produces a shared key, **not** threshold signing. Example: `dkg.run threshold=3 | out @dkg`.",
    input: "none",
    output: "text",
    params: [
      {
        name: "threshold",
        type: "int",
        default: 2,
        min: 1,
        max: 16,
        doc: "Participants required to reconstruct later (K)",
      },
      {
        name: "wait",
        type: "int",
        default: 120000,
        doc: "How long to wait for the other participants (ms)",
      },
    ],
  },
  {
    name: "rtc.restart",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "ports",
    doc: "Restart ICE on every peer connection of the live exchange and report the resulting per-peer state. Renegotiates in place — room, invite, and roster survive. The chainable form of the Connections panel's Restart button. Example: `rtc.restart | out @state`.",
    input: "none",
    output: "connstate",
    params: [],
  },
  {
    name: "rtc.stats",
    kind: "source",
    toolbox: "webrtc",
    shelf: "channel",
    glyph: "ports",
    doc: "Data-channel back-pressure and counters for the live exchange: `bufferedAmount` against its low-water threshold, ready state, and messages/bytes sent+received per peer. Use it to see whether `rtc.send` is queueing behind a slow link. Example: `rtc.stats | out @bp`.",
    input: "none",
    output: "stats",
    params: [],
  },
  {
    name: "rtc.quality",
    kind: "source",
    toolbox: "webrtc",
    shelf: "rtcstats",
    glyph: "ports",
    doc: "Live `getStats()` quality numbers for the exchange — round-trip time, bytes/packets each way, and packet loss per connected peer. Example: `rtc.quality | out @quality`.",
    input: "none",
    output: "stats",
    params: [],
  },
];

/**
 * Stamp the universal passthroughs with their real input type.
 *
 * `out`, `tee`, `peek`, `inspect`, `text`, `select`, and `in` accept *any*
 * value — the type checker has always known this, but each of them declared
 * `input: "bytes"` and relied on a hardcoded name list to override it. The
 * declaration was therefore a lie, and anything reading signatures rather
 * than asking the checker inherited it: the type browser reported that
 * nothing at all consumes `stats` or `candidate`, when in fact every one of
 * these does.
 *
 * Applied here rather than written into each spec so `POLYMORPHIC_STEPS`
 * stays the single source of truth — types.js owns it, and importing the
 * registry from there would close a cycle.
 */
for (const step of STEPS) {
  // Sources are excluded: `in` is in the passthrough set because it re-roots
  // the pipeline mid-chain, but it *reads a slot* rather than consuming a
  // tip, so its input is genuinely `none` and marking it `any` would put it
  // in every type's "accepted by" list.
  if (step.kind !== "source" && POLYMORPHIC_STEPS.has(step.name)) step.input = "any";
}

/** @type {Map<string, StepSpec>} */
const BY_NAME = new Map();
/** @type {Map<string, string>} */
const ALIAS_TO_CANONICAL = new Map();

/**
 * Explicit per-verb glyph ids. Conjugates / decodeTwins share one asset;
 * direction is shown by encode/decode tile tint in the ops drawer.
 * @type {Record<string, string>}
 */
export const STEP_GLYPHS = {
  genkey: "genkey",
  export: "export",
  import: "import",
  digest: "digest",
  sign: "sign",
  verify: "sign",
  "aes-gcm": "aead",
  "aes-cbc": "cipher",
  "aes-ctr": "cipher",
  "rsa-oaep": "rsa",
  "rsa-pkcs1": "rsa",
  hkdf: "hkdf",
  pbkdf2: "pbkdf2",
  ecdh: "agreement",
  wrap: "wrap",
  unwrap: "wrap",
  pem: "pem",
  der: "pem",
  base64: "base64",
  base64url: "base64",
  to: "hex",
  from: "hex",
  base32: "base32",
  utf8: "text",
  random: "random",
  passphrase: "passphrase",
  input: "input",
  out: "out",
  qr: "qr",
  "clipboard.read": "clipboard",
  "clipboard.write": "clipboard",
  "file.read": "file-read",
  "file.save": "file-save",
  "stream.seal": "stream",
  "stream.open": "stream",
  "age.keygen": "age-key",
  "age.recipient": "age-key",
  "age.encrypt": "age-lock",
  "age.decrypt": "age-lock",
  text: "text-sink",
  shares: "shares",
  "sss.split": "split",
  "sss.combine": "recover",
  blip39: "blip39",
  at: "at",
  foreach: "foreach",
  tee: "tee",
  in: "in",
  select: "select",
  as: "as",
  inspect: "inspect",
  peek: "peek",
  "agent.sign": "agent-sign",
  "agent.decrypt": "agent-decrypt",
  "ssh.encode": "ssh-key",
  "ssh.decode": "ssh-key",
  "ssh.fingerprint": "fingerprint",
  "ssh.sign": "sshsig-sign",
  "ssh.verify": "sshsig-sign",
  "gpg.encrypt": "gpg-encrypt",
  "gpg.decrypt": "gpg-decrypt",
  "gpg.sign": "gpg-sign",
  "gpg.verify": "gpg-sign",
  "gpg.genkey": "gpg-genkey",
  "gpg.inspect": "gpg-inspect",
  "gpg.symencrypt": "gpg-sym",
  "gpg.symdecrypt": "gpg-sym",
  "agent.unlock": "unlock",
  "agent.pub": "pubkey",
  "agent.list": "agent-list",
  "agent.save": "agent-save",
  "hkp.search": "hkp-search",
  "hkp.get": "hkp-get",
  "hkp.filter": "hkp-filter",
  "hkp.cache": "hkp-cache",
  "recipients.merge": "recipients",
  "webauthn.create": "wa-create",
  "webauthn.get": "wa-get",
  "webauthn.prf": "wa-prf",
  "webauthn.caps": "wa-caps",
  "webauthn.attest": "wa-attest",
  "webauthn.mds": "wa-mds",
  "jose.decode": "jose-decode",
  "jose.sign": "jose",
  "jose.verify": "jose",
  "jose.encrypt": "jose-jwe",
  "jose.decrypt": "jose-jwe",
};

for (const step of STEPS) {
  const assigned = STEP_GLYPHS[step.name] || step.glyph;
  if (assigned) step.glyph = assigned;
  else if (step.shelf && SHELF_META[step.shelf]?.glyph) {
    step.glyph = SHELF_META[step.shelf].glyph;
  } else if (TOOLBOX_META[step.toolbox]?.glyph) {
    step.glyph = TOOLBOX_META[step.toolbox].glyph;
  } else {
    step.glyph = "gear";
  }
  // Keys are lower-cased because `getStep`/`canonicalName` lower-case their
  // query — storing the original case would make any mixed-case op name
  // (e.g. `rtc.gather`) silently unresolvable. `step.name` keeps
  // its authored casing for display and serialization.
  BY_NAME.set(step.name.toLowerCase(), step);
  ALIAS_TO_CANONICAL.set(step.name.toLowerCase(), step.name);
  for (const a of step.aliases || []) {
    ALIAS_TO_CANONICAL.set(String(a).toLowerCase(), step.name);
    BY_NAME.set(String(a).toLowerCase(), step);
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
 * Familiar alias hints shown in the cipher meta-picker (not parse forms themselves).
 * @type {Record<string, string[]>}
 */
export const CIPHER_PICKER_ALIASES = {
  "aes-gcm": ["AES/GCM/NoPadding", "aes-256-gcm"],
  "aes-cbc": ["AES/CBC/PKCS5Padding", "aes-256-cbc"],
  "aes-ctr": ["AES/CTR/NoPadding", "aes-256-ctr"],
  "rsa-oaep": ["RSA/ECB/OAEPWithSHA-256AndMGF1Padding"],
  "rsa-pkcs1": ["RSA/ECB/PKCS1Padding"],
};

/**
 * @typedef {object} OpCollectionMember
 * @property {string} id
 * @property {string} name  StepSpec.name
 * @property {string} label  short mode caption (GCM, Base64, OAEP)
 * @property {string} [title]
 */

/**
 * Op family for shelf kits (AES modes, RSA paddings, Base64/Base32, …).
 * Members are usually `kitOnly`; recipe verbs stay concrete.
 *
 * @typedef {object} OpCollection
 * @property {string} id
 * @property {string} label
 * @property {Toolbox} toolbox
 * @property {string} shelf  insert near this shelf order
 * @property {string} glyph
 * @property {{ forward: string, reverse: string }} actionLabels
 * @property {string[]} [search]  filter needles for kit visibility
 * @property {OpCollectionMember[]} members
 */

/** @type {Record<string, OpCollection>} */
export const OP_COLLECTIONS = {
  aes: {
    id: "aes",
    label: "AES",
    toolbox: "webcrypto",
    shelf: "aead",
    glyph: "aead",
    actionLabels: { forward: "Encrypt", reverse: "Decrypt" },
    search: ["cipher", "encrypt", "decrypt", "aes", "aead", "gcm", "cbc", "ctr"],
    members: [
      {
        id: "gcm",
        name: "aes-gcm",
        label: "GCM",
        title: "AES-GCM — authenticated encrypt / decrypt",
      },
      {
        id: "cbc",
        name: "aes-cbc",
        label: "CBC",
        title: "AES-CBC — unauthenticated (prefer GCM)",
      },
      {
        id: "ctr",
        name: "aes-ctr",
        label: "CTR",
        title: "AES-CTR — unauthenticated (prefer GCM)",
      },
    ],
  },
  rsa: {
    id: "rsa",
    label: "RSA",
    toolbox: "webcrypto",
    shelf: "rsa",
    glyph: "rsa",
    actionLabels: { forward: "Encrypt", reverse: "Decrypt" },
    search: ["cipher", "encrypt", "decrypt", "rsa", "oaep", "pkcs"],
    members: [
      {
        id: "oaep",
        name: "rsa-oaep",
        label: "OAEP",
        title: "RSA-OAEP — preferred RSA encrypt / decrypt",
      },
      {
        id: "pkcs1",
        name: "rsa-pkcs1",
        label: "PKCS1",
        title: "RSAES-PKCS1-v1_5 — discouraged (prefer OAEP)",
      },
    ],
  },
  encoding: {
    id: "encoding",
    label: "Base",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "binary",
    actionLabels: { forward: "Encode", reverse: "Decode" },
    search: [
      "encode",
      "decode",
      "base64",
      "base64url",
      "base32",
      "binary",
    ],
    members: [
      {
        id: "base64",
        name: "base64",
        label: "Base64",
        title: "Base64 encode / decode",
      },
      {
        id: "base64url",
        name: "base64url",
        label: "Base64url",
        title: "URL-safe Base64 encode / decode",
      },
      {
        id: "base32",
        name: "base32",
        label: "Base32",
        title: "RFC 4648 Base32 encode / decode",
      },
    ],
  },
};

/**
 * @returns {OpCollection[]}
 */
export function listOpCollections() {
  return Object.values(OP_COLLECTIONS);
}

/**
 * @param {string} id
 * @returns {OpCollection|null}
 */
export function getOpCollection(id) {
  return OP_COLLECTIONS[id] || null;
}

/**
 * @param {string} stepName
 * @returns {OpCollection|null}
 */
export function collectionForStep(stepName) {
  const name = String(stepName || "");
  for (const col of listOpCollections()) {
    if (col.members.some((m) => m.name === name)) return col;
  }
  return null;
}

/**
 * Friendly shelf-tile verb (Encrypt / Decode / …). Null → use recipe display name.
 * @param {StepSpec|null|undefined} step
 * @param {{ decode?: boolean, pairRole?: "forward"|"reverse"|"solo" }} [opts]
 * @returns {string|null}
 */
export function pairTileLabel(step, opts = {}) {
  if (!step) return null;
  let labels = step.pairLabels || null;
  if (!labels) {
    const col = collectionForStep(step.name);
    if (col) labels = col.actionLabels;
  }
  if (!labels && step.conjugateOf) {
    const fwd = getStep(step.conjugateOf);
    labels = fwd?.pairLabels || null;
  }
  if (!labels) return null;
  const reverse = !!opts.decode || opts.pairRole === "reverse";
  if (reverse) return labels.reverse;
  if (
    opts.pairRole === "forward" ||
    opts.pairRole === "solo" ||
    step.decodeTwin ||
    step.conjugate
  ) {
    return labels.forward;
  }
  return labels.forward;
}

/**
 * AES modes for the OpsShelf AES drawer (kitOnly steps — not shelf tiles).
 * @type {OpCollectionMember[]}
 */
export const AES_MODE_PICKS = OP_COLLECTIONS.aes.members;

/**
 * RSA paddings for the OpsShelf RSA drawer (kitOnly steps — not shelf tiles).
 * @type {OpCollectionMember[]}
 */
export const RSA_PADDING_PICKS = OP_COLLECTIONS.rsa.members;

/**
 * Base64 / Base64url / Base32 for the encoding collection drawer.
 * @type {OpCollectionMember[]}
 */
export const ENCODING_MODE_PICKS = OP_COLLECTIONS.encoding.members;

/**
 * WebCrypto cipher steps offered by the Encrypt/Decrypt meta-picker.
 * Order: AEAD → Cipher → RSA (matches shelf taxonomy).
 * @returns {StepSpec[]}
 */
export function listCipherPickerSteps() {
  const order = ["aes-gcm", "aes-cbc", "aes-ctr", "rsa-oaep", "rsa-pkcs1"];
  /** @type {StepSpec[]} */
  const out = [];
  for (const name of order) {
    if (!CIPHER_DISPATCH_TARGETS.has(name)) continue;
    const spec = getStep(name);
    if (spec) out.push(spec);
  }
  return out;
}

/**
 * Builder payload when instantiating a cipher from the meta-picker.
 * Never returns name "encrypt" / "decrypt".
 * @param {string} concreteName
 * @param {boolean} [decode]
 * @returns {{ name: string, params: { decode?: boolean } }}
 */
export function instantiateCipherPick(concreteName, decode = false) {
  const name = String(concreteName || "").toLowerCase();
  if (!CIPHER_DISPATCH_TARGETS.has(name) || !getStep(name)) {
    throw new Error(`Unknown cipher pick "${concreteName}"`);
  }
  return decode ? { name, params: { decode: true } } : { name, params: {} };
}

/** Export/import formats offered by the Key formats meta-picker. */
export const KEY_FORMAT_PICKS = ["pkcs8", "spki", "jwk", "raw", "scalar"];

/**
 * Drawer labels / titles for key-format picks (openssl-flavored).
 * @type {Record<string, { label: string, title: string }>}
 */
export const KEY_FORMAT_META = {
  pkcs8: {
    label: "PKCS#8",
    title: "Private key PKCS#8 (openssl pkcs8 / pkey)",
  },
  spki: {
    label: "SPKI",
    title: "Public key SPKI (openssl pkey -pubout)",
  },
  jwk: {
    label: "JWK",
    title: "JSON Web Key (text)",
  },
  raw: {
    label: "raw",
    title: "Raw key bytes",
  },
  scalar: {
    label: "scalar",
    title: "Private scalar / d (fixed-length bytes for SSS)",
  },
};

/**
 * Tip-implied export vs import for the Formats kit (null → ask Export|Import).
 * @param {{ base?: string, kind?: string, encoding?: string }|null|undefined} tip
 * @returns {"export"|"import"|null}
 */
export function formatDirectionForTip(tip) {
  if (!tip || tip.base === "none") return null;
  if (tip.base === "keypair" || tip.base === "key") return "export";
  if (tip.base === "bytes") return "import";
  if (
    tip.base === "text" &&
    (tip.encoding === "jwk" || tip.kind === "pem" || tip.encoding === "pem")
  ) {
    return "import";
  }
  return null;
}

/**
 * @param {"export"|"import"} direction
 * @param {string} format
 * @returns {{ name: string, params: { format: string } }}
 */
export function instantiateFormatPick(direction, format) {
  const dir = direction === "import" ? "import" : "export";
  const fmt = String(format || "").toLowerCase();
  if (!KEY_FORMAT_PICKS.includes(fmt)) {
    throw new Error(`Unknown key format "${format}"`);
  }
  if (!getStep(dir)) throw new Error(`Missing step ${dir}`);
  return { name: dir, params: { format: fmt } };
}

/**
 * @param {string|undefined|null} shelf
 * @returns {ShelfMeta}
 */
export function getShelfMeta(shelf) {
  const key = String(shelf || "");
  return (
    SHELF_META[key] || {
      label: key || "Other",
      order: 99,
      defaultCollapsed: false,
    }
  );
}

/**
 * Default-collapsed shelf keys for the ops drawer (`toolbox:shelf`).
 * @returns {string[]}
 */
export function defaultCollapsedShelfKeys() {
  /** @type {Set<string>} */
  const keys = new Set();
  for (const s of STEPS) {
    if (!s.shelf) continue;
    if (getShelfMeta(s.shelf).defaultCollapsed) {
      keys.add(`${s.toolbox}:${s.shelf}`);
    }
  }
  return [...keys];
}

/**
 * Build conjugate / solo rows for a list of steps (typically one shelf).
 * Steps with `conjugateOf` are omitted (rendered beside their partner).
 * @param {StepSpec[]} items
 * @returns {DrawerRow[]}
 */
export function listDrawerRows(items) {
  /** @type {DrawerRow[]} */
  const rows = [];
  /** @type {Set<string>} */
  const seen = new Set();

  for (const s of items) {
    if (s.conjugateOf || seen.has(s.name)) continue;
    seen.add(s.name);

    if (s.decodeTwin) {
      rows.push({
        type: "pair",
        caption: s.pairCaption || s.name,
        forward: s,
        decodeTwin: true,
      });
      continue;
    }

    if (s.conjugate) {
      const reverse = getStep(s.conjugate);
      if (reverse && reverse.name === s.conjugate) {
        seen.add(reverse.name);
        rows.push({
          type: "pair",
          caption:
            s.pairCaption ||
            `${s.label || s.name} / ${reverse.label || reverse.name}`,
          forward: s,
          reverse,
        });
        continue;
      }
    }

    rows.push({ type: "solo", step: s });
  }

  return rows;
}

/** Reverse partners that are decode / inbound shaped (accent tint). */
const DECODE_CONJUGATE_REVERSES = new Set([
  "from",
  "der",
  "import",
  "unwrap",
  "verify",
  "out",
  "sss.combine",
  "gpg.decrypt",
  "gpg.verify",
  "gpg.symdecrypt",
]);

/**
 * Encode / decode / neutral direction for ops-tile tinting
 * (brand ≈ out/encode, accent ≈ in/decode).
 * @param {StepSpec} step
 * @param {{ decode?: boolean, pairRole?: "forward"|"reverse"|"solo" }} [opts]
 * @returns {"encode"|"decode"|"neutral"}
 */
export function pairDirection(step, opts = {}) {
  if (!step) return "neutral";
  if (opts.decode || (step.decodeTwin && opts.decode)) return "decode";
  if (opts.decode) return "decode";
  if (step.decodeTwin) {
    return opts.decode ? "decode" : "encode";
  }
  if (opts.pairRole === "reverse" || DECODE_CONJUGATE_REVERSES.has(step.name)) {
    return "decode";
  }
  if (opts.pairRole === "forward" && step.conjugate) return "encode";
  if (step.kind === "source" || step.kind === "flow") return "neutral";
  if (step.kind === "sink") return "encode";
  // Transforms: bytes→text tends encode; text→bytes tends decode
  const io = step.effectiveIo ? step.effectiveIo({}) : { input: step.input, output: step.output };
  if (io.input === "bytes" && io.output === "text") return "encode";
  if (io.input === "text" && io.output === "bytes") return "decode";
  return "neutral";
}

/**
 * Whether a compiled recipe needs the window thread (WebAuthn ceremonies /
 * localStorage MDS cache).
 * @param {{ steps?: { name: string, body?: { name: string }[] }[] } | null | undefined} ast
 * @returns {boolean}
 */
export function recipeNeedsMainThread(ast) {
  const visit = (steps) => {
    for (const step of steps || []) {
      const spec = getStep(step.name);
      if (spec?.toolbox === "webauthn") return true;
      if (
        step.name === "agent.unlock" ||
        step.name === "agent.save" ||
        // Boundary ops need the approval surface, the passkey ceremony and
        // IndexedDB — all main-thread (§26f).
        step.name === "agent.sign" ||
        step.name === "agent.decrypt"
      ) {
        return true;
      }
      if (step.name === "foreach" && visit(step.body || [])) return true;
      if (step.name === "tee") {
        if (visit(step.body || [])) return true;
        for (const br of step.branches || []) {
          if (visit(br.body || [])) return true;
        }
      }
    }
    return false;
  };
  const chains = ast?.chains || [];
  if (chains.length) {
    return chains.some((c) => visit(c.steps || []));
  }
  return visit(ast?.steps);
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
 * Accepts a coarse IoType string or a RefinedType.
 * @param {IoType|RefinedType|null} from
 * @returns {StepSpec[]}
 */
export function stepsAccepting(from) {
  /** @type {RefinedType} */
  const refined =
    from && typeof from === "object" && "base" in from
      ? /** @type {RefinedType} */ (from)
      : typeOf(/** @type {IoType} */ (from || "none"));

  if (!refined || refined.base === "none") {
    return STEPS.filter((s) => s.kind === "source" || s.input === "none");
  }
  return STEPS.filter((s) => stepAcceptsRefined(s, refined));
}

