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

import { CIPHER_DISPATCH_TARGETS } from "./step-names.js";
import { stepAcceptsRefined, typeOf } from "./types.js";

/** @typedef {"none"|"bytes"|"text"|"int"|"bool"|"key"|"keypair"|"shares"|"artifact"|"bundle"|"item"|"recipients"|"openpgp-key"} IoType */
/** @typedef {"source"|"transform"|"sink"|"flow"} StepKind */
/** @typedef {"enum"|"int"|"string"|"bool"|"flag"|"slot"} ParamType */
/** @typedef {"webcrypto"|"openpgp"|"sss"|"webauthn"|"encoding"|"flow"|"io"|"agent"|"hkp"} Toolbox */
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
 * @property {"shares"|"gpg"|"text"|"envelope"|"key"|"peer"|null} [unresolvedInputs]  needs runtime input panel
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
  webcrypto: { label: "WebCrypto", badge: "WebCrypto", order: 0, glyph: "webcrypto" },
  encoding: { label: "Encoding", badge: "Encode", order: 1, glyph: "encoding" }, // pem, base64, base64url, base32, hex, utf8
  io: { label: "Input / output", badge: "I/O", order: 2, glyph: "io" },
  flow: { label: "Flow", badge: "Flow", order: 3, glyph: "flow" },
  openpgp: { label: "OpenPGP", badge: "OpenPGP", order: 4, glyph: "openpgp" },
  agent: { label: "Agent", badge: "Agent", order: 5, glyph: "agent" },
  hkp: { label: "HKP", badge: "HKP", order: 6, glyph: "hkp" },
  sss: { label: "SSS / BLIP39", badge: "SSS", order: 7, glyph: "sss" },
  webauthn: { label: "WebAuthn", badge: "WebAuthn", order: 8, glyph: "webauthn" },
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
  pubkey: { label: "Public key", order: 0, glyph: "pubkey" },
  gpgsign: { label: "Sign", order: 1, glyph: "sign" },
  password: { label: "Password", order: 2, glyph: "password" },
  split: { label: "Split", order: 0, glyph: "split" },
  recover: { label: "Combine", order: 1, glyph: "recover" },
  binary: { label: "Binary", order: 0, glyph: "binary" },
  text: { label: "Text", order: 1, glyph: "text" },
  ports: { label: "Ports", order: 0, glyph: "ports" },
  control: { label: "Control", order: 0, glyph: "control" },
  essentials: { label: "Essentials", order: 0, defaultCollapsed: false, glyph: "essentials" },
  attestation: { label: "Attestation / MDS", order: 1, defaultCollapsed: true, glyph: "attestation" },
  vault: { label: "Vault", order: 0, glyph: "agent" },
  directory: { label: "Directory", order: 1, glyph: "recipients" },
  lookup: { label: "Lookup", order: 0, glyph: "hkp" },
  recipients: { label: "Recipients", order: 2, glyph: "recipients" },
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
    doc: "Free-form text at run time (textarea / file). Never stored in the recipe. Example: `input | utf8 | to hex`. (Legacy aliases `paste`/`cat` migrate via Upgrade recipe.)",
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
    doc: "Hash bytes with SubtleCrypto.digest (SHA-256 / 384 / 512; SHA-1 available but discouraged). Example: `random 32 | digest | to hex | out @digest`.",
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
    name: "to",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "hex",
    conjugate: "from",
    pairCaption: "To / From",
    pairLabels: { forward: "Encode", reverse: "Decode" },
    doc: "Encode bytes to text. Today: `to hex` (lowercase hex). Example: `… | digest | to hex | out @digest`.",
    input: "bytes",
    output: "text",
    params: [
      {
        name: "encoding",
        type: "enum",
        positional: true,
        default: "hex",
        enum: ["hex"],
        doc: "Target encoding (hex for now; more encodings later)",
      },
    ],
    effectiveIo(params) {
      void params;
      return { input: "bytes", output: "text" };
    },
  },
  {
    name: "from",
    kind: "transform",
    toolbox: "encoding",
    shelf: "binary",
    glyph: "hex",
    conjugateOf: "to",
    doc: "Decode encoded text → bytes. Today: `from hex`. Example: `in @digest | from hex | …`.",
    input: "text",
    output: "bytes",
    params: [
      {
        name: "encoding",
        type: "enum",
        positional: true,
        default: "hex",
        enum: ["hex"],
        doc: "Source encoding (hex for now)",
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
    doc: "Source a prior `out` slot (live typed value). Chains are blank-line separated. Forms: `in @kp`, `in kp`, `in 1`. (`from` is the encoding verb — use `from hex`, not slot load.) See docs/RECIPE.md.",
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
  {
    name: "agent.unlock",
    kind: "source",
    toolbox: "agent",
    shelf: "vault",
    doc: "Unlock a My Keys private key by fingerprint into the pipeline (sensitive). Prefer `agent.unlock AABB… | out @me` then `gpg.sign key=@me`. Main-thread (passkey).",
    input: "none",
    output: "openpgp-key",
    params: [
      {
        name: "fpr",
        type: "string",
        positional: true,
        default: "",
        doc: "Vault fingerprint (hex; spaces/0x ignored)",
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
    doc: "Save pipeline armored private into My Keys. `protection=device|passphrase|passkey`. Passphrase via Inputs when `protection=passphrase`. Example: `gpg.genkey email=\"you@example.com\" | agent.save protection=device | out @priv`.",
    input: "openpgp-key",
    output: "openpgp-key",
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
];

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
  "gpg.encrypt": "gpg-encrypt",
  "gpg.decrypt": "gpg-encrypt",
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
      if (step.name === "agent.unlock" || step.name === "agent.save") return true;
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

