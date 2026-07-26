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

import { stepAcceptsRefined, typeOf } from "./types.js";

/** @typedef {"none"|"bytes"|"text"|"key"|"keypair"|"shares"|"artifact"|"bundle"|"item"} IoType */
/** @typedef {"source"|"transform"|"sink"|"flow"} StepKind */
/** @typedef {"enum"|"int"|"string"|"bool"|"flag"} ParamType */
/** @typedef {"webcrypto"|"openpgp"|"sss"|"webauthn"|"encoding"|"flow"|"io"} Toolbox */
/** @typedef {"essentials"|"attestation"|string} Shelf */
/** @typedef {import("./types.js").StepOverload} StepOverload */
/** @typedef {import("./types.js").RefinedType} RefinedType */

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
 * @property {Toolbox} toolbox
 * @property {Shelf} [shelf]  optional sub-group within a toolbox (ops drawer)
 * @property {string} [label]  optional UI verb (recipe name stays unique)
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


/** @type {Record<Toolbox, { label: string, badge: string, order: number }>} */
export const TOOLBOX_META = {
  webcrypto: { label: "WebCrypto", badge: "WebCrypto", order: 0 },
  openpgp: { label: "OpenPGP", badge: "OpenPGP", order: 1 },
  sss: { label: "SSS / BLIP39", badge: "SSS", order: 2 },
  webauthn: { label: "WebAuthn", badge: "WebAuthn", order: 3 },
  encoding: { label: "Encoding", badge: "Encode", order: 4 },
  io: { label: "Input / output", badge: "I/O", order: 5 },
  flow: { label: "Flow", badge: "Flow", order: 6 },
};

/**
 * Shelves (sub-groups) inside a toolbox. Used by WebAuthn so attestation/MDS
 * stay out of the way until needed.
 * @type {Record<string, { label: string, order: number, defaultCollapsed?: boolean }>}
 */
export const SHELF_META = {
  essentials: { label: "Essentials", order: 0, defaultCollapsed: false },
  attestation: { label: "Attestation / MDS", order: 1, defaultCollapsed: true },
};

/** @type {StepSpec[]} */
export const STEPS = [
  {
    name: "genkey",
    kind: "source",
    toolbox: "webcrypto",
    doc: "Generate a WebCrypto keypair/key. Example: `genkey ec/p256 | tee` then `- .public | export spki | pem | out @public`, stem `export pkcs8 | pem | out @private`.",
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
    toolbox: "io",
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
    doc: "EFF Large Wordlist diceware passphrase (≈12.9 bits/word). Example: `passphrase 6 | out @passphrase`.",
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
    name: "shares",
    kind: "source",
    toolbox: "sss",
    doc: "Bind BLIP39 share mnemonics at run time (never stored in the recipe). Typical recover: `shares | blip39 -d | recover | …`. Map each share with `foreach` / `- out @share`. For free-form text use `input`.",
    input: "none",
    output: "shares",
    unresolvedInputs: "shares",
    params: [],
  },
  {
    name: "input",
    kind: "source",
    toolbox: "io",
    doc: "Free-form text at run time (textarea / file). Never stored in the recipe. Aliases: `paste`, `cat`. Example: `input | utf8 | hex`.",
    input: "none",
    output: "text",
    unresolvedInputs: "text",
    aliases: ["paste", "cat"],
    params: [],
  },
  {
    name: "decrypt",
    kind: "source",
    toolbox: "openpgp",
    doc: "Decrypt OpenPGP ciphertext at run time and/or accept already-plaintext BLIP39 mnemonics. Browser vault keys only (no smartcard/YubiKey in-page). Example: `decrypt gpg | blip39 -d | recover | …`.",
    input: "none",
    output: "shares",
    unresolvedInputs: "gpg",
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
    toolbox: "webcrypto",
    doc: "Export a key (pkcs8 / spki / jwk / raw / scalar). Prefer `export spki` after `.public`, or `export pkcs8` / `export scalar` on the stem. Example: `.public | export spki | pem | out @public`.",
    input: "keypair",
    output: "bytes",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "pkcs8",
        enum: ["pkcs8", "spki", "jwk", "raw", "scalar", "d"],
        doc: "Export format (scalar/d = private key material as fixed-length bytes for sss)",
      },
      {
        name: "which",
        type: "enum",
        default: "private",
        enum: ["private", "public"],
        doc: "Which half to export. Ignored for format=scalar/d (always private). Prefer format=spki for public material.",
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
    toolbox: "webcrypto",
    doc: "Import DER/raw/scalar bytes into a WebCrypto keypair. Example: `… | recover | import scalar alg=ec/p256 | export pkcs8 | pem | out @private`.",
    input: "bytes",
    output: "keypair",
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "pkcs8",
        enum: ["pkcs8", "spki", "raw", "scalar", "d"],
        doc: "Import format (scalar/d = EC/OKP private key bytes)",
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
          "aes/128",
          "aes/256",
          "hmac/sha256",
          "hmac/sha512",
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
    name: "digest",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "Hash bytes with SubtleCrypto.digest (SHA-256 / 384 / 512). Example: `random 32 | digest | hex | out @digest`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "alg",
        type: "enum",
        positional: true,
        default: "sha-256",
        enum: ["sha-256", "sha-384", "sha-512"],
        doc: "Hash algorithm",
      },
    ],
  },
  {
    name: "sign",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "Sign pipeline bytes with a bound WebCrypto private/HMAC JWK (key panel). OpenPGP signing stays on the Encrypt page. Example: `input | utf8 | sign | base64url`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [],
  },
  {
    name: "verify",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "Verify a signature over pipeline message bytes. Bind public/HMAC JWK via the key panel; signature as base64url param or runtime binding.",
    input: "bytes",
    output: "text",
    unresolvedInputs: "key",
    params: [
      {
        name: "signature",
        type: "string",
        default: "",
        doc: "Base64url signature (empty = use runtime sig binding)",
      },
    ],
  },
  {
    name: "aesgcm",
    kind: "transform",
    toolbox: "webcrypto",
    label: "encrypt",
    doc: "AES-GCM encrypt (default) or decrypt with `-d`. Ciphertext is IV(12)+CT/tag. Bind an AES oct JWK in the key panel. Distinct from OpenPGP `encrypt`.",
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
        name: "aad",
        type: "string",
        default: "",
        doc: "Optional additional authenticated data (UTF-8)",
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
    doc: "HKDF-Extract/Expand over pipeline IKM bytes to OKM. Example: `wa-prf | hkdf length=32 info=basilisk | …`.",
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
        doc: "Output length in bytes",
      },
      {
        name: "salt",
        type: "string",
        default: "",
        doc: "Optional salt (UTF-8; empty = zero-length salt)",
      },
      {
        name: "info",
        type: "string",
        default: "",
        doc: "Optional info/context string (UTF-8)",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha-256",
        enum: ["sha-256", "sha-384", "sha-512"],
        doc: "HKDF hash",
      },
    ],
  },
  {
    name: "pbkdf2",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "PBKDF2-HMAC derive key bytes from pipeline password (text or bytes). Example: `passphrase 6 | pbkdf2 length=32 salt=… | …`.",
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
        doc: "Output length in bytes",
      },
      {
        name: "salt",
        type: "string",
        default: "basilisk",
        doc: "Salt (UTF-8)",
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
  },
  {
    name: "ecdh",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "ECDH/X25519 `deriveBits` with bound local private + peer public JWK. Output shared-secret bytes — usually pipe into `hkdf`.",
    input: "none",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "bits",
        type: "int",
        default: 256,
        min: 128,
        max: 528,
        doc: "Shared secret bit length (P-256: 256)",
      },
    ],
  },
  {
    name: "wrap",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "AES-KW wrap: wrapping key from key panel; key-to-wrap from wrap panel (oct JWK). Emits wrapped key bytes.",
    input: "none",
    output: "bytes",
    unresolvedInputs: "key",
    params: [],
  },
  {
    name: "unwrap",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "AES-KW unwrap of pipeline wrapped bytes with bound wrapping key to raw key bytes.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [
      {
        name: "alg",
        type: "enum",
        default: "aes/256",
        enum: ["aes/128", "aes/256"],
        doc: "Algorithm of the wrapped key",
      },
    ],
  },
  {
    name: "pem",
    kind: "transform",
    toolbox: "encoding",
    doc: "Wrap DER as PEM, or strip armor with `-d`. Example: `export pkcs8 | pem | out @private`.",
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
    toolbox: "encoding",
    doc: "Pass DER/binary bytes through unchanged (identity).",
    input: "bytes",
    output: "bytes",
    params: [],
  },
  {
    name: "base64",
    kind: "transform",
    toolbox: "encoding",
    doc: "Encode bytes as Base64, or decode with `-d`. Example: `random 32 | base64 | out @secret`.",
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
    doc: "Encode bytes as URL-safe Base64 without padding. Example: `random 32 | base64url | out @secret`.",
    input: "bytes",
    output: "text",
    params: [],
  },
  {
    name: "hex",
    kind: "transform",
    toolbox: "encoding",
    doc: "Encode bytes as lowercase hex, or decode with `-d`. Example: `… | digest | hex | out @digest`.",
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
    toolbox: "encoding",
    doc: "Decode UTF-8 bytes → text (or encode text → bytes when holding text). Example: `… | symdecrypt | utf8 | out @pem`.",
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
    name: "sss",
    kind: "transform",
    toolbox: "sss",
    doc: "Split a 16/32-byte master into raw SSS shares (K-of-N). Pipe into `blip39` for mnemonics. EC: `export scalar | sss …`. Large PEM: `… | pem | out @pem | symencrypt | sss …`.",
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
    doc: "Encode raw SSS shares as BLIP39 mnemonics, or decode with `-d`. Example: `… | sss threshold=2 shares=3 | blip39 | foreach` / `- out @share`. Recover: `shares | blip39 -d | recover`.",
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
    name: "recover",
    kind: "transform",
    toolbox: "sss",
    doc: "Combine raw SSS shares into the 16/32-byte master. Decode mnemonics first: `shares | blip39 -d | recover`. Unwrap envelopes with `symdecrypt` after recover.",
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
    name: "symencrypt",
    kind: "transform",
    toolbox: "openpgp",
    doc: "OpenPGP-symmetric-encrypt the payload under a fresh 32-byte master (SKESK/SEIPD), emit `envelope.asc`, pass master bytes to `sss`. Example: `… | pem | out @pem | symencrypt | sss threshold=2 shares=3 | blip39 | foreach` / `- out @share`.",
    input: "text",
    output: "bytes",
    params: [
      {
        name: "name",
        type: "string",
        default: "envelope",
        doc: "Envelope artifact filename stem",
      },
    ],
    // Type flow via inferParamDrivenType (rejects master/scalar; accepts pem/der/opaque).
  },
  {
    name: "symdecrypt",
    kind: "transform",
    toolbox: "openpgp",
    doc: "Decrypt a bound `envelope.asc` using pipeline master bytes as the hex passphrase (inverse of `symencrypt`). Example: `shares | blip39 -d | recover | symdecrypt | utf8 | out @pem`.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "envelope",
    params: [],
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
    flowControl: true,
    doc: "Map a required body over a shares collection. Indent `-` lines or `{ … }`. Optional `foreach .items` / `.values` / `.keys`. Example: `… | blip39 | foreach` / `- out @share` or `- encrypt gpg`.",
    input: "shares",
    output: "bundle",
    params: [],
  },
  {
    name: "at",
    kind: "transform",
    toolbox: "sss",
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
    name: "in",
    kind: "source",
    toolbox: "flow",
    doc: "Source a prior `out` slot (live typed value). Chains are blank-line separated. Forms: `in @kp`, `in kp`, `in 1`. Alias: `from`. See docs/RECIPE.md.",
    input: "none",
    output: "bytes",
    aliases: ["from"],
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
    doc: "Project a member via selector. Usually written bare: `.public | export spki | pem`. Also as a tee/foreach branch prefix: `- .public | …`.",
    input: "bytes",
    output: "bytes",
    params: [
      {
        name: "selector",
        type: "string",
        positional: true,
        doc: "Selector text, e.g. .private or .value",
      },
    ],
  },
  {
    name: "encrypt",
    kind: "sink",
    toolbox: "openpgp",
    unresolvedRecipients: true,
    doc: "OpenPGP-encrypt the current value (`gpg --encrypt`). Recipients bound at run time. Alias: `gpg`. Common in foreach: `… | blip39 | foreach` / `- encrypt gpg`.",
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
    toolbox: "io",
    doc: "Render the current text as a QR code SVG artifact. Example: `… | blip39 | [1] | qr`.",
    input: "text",
    output: "artifact",
    params: [],
  },
  {
    name: "text",
    kind: "sink",
    toolbox: "io",
    doc: "Emit a message tile (no filename; Encrypt compose). Aliases: `print`, `echo`. Prefer `out @label` when you need a file tile + reusable slot.",
    input: "text",
    output: "text",
    aliases: ["print", "echo"],
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
    name: "wa-caps",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    label: "caps",
    doc: "Probe WebAuthn / PublicKeyCredential capabilities (platform UVPA, conditional UI, clientCapabilities). Output JSON text. No CAST — discovery only.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "wa-create",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    label: "create",
    doc: "Create a WebAuthn credential with PRF (platform or roaming). Returns PRF IKM bytes for HKDF/aesgcm. Soft MDS on attestation; does not block. Main-thread only.",
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
    name: "wa-get",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    label: "get",
    doc: "WebAuthn assertion ceremony; emits clientExtensionResults JSON (inspect PRF support). For pipeline PRF IKM bytes use wa-prf. Main-thread only.",
    input: "none",
    output: "text",
    params: [],
  },
  {
    name: "wa-prf",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    label: "prf",
    doc: "Unlock PRF IKM from the vault passkey (same ceremony as My Keys unlock). Pipe into `hkdf` / `aesgcm`. Main-thread only. Example: `wa-prf | hkdf length=32 | …`.",
    input: "none",
    output: "bytes",
    params: [],
  },
  {
    name: "wa-attest",
    kind: "transform",
    toolbox: "webauthn",
    shelf: "attestation",
    label: "attest",
    doc: "Parse WebAuthn attestationObject bytes → JSON (fmt, aaguid). Soft / informational — not a CAST gate.",
    input: "bytes",
    output: "text",
    params: [],
  },
  {
    name: "wa-mds",
    kind: "transform",
    toolbox: "webauthn",
    shelf: "attestation",
    label: "mds",
    doc: "Soft FIDO MDS lookup for an AAGUID (param or prior JSON aaguid from wa-attest). verified/unverified/unavailable — never blocks crypto. Same-origin MDS proxy.",
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
    doc: "Human-readable dump of the current value (openssl-style / hexdump). Tile keeps a snapshot for live format switching. Aliases: `dump`, `hexdump`. Example: `genkey ec/p256 | tee` / `- .private | inspect`.",
    input: "bytes",
    output: "text",
    aliases: ["dump", "hexdump"],
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
    doc: "Mid-stem fork: indented `-` body (or `{ … }`) on a clone; `- .public | …` projects members. Stem unchanged. Requires a body — use `peek` for side inspect. Prefer over multi-chain when forking mid-pipeline.",
    input: "bytes",
    output: "bytes",
    params: [],
  },
  {
    name: "peek",
    kind: "transform",
    toolbox: "flow",
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
 * @param {string|undefined|null} shelf
 * @returns {{ label: string, order: number, defaultCollapsed?: boolean }}
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

