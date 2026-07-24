/**
 * Toolkit step registry — single source of truth for steps, params, docs, and
 * input/output types. Drives the parser, builder, autocomplete, and Reference panel.
 *
 * Modeled on CyberChef's Operation metadata (name / description / inputType /
 * outputType / typed args / flowControl). Verbs mirror shell commands they replace
 * (gpg --encrypt/--decrypt, base64 -d, ssss-split/combine, openssl pkey).
 */

import { stepAcceptsRefined, typeOf } from "./types.js";

/** @typedef {"none"|"bytes"|"text"|"key"|"keypair"|"shares"|"artifact"|"bundle"} IoType */
/** @typedef {"source"|"transform"|"sink"|"flow"} StepKind */
/** @typedef {"enum"|"int"|"string"|"bool"|"flag"} ParamType */
/** @typedef {"webcrypto"|"openpgp"|"sss"|"encoding"|"flow"|"io"} Toolbox */
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
  encoding: { label: "Encoding", badge: "Encode", order: 3 },
  io: { label: "Input / output", badge: "I/O", order: 4 },
  flow: { label: "Flow", badge: "Flow", order: 5 },
};

/** @type {StepSpec[]} */
export const STEPS = [
  {
    name: "genkey",
    kind: "source",
    toolbox: "webcrypto",
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
    toolbox: "io",
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
    toolbox: "io",
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
    name: "shares",
    kind: "source",
    toolbox: "sss",
    doc: "Bind BLIP39 share mnemonics at run time (never stored in the recipe). Output type is shares/mnemonic — pipe into blip39 -d then recover for bytes/master, or foreach to map each share. For free-form text use the input step instead.",
    input: "none",
    output: "shares",
    unresolvedInputs: "shares",
    params: [],
  },
  {
    name: "input",
    kind: "source",
    toolbox: "io",
    doc: "Free-form text provided at run time via a textarea or loaded from a file (like cat). The data is never stored in the pipeline text.",
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
    doc: "Decrypt OpenPGP ciphertext at run time and/or accept already-plaintext BLIP39 mnemonics. Browser vault keys only — OpenPGP smartcards/YubiKey GPG are not available to web pages; decrypt those shares externally and paste the mnemonics.",
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
    toolbox: "webcrypto",
    doc: "Export a key to a binary encoding (PKCS#8 private, SPKI public, JWK, raw, or scalar/d for EC/OKP private keys).",
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
    doc: "Import DER/raw/scalar key bytes into a WebCrypto keypair (openssl pkey -in / gpg --import).",
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
    doc: "Hash bytes with WebCrypto SubtleCrypto.digest (SHA-256 / SHA-384 / SHA-512).",
    input: "bytes",
    output: "bytes",
    aliases: ["hash", "sha"],
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
    doc: "Sign pipeline bytes with a bound WebCrypto private/HMAC key (JWK panel). OpenPGP signing stays on the Encrypt page.",
    input: "bytes",
    output: "bytes",
    unresolvedInputs: "key",
    params: [],
  },
  {
    name: "verify",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "Verify a signature over pipeline message bytes. Bind public/HMAC key via the key panel; pass signature as base64url in the signature param or sig binding.",
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
    doc: "AES-GCM encrypt (default) or decrypt with -d. Ciphertext is IV(12) then CT/tag. Bind an AES oct JWK in the key panel. Distinct from OpenPGP encrypt.",
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
    doc: "HKDF-Extract/Expand over pipeline IKM bytes to OKM bytes.",
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
    doc: "PBKDF2-HMAC derive key bytes from pipeline password (text or bytes).",
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
    doc: "ECDH/X25519 deriveBits using bound local private key and peer public JWK. Output shared secret bytes (pipe into hkdf).",
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
    toolbox: "encoding",
    doc: "Encode bytes as URL-safe Base64 without padding (websafe).",
    input: "bytes",
    output: "text",
    params: [],
  },
  {
    name: "hex",
    kind: "transform",
    toolbox: "encoding",
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
    toolbox: "encoding",
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
    name: "sss",
    kind: "transform",
    toolbox: "sss",
    doc: "Split a 16- or 32-byte master into raw Shamir (SSS) shares (K-of-N). Does not encode mnemonics — pipe into blip39 for word phrases. For EC keys use export scalar first; for PEM/arbitrary data use symencrypt first.",
    input: "bytes",
    output: "shares",
    aliases: ["split", "sss-split"],
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
    doc: "Encode raw SSS shares as BLIP39 mnemonics, or decode with -d (mnemonic → raw). Checksum tag basilisk-slip39-v1; uses the official SLIP-39 wordlist.",
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
    doc: "Combine raw SSS shares into the 16/32-byte master (ssss-combine). Input shares/raw → output bytes/master. Decode mnemonics first with blip39 -d; unwrap OpenPGP envelopes separately with symdecrypt.",
    input: "shares",
    output: "bytes",
    aliases: ["sss-combine"],
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
    doc: "OpenPGP symmetric-encrypt the payload under a fresh 32-byte master (SKESK / SEIPD), emit envelope.asc, and pass the master bytes to sss. Recover with gpg --decrypt using the hex master as passphrase.",
    input: "text",
    output: "bytes",
    aliases: ["pgpenvelop", "skesk"],
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
    doc: "Decrypt a runtime-bound OpenPGP envelope.asc using the pipeline bytes as the hex passphrase master (inverse of symencrypt).",
    input: "bytes",
    output: "bytes",
    aliases: ["pgpunwrap"],
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
    name: "fanout",
    kind: "transform",
    toolbox: "webcrypto",
    doc: "Emit a side-stream artifact from the current value (e.g. public SPKI/PEM) and pass the value through unchanged — for multi-pronged outputs beside a private scalar split.",
    input: "keypair",
    output: "keypair",
    aliases: ["side", "redirect"],
    params: [
      {
        name: "format",
        type: "enum",
        positional: true,
        default: "spki",
        enum: ["spki", "pkcs8", "jwk", "pem", "scalar"],
        doc: "Side artifact encoding. spki = public DER; pkcs8 = private DER; pem/jwk honor which; scalar always private.",
      },
      {
        name: "which",
        type: "enum",
        default: "public",
        enum: ["private", "public"],
        doc: "Which key half to emit. Locked to public for format=spki; locked to private for format=scalar/pkcs8.",
      },
      {
        name: "name",
        type: "string",
        default: "fanout",
        doc: "Artifact filename stem",
      },
      {
        name: "ext",
        type: "string",
        default: "",
        doc: "File extension override",
      },
      {
        name: "label",
        type: "string",
        default: "",
        doc: "Display label",
      },
    ],
    overloads: [
      {
        when: { base: "keypair" },
        output: (current) => ({ ...current }),
      },
    ],
  },
  {
    name: "foreach",
    kind: "flow",
    toolbox: "flow",
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
    toolbox: "flow",
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
    toolbox: "openpgp",
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
    toolbox: "io",
    doc: "Render the current text as a QR code SVG artifact (qrencode).",
    input: "text",
    output: "artifact",
    params: [],
  },
  {
    name: "text",
    kind: "sink",
    toolbox: "io",
    doc: "Emit a message tile (no filename). Encrypt opens it in the compose box. Prefer this for PEM, hex, base64, or other printable secrets you want to encrypt as a message body.",
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
    doc: "Emit a named file tile (set name/ext) and pass the value through. Encrypt attaches the raw bytes as a file — use this when you want a downloadable attachment rather than a compose message.",
    input: "text",
    output: "text",
    aliases: ["output", "save", "emit"],
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "output",
        doc: "Filename stem (required intent for file disposition)",
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
    name: "inspect",
    kind: "transform",
    toolbox: "flow",
    doc: "Replace the pipeline value with a human-readable dump (openssl … -text / hexdump). Accepts any type; output is text/opaque. Preferred terminal when you want to see a value instead of emitting a result tile.",
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
        doc: "Dump style (hexdump forced when the step is named hexdump)",
      },
    ],
  },
  {
    name: "tee",
    kind: "transform",
    toolbox: "flow",
    doc: "Pass the value through unchanged while emitting an inspection artifact (Unix tee). Useful mid-pipeline for keypairs before export/sss.",
    input: "bytes",
    output: "bytes",
    aliases: ["peek"],
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "tee",
        doc: "Artifact label / filename stem",
      },
      {
        name: "format",
        type: "enum",
        default: "auto",
        enum: ["auto", "text", "hex", "hexdump", "jwk", "meta"],
        doc: "Inspection format for the side artifact",
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

/**
 * Whether a value type can feed a step's declared input (coarse legacy helper).
 * Prefer resolveStepType / stepAcceptsRefined for refined checks.
 * @param {IoType} from
 * @param {IoType} to
 * @param {string} [stepName]
 * @returns {boolean}
 */
export function ioCompatible(from, to, stepName) {
  if (
    stepName === "tee" ||
    stepName === "inspect" ||
    stepName === "out" ||
    stepName === "text" ||
    stepName === "fanout"
  ) {
    return !!from && from !== "none";
  }
  if (to === "none") return from === "none" || !from;
  if (from === to) return true;
  if (stepName === "merge") return true;
  if (stepName === "foreach" && from === "shares") return true;
  if (stepName === "recover" && from === "shares") return true;
  if (from === "shares" && to === "text") return false; // need foreach
  if (from === "text" && to === "artifact") return true;
  if (from === "artifact" && to === "bundle") return true;
  if (stepName === "utf8" && (from === "bytes" || from === "text")) return true;
  if (stepName === "symencrypt" && (from === "text" || from === "bytes")) return true;
  return false;
}
