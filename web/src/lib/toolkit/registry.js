/**
 * Toolkit step registry — single source of truth for steps, params, docs, and
 * input/output types. Drives the parser, builder, autocomplete, and Reference panel.
 *
 * Normative recipe grammar: docs/RECIPE.md
 * Modeled on CyberChef Operation metadata (name / description / inputType /
 * outputType / typed args / flowControl). Verbs mirror shell commands they replace
 * (gpg --encrypt/--decrypt, base64 -d, ssss-split/combine, openssl pkey).
 *
 * Prefer positional short form in docs (`genkey ec/p256`, `out $public`, `in $kp`).
 */

import { BASE_ENCODINGS, CIPHER_DISPATCH_TARGETS } from "./step-names.js";
import {
  POLYMORPHIC_STEPS,
  genkeyOutputBase,
  stepAcceptsRefined,
  typeOf,
} from "./types.js";

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
/**
 * What kind of randomness a step draws — and therefore whether a run that
 * agrees its entropy in advance may run the step at all.
 *
 * The question is *not* "does it draw randomness". It is **"does it draw
 * randomness that becomes, or protects, a secret"**:
 *
 * - `none` — draws none. Two runs on the same inputs agree byte for byte, so
 *   far as entropy is concerned. (`run.receipt` is `none` and still differs
 *   between runs: that is the clock, which the manifest declares separately.)
 * - `public` — draws a value that is published alongside the output and whose
 *   only requirement is freshness: an IV, a nonce, a set id, a challenge. A
 *   peer who can recompute it learns nothing they could not read off the
 *   result. Safe to seed, which is why every `public` here carries the argument
 *   for it at the declaration.
 * - `keying` — the randomness becomes key material, or is what stands between
 *   key material and an attacker. Seeding it from a value every participant can
 *   recompute means every participant can recompute the key, and a key everyone
 *   can recompute is not a key.
 *
 * **Omission means `keying`** — see `stepEntropy`. Same discipline as `slot`
 * defaulting to `false` and `emptyMeans` before it: the failure mode of
 * forgetting has to be refusal, not permission. An op added next year that
 * mints a key and says nothing about entropy must be refused by a mirrored run,
 * not silently seeded by it.
 * @typedef {"none"|"public"|"keying"} EntropyKind
 */
/**
 * What kind of *value* a parameter needs. Only that — how the value may be
 * supplied is `ParamSpec.slot`, and the two are orthogonal. `"slot"` used to
 * live in this union, which is why they were not: it named a supply mechanism
 * and left the value kind unsaid, while `"string"` named a value kind and
 * (wrongly) implied a literal.
 * @typedef {"enum"|"int"|"string"|"bytes"|"bool"|"flag"} ParamType
 */
/**
 * Every toolbox a step in this file declares.
 *
 * Checked against the file rather than remembered: `age`, `otp`, `quorum` and
 * `ssh` were missing, which is 24 steps whose toolbox was outside the type
 * meant to name them. `quorum` in particular has been its own category since
 * the mesh ops were split out.
 *
 * @typedef {"webcrypto"|"openpgp"|"sss"|"webauthn"|"encoding"|"flow"|"io"|"agent"|"hkp"|"webrtc"|"jose"|"age"|"otp"|"quorum"|"ssh"} Toolbox
 */
/** @typedef {string} Shelf */
/** @typedef {import("./types.js").StepOverload} StepOverload */
/** @typedef {import("./types.js").RefinedType} RefinedType */
/** @typedef {import("./input-needs.js").InputPanel} InputPanel */
/**
 * A panel need gated on how the step is configured, and on what reaches it.
 * @typedef {object} RuntimeInput
 * @property {InputPanel} panel
 * @property {Record<string, string|string[]>} [when]  sibling param settings that arm it
 * @property {IoType[]} [whenInput]  incoming pipeline bases that arm it. A step
 *   collecting a piped value has nothing left to ask a person for, so the tray
 *   is only a need when the pipe handed it `none`. Unknown at the point of
 *   asking (a bare op in the drawer, with no pipeline around it) counts as
 *   armed: advertising a tray that turns out to be unnecessary is a smaller
 *   error than hiding one a run will stop for.
 */

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
 * @property {ParamType} type  the value kind only — enum | int | string | bytes | bool | flag
 * @property {boolean|"required"} [slot]  whether a `$ref`, resolved at run time, may
 *   stand in for the value. `false` (the default) literal only; `true` literal or
 *   `$ref`; `"required"` `$ref` only, never a literal.
 *
 *   Omission fails closed, which is the point: before this field the validator
 *   decided by sniffing the leading sigil, so `type: "string"` params quietly
 *   accepted refs — `passphrase=`, `aad=`, `salt=`, `info=`, `signature=` and
 *   `gpg.encrypt to=` among them — and nothing said so. Declaring it makes both
 *   directions compile-time: a ref bound to a `slot: false` param is an error
 *   before the run, not a literal `"$k"` handed to a cipher.
 * @property {IoType|IoType[]} [slotOf]  the pipeline type(s) the resolved value must
 *   have. Omitted means *any* registered slot (`in $x` is the honest case). Checked
 *   at compile time, which is the determinism rule — the type is known before the
 *   run — finally applied to inputs and not only to outputs.
 * @property {boolean} [unresolvedInput]  leaving this param unbound leaves an input
 *   the *run* has to ask for: the engine falls back to a panel instead of failing.
 *   Which panel is not declared — it is rendered from `slotOf` (see
 *   `input-needs.js`), because a panel is a view of the type a ref would have to
 *   resolve to, not a second vocabulary alongside it.
 *
 *   This is the field that could not be derived. `stepNeedsKeyPanel` was a
 *   hand-written switch over nine op names standing in for it, so `stream.seal`
 *   and `stream.open` — declared `slot: "required"`, engine falling back to the
 *   key panel — showed no panel and could not be run, and nothing failed.
 * @property {string} [requiredWith]  names a sibling param whose truthiness arms
 *   this requirement. `gpg.encrypt key=` is needed only when `sign` is set;
 *   without the gate, every plain `gpg.encrypt` would ask for a signing key.
 * @property {string} [doc]
 * @property {*} [default]  filled when omitted; omitted from serialize unless serialize:"always"
 * @property {string} [emptyMeans]  what leaving this blank actually *does*, as a
 *   short phrase — the effective default, rendered where the choice is made.
 *
 *   An empty default is the one default the UI cannot show: `default ""` draws
 *   as an empty field, which reads as "nothing happens" whether or not
 *   something does. `rtc.ice stun=` is the case that made this a field rather
 *   than a habit — blank meant *contact Cloudflare and Google*, and the only
 *   place that was written down was a doc string in a tooltip. A default that
 *   changes behaviour is visible at the point of choosing or it is not a
 *   default, it is a surprise.
 *
 *   Written once here and rendered three ways — the field's placeholder, the
 *   hint under the field while it is empty (i.e. exactly while it is in
 *   effect), and the tool card's parameter list, where `default ` used to
 *   print with nothing after it. Not repeated in `doc`: two spellings of one
 *   fact are a defect already.
 * @property {string[]} [enum]  allowed values when type === "enum"
 * @property {number} [min]  int lower bound (docs / UI; validate may enforce)
 * @property {number} [max]  int upper bound
 * @property {boolean} [positional]  first bare token binds here (≤1 per step)
 * @property {string} [flag]  bare CLI flag (e.g. "-d") that sets this bool to true
 * @property {boolean} [allowIndex]  for slot params: allow 1-based index refs (default false)
 * @property {"always"} [serialize]  always emit `name=value` even when equal to default
 * @property {boolean} [acceptsPooled]  this param may be bound to a value from
 *   `entropy.pool` even when the step produces key material.
 *
 *   **Default-deny, and the default is the point.** A pooled value is
 *   randomness every participant can recompute, so anything derived from it is
 *   derivable by the whole room — which is why the compiler refuses a pooled
 *   value reaching a step whose output is a key. This says "not through *this*
 *   param", and it is only true where the input is public *by definition*: a
 *   salt (RFC 5869 §3.1, RFC 8018 §4.1 — non-secret by construction), HKDF's
 *   `info` context, an AEAD's additional data. Those are published alongside
 *   the thing they protect; a pooled one costs nothing and is the case
 *   `entropy.pool` exists to serve.
 *
 *   Declared on the param rather than kept as a list of (op, param) pairs
 *   somewhere, so a new op taking a public salt says so itself and a new op
 *   that does not is refused without anyone remembering to add it.
 *
 *   Never on a param that carries the secret being protected. If you are
 *   reaching for this on a `key`, `passphrase` or `master`, the answer is that
 *   a pooled value cannot go there.
 * @property {boolean} [secret]  this param carries key material, or the passphrase
 *   standing between key material and whoever holds the artifact. The field is
 *   locked to a bound `$slot` ref and never renders free text (design v2 §22a).
 *
 *   **Always with `slot: "required"`, and the pairing is the whole rule.** This
 *   flag on its own is a *serialization* rule: `serializeStep` drops any value
 *   here that is not a `$ref`, so a literal typed in Source view vanishes from
 *   the text. Vanishing is the wrong fix for a value that decides what the run
 *   produces — the recipe would then describe a split, a `gpg -c` message or a
 *   protected key it no longer performs, and `handoffContext` would digest two
 *   texts that mean different things into manifests claiming to be the same run.
 *   `slot: "required"` refuses the literal one layer earlier, at the parser,
 *   where the author is still present to be told; the `$ref` then survives every
 *   serialization intact, so the recipe names its secret without carrying it.
 *
 *   `serializeStep`'s drop stays as a second line, for an AST assembled by
 *   something other than the parser. It should never have anything to do.
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
 * @property {IoType[]} [collects]  sources only — the pipeline types this step
 *   *folds into* its output instead of discarding. A source declares `input:
 *   "none"` and so type-checks nothing arriving through the pipe, which is
 *   correct for the corpus idiom of re-rooting a chain (`genkey | out $a |
 *   genkey | out $b`) and wrong for a source whose job is to assemble a value
 *   out of what the author already has. Listing the accepted bases turns the
 *   discard into a refusal for everything else, and the output type is
 *   unchanged by what arrives — `inferSourceType` still answers it, so it stays
 *   knowable before the run.
 * @property {IoType} output
 * @property {EntropyKind} [entropy]  the kind of randomness this step draws.
 *   Read through `stepEntropy`, never directly: **absent means `keying`**, so a
 *   step that forgets to declare is refused by a mirrored run rather than
 *   seeded by one. Required (by `registryIssues`) on every step whose `output`
 *   is in `SECRET_BEARING_OUTPUTS` — that is the population where declaring
 *   `none` by reflex would be the expensive mistake, so the author has to say
 *   something rather than leave the field off and be quietly safe.
 * @property {ParamSpec[]} [params]
 * @property {boolean} [flowControl]
 * @property {boolean} [unresolvedRecipients]  needs runtime recipient binding
 * @property {InputPanel|RuntimeInput|(InputPanel|RuntimeInput)[]} [unresolvedInputs]  the panel(s)
 *   this step's *pipeline value* comes from — the input that arrives through the pipe and so
 *   has no param to be bound to (`input`, `shares`, `keypair`, `gpg.decrypt`). A `when:` guard
 *   names the param settings that arm it, and a `whenInput:` guard the incoming pipeline bases
 *   that do — a step that collects a piped value needs no tray when one arrived. Panels for a step's *params* are not declared here:
 *   they are derived from `ParamSpec.unresolvedInput`, which is what lets binding `key=$slot`
 *   retire the panel without a second list saying so.
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
  // Next to WebAuthn because that is where a user looking for "the second
  // factor" arrives, and the two are the same errand answered by different
  // hardware — a passkey held by an authenticator, or a shared secret held by
  // a phone. Its own toolbox rather than a WebCrypto shelf for the `ssh`
  // reason (§29b): TOTP's key container is a Base32 string, not a CryptoKey,
  // its wire format is an `otpauth://` URI, and filing `otp.verify` under
  // WebCrypto's Sign shelf would imply it and `verify` are two settings of
  // one op when they share nothing but a verb.
  otp: { label: "OTP", badge: "OTP", order: 11, glyph: "otp", color: "#db61a2" },
  // The toolbox, its `peer` shelf and its `channel` shelf all pointed at
  // `agent` — a vault key standing for a peer connection. Enumerating all 118
  // steps showed `agent` resolved for exactly seven ops, every one of them
  // WebRTC, and for no `agent.*` op at all: the mark belonged to the toolbox
  // that had never been drawn, not to the one it was named after. `webrtc` is
  // a span on two footings, because a connection is something ICE *builds*
  // between two ends rather than a wire it is handed.
  webrtc: { label: "WebRTC", badge: "WebRTC", order: 12, glyph: "webrtc", color: "#58a6ff" },
  // Quorum is a *consumer* of WebRTC, not a division of it. It held the drawer
  // header for a while — `quorum` was renamed to `webrtc` so all the network
  // ops lived in one category — and a spec-named drawer ended up containing
  // five ops no specification describes: a room derived from a PGP audience, a
  // signed invite posted through a relay, and traffic encrypted under a
  // pairwise key. `WEBRTC-TOOLBOX.md` §8 had already said so, in a section
  // titled "not an MDN section — a Basilisk-specific fit"; the registry is
  // what lagged. The test is now simply whether an op is a WebRTC built-in.
  //
  // Filed immediately after `webrtc` because that is the layering: the mesh is
  // session management for RTC peers, so a reader who has just met
  // `peer.offer` meets `quorum.offer` next. Purple rather than another blue,
  // because what quorum adds to a peer connection is the OpenPGP identity
  // binding, and that is the family the colour should name.
  quorum: { label: "Quorum", badge: "Quorum", order: 13, glyph: "quorum", color: "#bc8cff" },
  jose: { label: "JOSE", badge: "JOSE", order: 14, glyph: "jose", color: "#ffa657" },
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
  // OTP splits enrolment from use, because they happen months apart and only
  // one of them puts the shared secret on screen: `otp.uri`/`otp.parse` move
  // the credential, `otp.code`/`otp.verify` never emit it.
  // `enrolment` keeps `qr` on purpose — a QR code is not a stand-in for what
  // enrolment is, it *is* what enrolment is, and `otp.uri`'s own example ends
  // in the `qr` sink. `otpcode` had been borrowing OpenPGP's `password` key,
  // which said "a shared secret" and nothing about the half that matters here:
  // the code is only good for one period. `otp` is the same key with a
  // countdown dial for a bow, so the two shelves now read as one toolbox.
  enrolment: { label: "Enrolment", order: 0, glyph: "qr" },
  otpcode: { label: "Code", order: 1, glyph: "otp" },
  ice: { label: "ICE / STUN", order: 0, glyph: "ports" },
  // Two shelves, two marks, neither of them a key. `peer` is the offer and the
  // answer facing each other across a gap — signalling is precisely the phase
  // where the two halves are addressed to each other and have not arrived.
  // `channel` is the two directions an `RTCDataChannel` carries, drawn
  // vertically so the horizontal band stays `ports`'.
  peer: { label: "Peer & signaling", order: 1, glyph: "peer" },
  channel: { label: "Data channel", order: 2, glyph: "channel" },
  rtcstats: { label: "Stats", order: 3, glyph: "ports" },
  /**
   * Quorum's lifecycle shelf — open an exchange, join one, end one.
   *
   * Deliberately *not* `peer`: "Peer & signaling" names the phase where two
   * ends address SDP halves at each other, and `quorum.offer` does not do that
   * — it derives a room from an audience and publishes a signed invite. The
   * mark is the mesh, three nodes closed into a ring, built from `webrtc`'s
   * own vocabulary of filled endpoint nodes with one more node and no open
   * span, because that is what the layer adds.
   *
   * `quorum.send`/`quorum.recv` are on `channel` — the same key, the same
   * "Data channel" header and the same two-arrow mark `peer.send`/`peer.recv`
   * carry one toolbox above. Shelf keys are global while the grouping is
   * per-toolbox, so the parallel costs nothing and keeps the two send verbs
   * legible as the same errand with different protection.
   */
  exchange: { label: "Exchange", order: 0, glyph: "quorum" },
  /**
   * Things the room does *together*, once it is open. `exchange` opens and
   * closes a room and `channel` moves bytes across one; drawing a value every
   * participant helped choose is neither, and folding it into either would
   * misfile the one shelf where an op is worthless alone.
   */
  ceremony: { label: "Ceremony", order: 3, glyph: "quorum" },
};

/**
 * The OTP parameters that describe a token, shared by `otp.uri`, `otp.code`
 * and `otp.verify` so the three cannot drift apart.
 *
 * Every one of them is also a field of the `otpauth://` URI, which is why
 * `otp.code` and `otp.verify` ignore these when a URI arrives on the stem:
 * the URI is what the other side is holding, and two answers to `digits=`
 * cannot both be obeyed. `otp.parse` is the way to override — strip the URI
 * to its secret and these take over again.
 * @type {ParamSpec[]}
 */
const OTP_TOKEN_PARAMS = [
  {
    name: "mode",
    type: "enum",
    default: "totp",
    enum: ["totp", "hotp"],
    doc: "totp counts time steps (RFC 6238); hotp counts events with counter= (RFC 4226)",
  },
  {
    name: "algorithm",
    type: "enum",
    default: "sha1",
    enum: ["sha1", "sha256", "sha512"],
    doc: "HMAC digest. sha1 is RFC 4226's and what every authenticator assumes — the collision story that condemns bare SHA-1 does not reach HMAC",
  },
  {
    name: "digits",
    type: "enum",
    default: "6",
    enum: ["6", "7", "8"],
    doc: "Code length. RFC 4226 allows 6–8; most apps only display 6",
  },
  {
    name: "period",
    type: "int",
    default: 30,
    min: 1,
    doc: "Seconds per time step (totp only). 30 is universal; 60 exists",
  },
  {
    name: "counter",
    type: "int",
    default: 0,
    min: 0,
    doc: "Event counter (hotp only) — the number this code is for",
  },
];

/**
 * `at=` — the instant to compute for. Shared by the two ops that read a clock.
 * @type {ParamSpec}
 */
const OTP_AT_PARAM = {
  name: "at",
  type: "int",
  default: 0,
  min: 0,
  doc: "Unix seconds to compute for; 0 is now. Pin it to make a run reproducible (RFC 6238's vectors are times)",
};

/** @type {StepSpec[]} */
export const STEPS = [
  {
    name: "genkey",
    kind: "source",
    toolbox: "webcrypto",
    shelf: "keys",
    doc: "Generate a WebCrypto keypair/key. Curves: `ec/p256`…`p521`, `ed25519`, `x25519` (ECDH). Symmetric: `aes/128|192|256`, `hmac/sha256|384|512`. RSA `hash=` for hashed RSA. Example: `genkey x25519 | out $local` then `ecdh private=$local peer=$peer`.",
    input: "none",
    output: "keypair",
    entropy: "keying",
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
    doc: "Cryptographically random bytes (`crypto.getRandomValues`). Example: `random 32 | base64url | out $secret`.",
    input: "none",
    output: "bytes",
    entropy: "keying",
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
    doc: "A literal byte string. Example: `bytes deadbeef | aes-gcm $key | out $ct`. Also accepts base64 (`encoding=base64`) or plain text (`encoding=utf8`); a leading `0x` on hex is optional. Quote the value if it contains a space or `=` — base64 padding needs `bytes \"aGVsbG8=\" encoding=base64`.",
    input: "none",
    output: "bytes",
    entropy: "none",
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
    doc: "Import a keypair you already have, pasted at run time (never stored in the recipe). `which=private` (default) wants a PKCS#8 PEM or a JWK with `d` and yields the full pair; `which=public` reads an SPKI PEM or a public JWK and yields a public-key tip. The recipe names which, because the tip's type is fixed before the paste is read — material of the other half is refused by name rather than typed as whatever it turned out to be. Example: `keypair jwk alg=ed25519 | export spki | pem | out $pub`. To make a new one instead, use `genkey`.",
    input: "none",
    output: "keypair",
    entropy: "none",
    effectiveIo(params) {
      return {
        input: "none",
        output: String(params?.which || "private") === "public" ? "key" : "keypair",
      };
    },
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
        /**
         * The half being pasted. `import`'s `which=` is the same param for the
         * same reason, and the two ops share the check behind it: the PEM
         * label and the JWK's `d` are both read *after* the type is settled,
         * so neither can be what settles it.
         */
        name: "which",
        type: "enum",
        default: "private",
        enum: ["private", "public"],
        doc: "private (default) = a PKCS#8 PEM or a JWK with `d` → keypair; public = an SPKI PEM or a public JWK → a public `key` tip.",
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
    doc: "Generate a passphrase. Default EFF diceware (`mode=diceware`, ≈12.9 bits/word); `mode=char` uses a 69-char alphabet. Example: `passphrase 6 | out $passphrase` or `passphrase mode=char length=20`.",
    input: "none",
    output: "text",
    entropy: "keying",
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
    doc: "Collect BLIP39 share mnemonics into one set. Gathers what is piped in (one mnemonic, or a bundle from `quorum.recv count=`), what `with=$slot` names, and — when the recipe names nothing — what the Inputs tray holds (never stored in the recipe). Recover from the tray: `shares | blip39 -d | sss.combine | …`. Recover from shares a room delivered: `$share | shares with=$late | blip39 -d | sss.combine | …`, or `quorum.recv count=2 | shares | blip39 -d | sss.combine | …`. Map each share with `foreach` / `- out $share`. For free-form text use `input`.",
    input: "none",
    // What the pipe may hand this source instead of being thrown away. Every
    // other source re-roots — `genkey | out $a | genkey | out $b` is the corpus
    // idiom and discarding is what makes it work — so this is declared per step
    // rather than made a rule about sources. It is declared *here* because a
    // share is the one value where a discard costs somebody the thing they were
    // sent, and because this step's job is assembling a set out of what you
    // have: the pipe is one of the places you have it.
    collects: ["text", "bundle"],
    output: "shares",
    entropy: "none",
    // Only when the recipe named nothing. `with=` puts the shares in the text,
    // and a cell whose values are named must not be held back waiting for a
    // tray nobody needs to open; `whenInput` says the same of a piped value.
    unresolvedInputs: [{ panel: "shares", when: { with: "" }, whenInput: ["none"] }],
    params: [
      {
        name: "with",
        type: "string",
        slot: "required",
        slotOf: ["text", "bundle"],
        default: "",
        emptyMeans: "collect only what the pipe and the Inputs tray hold",
        doc: "One more slot to fold into the set — a received mnemonic (`with=$late`) or a bundle from `quorum.recv count=`",
      },
    ],
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
    entropy: "none",
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
    entropy: "none",
    // Two panels, not one: the ciphertext, and share rows for mnemonics
    // already decrypted outside the browser (Kleopatra / gpg / YubiKey —
    // OpenPGP cards are not reachable from JS). The second used to be pushed
    // by hand in the validator, where the tool card could not see it.
    unresolvedInputs: ["gpg", "shares"],
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
    entropy: "none",
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
    doc: "Import DER/raw/scalar/JWK. `import spki` yields a public `key` tip; other formats yield a full keypair, and `import jwk which=public` yields a public `key` tip from JWK. The tip's type is fixed by `format=`, `alg=` and `which=` — a JWK that turns out to hold something else (a symmetric `oct`, another curve, no `d`) is refused by name rather than imported as whatever it happens to be. Example: `… | export jwk | import jwk alg=ed25519` or `import scalar alg=ec/p256`.",
    input: "bytes",
    output: "keypair",
    entropy: "none",
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
        /**
         * The half a JWK is being read for — `spki` / `pkcs8` say it in the
         * format name, and JWK is the one format that carries either.
         *
         * Named rather than sniffed from `d` for the reason the whole class
         * exists: the compiler declares the tip before the picker opens and
         * has no JWK to look at, so a body-driven answer would be a type the
         * recipe never wrote. `export jwk which=public` is the conjugate, and
         * this reads back what that writes.
         */
        name: "which",
        type: "enum",
        default: "private",
        enum: ["private", "public"],
        doc: "jwk only: `private` (default) needs a JWK with `d` and yields a keypair; `public` reads the public half alone and yields a public `key` tip (`export jwk which=public` is what writes one). Refused on the DER formats, which already name their half.",
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
        default: "auto",
        enum: ["auto", ...RSA_HASH_ENUM],
        doc: "Hash the imported RSA key binds (`auto` = the JWK's own `alg`, else sha-256; ignored for other algs)",
      },
    ],
    effectiveIo(params) {
      const format = String(params?.format || "pkcs8").toLowerCase();
      if (format === "jwk") {
        // Must agree with `inferParamDrivenType`: the caret reads this and the
        // type walker reads that, and a disagreement is how an op gets offered
        // after a step that really produced the other shape. A symmetric `alg=`
        // and `which=public` both make this one key.
        const single =
          String(params?.which || "private").toLowerCase() === "public" ||
          genkeyOutputBase(String(params?.alg || "ec/p256")) === "key";
        return { input: "text", output: single ? "key" : "keypair" };
      }
      if (format === "spki") return { input: "bytes", output: "key" };
      return { input: "bytes", output: "keypair" };
    },
  },

  {
    name: "digest",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "digest",
    doc: "Hash bytes with SubtleCrypto.digest (SHA-256 / 384 / 512; SHA-1 available but discouraged). Example: `random 32 | digest | encode hex | out $digest`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
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
    doc: "Sign pipeline bytes with a WebCrypto private/HMAC key. Prefer `sign key=$kp` (slot from `out`); else key panel. RSA-PSS `saltLength=` (default 32); ECDSA optional `hash=` override. Example: `input | utf8 | sign key=$kp | base64url`.",
    input: "bytes",
    output: "bytes",
    // keying, and no `getRandomValues` in this repo says so: the randomness is
    // WebCrypto's own. Running `sign` twice over identical bytes with an
    // imported P-256 key gives two different signatures — that is the ECDSA
    // nonce, and two signatures sharing one nonce hand over the private key.
    // RSA-PSS draws its salt the same way. (Ed25519 alone is deterministic;
    // the declaration is per step, so it takes the worst algorithm it offers.)
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live key slot (`$kp`); omit to use the key panel",
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
        doc: "ECDSA hash override (`auto` = curve default: P-256→SHA-256, P-384→SHA-384, P-521→SHA-512). RSA and HMAC keys bind their digest at generate/import; naming a different one here is refused, not applied",
      },
    ],
  },
  {
    name: "verify",
    kind: "transform",
    toolbox: "webcrypto",
    shelf: "sign",
    conjugateOf: "sign",
    doc: "Verify a signature over pipeline message bytes. Prefer `verify key=$pub`; else key panel. Default fail-loud; `soft` / `-q` emits `true`/`false` instead of throwing on bad sig. Signature via `signature=` or runtime binding. Same `saltLength=` / `hash=` as sign.",
    input: "bytes",
    output: "bool",
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live public/HMAC key slot (`$pub`); omit to use the key panel",
      },
      {
        name: "signature",
        type: "bytes",
        slot: true,
        slotOf: ["bytes", "text"],
        default: "",
        emptyMeans: "use the signature bound at run time",
        doc: "Base64url signature, or `$slot` of bytes/text",
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
        doc: "ECDSA hash override (`auto` = curve default; must match sign). RSA and HMAC keys bind their digest at import; naming a different one here is refused, not applied",
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
    doc: "AES-GCM encrypt (default) or decrypt with `-d`. Prefer `aes-gcm key=$cek`; else key panel. Optional `tagLength=` (default 128). Also accepts `aes-256-gcm` / `AES/GCM/NoPadding`. Bare `encrypt`/`decrypt` sugar is migrator-only — write the concrete op. Distinct from OpenPGP `gpg.encrypt`.",
    input: "bytes",
    output: "bytes",
    // public: a 12-byte GCM IV, and `aesGcmEncrypt` returns `IV || ciphertext`
    // — the drawn value *is* the first twelve bytes of this step's own output.
    // Its requirement is uniqueness under a key, never secrecy, so a peer who
    // can recompute it has learned something it could already read.
    entropy: "public",
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
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live AES key slot (`$cek`); omit to use the key panel",
      },
      {
        name: "aad",
        type: "bytes",
        slot: true,
        slotOf: ["bytes", "text"],
        default: "",
        // Additional *authenticated* data — authenticated, not encrypted, so
        // it travels in the clear beside the ciphertext.
        acceptsPooled: true,
        doc: "Optional AAD as UTF-8 string, or `$slot` of text/bytes",
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
    doc: "AES-CBC encrypt/decrypt (`-d`). Unauthenticated — prefer `aes-gcm` for new work. Packing IV(16)||CT. Prefer `aes-cbc key=$cek`. Also accepts sized/JCE forms. Distinct from OpenPGP `gpg.encrypt`.",
    input: "bytes",
    output: "bytes",
    // public: a 16-byte CBC IV, prefixed to the ciphertext by `aesCbcEncrypt`
    // and read straight back off it by `aesCbcDecrypt`. The doc line above
    // spells the packing out — `IV(16)||CT` — which is the argument.
    entropy: "public",
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
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live AES key slot (`$cek`); omit to use the key panel",
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
    doc: "AES-CTR encrypt/decrypt (`-d`). Unauthenticated — prefer `aes-gcm` for new work. Packing IV(16)||CT (128-bit counter block); `length=` is AesCtrParams.length (default 64), not IV size. Prefer `aes-ctr key=$cek`. Also accepts sized/JCE forms. Distinct from OpenPGP `gpg.encrypt`.",
    input: "bytes",
    output: "bytes",
    // public: the 128-bit initial counter block, prefixed to the ciphertext
    // exactly as the CBC IV is. It must be fresh per message under a key — a
    // seeded pool yields one draw per call, not one value for the whole run —
    // and it travels in the clear either way.
    entropy: "public",
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
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live AES key slot (`$cek`); omit to use the key panel",
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
    doc: "RSA-OAEP encrypt (default) or decrypt with `-d`. Prefer `rsa-oaep key=$rk`; else key panel. Optional `label=` (must match on decrypt). Also accepts JCE `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. Distinct from OpenPGP `gpg.encrypt` and AES `aes-gcm`.",
    input: "bytes",
    output: "bytes",
    // keying: the OAEP seed. Unlike an IV it is not published — it is what
    // makes encrypting the same plaintext twice give different ciphertext, so
    // a peer who can recompute it can confirm a guessed plaintext by
    // re-encrypting it. Drawn inside WebCrypto, which is why the empirical
    // sweep sees a differing output and no visible draw.
    entropy: "keying",
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
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live RSA-OAEP key slot (`$rk`); omit to use the key panel",
      },
      {
        name: "label",
        type: "string",
        default: "",
        emptyMeans: "no label — the label is omitted",
        doc: "Optional OAEP label (UTF-8). Decryption must use the same label or it fails.",
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
    doc: "RSAES-PKCS1-v1_5 encrypt/decrypt (`-d`). Discouraged — prefer `rsa-oaep`. Pure-JS (not SubtleCrypto). Uses any RSA key (OAEP/PSS JWK) via `key=$rk`. Also accepts `RSA/ECB/PKCS1Padding`. Outputs tagged legacy/discouraged.",
    input: "bytes",
    output: "bytes",
    // keying: the PKCS#1 v1.5 padding string (`rsaes-pkcs1.js`), which does the
    // OAEP seed's job — hide that this ciphertext is an encryption of a value
    // an attacker could otherwise guess and check.
    entropy: "keying",
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
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live RSA key slot (`$rk`); omit to use the key panel",
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
    doc: "HKDF-Extract/Expand. Default emits OKM bytes; `as=aes/256` / `as=aes-kw/256` / HMAC uses deriveKey → live `key` tip (`which: secret`), matching `unwrap`. Distinct from the `as master` cast stage. Example: `webauthn.prf | hkdf 32 as=aes/256 | out $cek`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
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
        type: "bytes",
        slot: true,
        slotOf: ["bytes", "text"],
        default: "",
        emptyMeans: "a zero-length salt",
        // RFC 5869 §3.1: the salt is non-secret by construction, and a salt
        // the room agreed on is what `entropy.pool` is for.
        acceptsPooled: true,
        doc: "Optional salt as UTF-8 string, or `$slot` of text/bytes",
      },
      {
        name: "info",
        type: "bytes",
        slot: true,
        slotOf: ["bytes", "text"],
        default: "",
        // Context, not key material — published with whatever it binds.
        acceptsPooled: true,
        doc: "Optional info/context as UTF-8 string, or `$slot` of text/bytes",
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
    doc: "PBKDF2-HMAC derive. Default OKM bytes; `as=aes/256` / `as=aes-kw/256` / HMAC uses deriveKey → live `key` tip (`which: secret`). Example: `passphrase 6 | pbkdf2 32 as=aes/256 | out $cek`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
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
        type: "bytes",
        slot: true,
        slotOf: ["bytes", "text"],
        default: "basilisk",
        // RFC 8018 §4.1: a PBKDF2 salt need not be secret. The secret is the
        // passphrase arriving through the pipe, which is *not* accepted pooled.
        acceptsPooled: true,
        doc: "Salt as UTF-8 string, or `$slot` of text/bytes",
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
    doc: "ECDH/X25519 deriveBits (default) or deriveKey via `as=aes/256` / `as=aes-kw/256` → live `key` tip (`which: secret`). Prefer `genkey x25519` then `ecdh private=$local peer=$peer`. bits=0 auto-sizes from curve.",
    input: "none",
    output: "bytes",
    entropy: "none",
    params: [
      {
        name: "private",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Local private key slot (`$local`); omit to use the key panel",
      },
      {
        name: "peer",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Peer public key slot (`$peer`); omit to use the peer JWK panel",
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
    doc: "Wrap a CEK. Default AES-KW; also `mode=aes-gcm|aes-cbc|aes-ctr` (IV||wrapped) or `mode=rsa-oaep`. Optional `label=` (RSA-OAEP), `tagLength=` (AES-GCM), `length=` (AES-CTR). Prefer `wrap key=$kek target=$cek`.",
    input: "none",
    output: "bytes",
    // keying: whatever this draws is wrapped around key material by
    // construction. `aes-kw` draws nothing, `aes-gcm`/`aes-cbc`/`aes-ctr` draw
    // an IV and `rsa-oaep` a seed — and one declaration covers every mode, so
    // it takes the mode that must not be seeded.
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Wrapping key slot (`$kek` AES or `$rk` RSA); omit to use the key panel",
      },
      {
        name: "target",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Key-to-wrap slot (`$cek`); omit to use the wrap panel",
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
        emptyMeans: "no label — the label is omitted",
        doc: "OAEP label when mode=rsa-oaep (UTF-8). Unwrapping must use the same label.",
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
    doc: "Unwrap pipeline wrapped bytes into a live `key` tip (CryptoKey). Modes match `wrap`. Prefer `unwrap key=$kek`. Content modes expect IV||wrapped packing. Use `export raw` when you need bytes.",
    input: "bytes",
    output: "key",
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Wrapping key slot (`$kek` AES or `$rk` RSA); omit to use the key panel",
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
    doc: "Wrap DER bytes as PEM armor. Label auto: SPKI/`which=public` → PUBLIC KEY, PKCS#8 → PRIVATE KEY. Conjugate: `der` strips armor. Example: `:public | export spki | pem | out $public`.",
    input: "bytes",
    output: "text",
    entropy: "none",
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
    doc: "Strip PEM armor → DER bytes. Sets format/which from the BEGIN label when known. Example: `in $pub | der | import spki` or `in $pub | der | as key`.",
    input: "text",
    output: "bytes",
    entropy: "none",
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
    doc: "Encode bytes as Base64 (`base64.encode`) or decode (`base64.decode`). Example: `random 32 | base64.encode | out $secret`. Also accepts `base64 -d`.",
    input: "bytes",
    output: "text",
    entropy: "none",
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
    entropy: "none",
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
    doc: "Encode bytes as text in a base alphabet. Example: `… | digest | encode hex | out $digest`, or `… | encode base64url`. (`to` is the old spelling and still parses.)",
    input: "bytes",
    output: "text",
    entropy: "none",
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
    doc: "Decode base-encoded text → bytes. Example: `in $digest | decode hex | …`, or `… | decode base64`. (`from` is the old spelling and still parses.)",
    input: "text",
    output: "bytes",
    entropy: "none",
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
    doc: "Encode bytes as RFC 4648 Base32 (`base32.encode`) or decode (`base32.decode`). Example: `random 10 | base32.encode | out $id`.",
    input: "bytes",
    output: "text",
    entropy: "none",
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
    doc: "Decode UTF-8 bytes → text (or encode text → bytes when holding text). Example: `… | gpg.symdecrypt | utf8 | out $pem`.",
    input: "bytes",
    output: "text",
    entropy: "none",
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
    doc: "Split a secret (≤ 32 bytes) into **verifiable** shares — Feldman VSS over P-256. Unlike `sss.split`, the share set carries public commitments, so a custodian can check their share is genuine the moment they receive it (`vss.verify`) instead of discovering a bad one when recovery fails. Emits the same `shares` shape, so `blip39` / `foreach` / `at` work unchanged. For arbitrary-length data use `sss.split` — verifiability needs a prime-order group, which GF(256) is not. Example: `export scalar | vss.split threshold=2 shares=3 | blip39 | foreach` / `- out $share`.",
    input: "bytes",
    output: "shares",
    entropy: "keying",
    params: [
      // Never dropped on serialize, for the reason spelled out on `sss.split`:
      // K-of-N is a decision about this secret and these custodians, not a
      // build-wide default, so it has to be in the text both ends compare.
      {
        name: "threshold",
        type: "int",
        default: 2,
        min: 1,
        max: 16,
        serialize: "always",
        doc: "Shares required to recover (K)",
      },
      {
        name: "shares",
        type: "int",
        default: 3,
        min: 1,
        max: 16,
        serialize: "always",
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
    doc: "Check shares against their Feldman commitments and pass them through — fail-loud, so `in $shares | vss.verify | vss.combine` refuses to reconstruct from a tampered share rather than returning a wrong secret. Uses the commitments carried on a `vss.split` set, or `commitments=$slot` when a custodian holds them separately. Example: `in $shares | vss.verify | out $ok`.",
    input: "shares",
    output: "shares",
    entropy: "none",
    params: [
      {
        name: "commitments",
        type: "string",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        // Blank is the ordinary case, not an omission: `commitmentsFor` reads
        // them off the share set the pipeline carries and only wants a slot
        // once the shares have been split from them. Said here because
        // `input-needs.js` reads this field to decide whether an empty
        // `slot: "required"` param is a choice or a run that will die.
        emptyMeans: "the commitments carried by the share set itself",
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
    doc: "Extract a `vss.split` set's public commitments as JSON, so they can be published alongside the shares. Commitments do not survive `blip39` — words carry no commitments — and that matches reality: a custodian holds a secret share and the public commitments, arriving by different routes. Example: `… | vss.split … | tee` / `- vss.commitments | out $commitments`.",
    input: "shares",
    output: "text",
    entropy: "none",
    params: [],
  },
  {
    name: "vss.combine",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    conjugateOf: "vss.split",
    glyph: "recover",
    doc: "Reconstruct the secret from a threshold of `vss.split` shares (Lagrange interpolation over P-256). Pair with `vss.verify` first if the shares came from elsewhere. Example: `shares | blip39.decode | vss.verify | vss.combine | out $secret`.",
    input: "shares",
    output: "bytes",
    entropy: "none",
    params: [],
  },
  {
    /**
     * Filed with `vss.*` rather than with the mesh it runs over.
     *
     * It was in the WebRTC toolbox, on the `peer` shelf, because a live
     * exchange is its transport — but that is not what it is *about*, and
     * transport is not a filing rule anywhere else here: `rtc.check`,
     * `rtc.state`, `rtc.stats`, `rtc.quality` and `rtc.restart` all require a
     * live exchange too and are WebRTC ops regardless. What `dkg.run` does is
     * Feldman VSS over P-256 — the same scheme, the same curve and the same
     * commitments as the four `vss.*` ops directly above, which is why it was
     * already wearing the `split` mark while sitting three toolboxes away from
     * the shelf that owns it.
     *
     * The comparison it belongs to is the one this shelf now states in full:
     * to get a k-of-n key you either split one you hold (`sss.split`,
     * `vss.split`) or generate one nobody ever holds (`dkg.run`). Its doc
     * string carries the exchange prerequisite, which is where a runtime
     * requirement belongs.
     */
    name: "dkg.run",
    kind: "source",
    toolbox: "sss",
    shelf: "split",
    glyph: "split",
    doc: "**Experimental.** Run a distributed key generation across the live exchange (Feldman VSS over P-256): every participant deals a contribution, verifies what they receive, and sums — so the private key is never assembled anywhere, and any `threshold` of the room can reconstruct it later. Needs a live `quorum.offer`/`quorum.join` with every participant present. There is no complaint round: a bad share aborts the run and names the dealer, and the group must restart without them. Produces a shared key, **not** threshold signing. Example: `dkg.run threshold=3 | out $dkg`.",
    input: "none",
    output: "text",
    // keying, and the least arguable case in the registry: the output is this
    // participant's share of a distributed key.
    entropy: "keying",
    params: [
      // Never dropped on serialize, for the reason spelled out on `sss.split`.
      // Here it decides how many of the room can reconstruct the group key
      // afterwards, which is the one thing a participant is agreeing to.
      {
        name: "threshold",
        type: "int",
        default: 2,
        min: 1,
        max: 16,
        serialize: "always",
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
    /**
     * The other half of `entropy: { mode: "pool" }`.
     *
     * `manifest.js` has declared the mode and shipped the refusal that guards
     * it — a pooled run may contain no op that draws `keying` randomness —
     * while saying in its own header that nothing produced the value. This
     * produces it.
     *
     * One op, not a step per round: commit and reveal each block on every
     * other participant, and two chained steps would be two places to stall
     * with no way to say which. Same reasoning as `dkg.run`.
     */
    name: "entropy.pool",
    kind: "source",
    // Placed by what it *is*, the way `dkg.run` was moved to the shelf that
    // owns Feldman VSS rather than the one that owns live connections. This is
    // not SubtleCrypto — nothing here calls it — it is a ceremony the room
    // performs, so it sits beside the other ops that only mean anything with an
    // exchange open. Its own shelf, because `exchange` opens and closes a room
    // and `channel` moves bytes across one; drawing a value together is
    // neither.
    toolbox: "quorum",
    shelf: "ceremony",
    glyph: "ports",
    doc: "Draw randomness the whole room chose: every participant commits to a nonce, then reveals it, and the pool is a digest over all the reveals — so no participant can pick the value by moving last. Needs a live `quorum.offer`/`quorum.join` with every participant present; a participant who commits and never reveals stalls the round rather than deciding it. **Public-safe randomness only** — salts, nonces, IVs, challenges. Never key material: a value everyone can recompute is a key everyone can recompute, which `manifest.js` refuses before the run. Example: `entropy.pool | out $salt`.",
    input: "none",
    output: "bytes",
    // `public` is the whole point rather than a concession: this value is
    // published to the room by construction, and every participant recomputes
    // it. Declaring `keying` would be false, and declaring nothing reads as
    // `keying` and would make a pooled run refuse itself.
    entropy: "public",
    params: [
      {
        name: "wait",
        type: "int",
        default: 120000,
        doc: "How long to wait for the other participants (ms)",
      },
    ],
  },
  {
    name: "sss.split",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    conjugate: "sss.combine",
    pairCaption: "Split / combine",
    doc: "Split a 16/32-byte master into raw SSS shares (K-of-N). Pipe into `blip39` for mnemonics. EC: `export scalar | sss.split …`. Large PEM: `… | pem | out $pem | gpg.symencrypt mode=master | sss.split …`.",
    input: "bytes",
    output: "shares",
    entropy: "keying",
    params: [
      /**
       * ## Why the quorum is never dropped on serialize
       *
       * `serializeStep` omits a named param equal to its default, which is
       * right for a param whose default is a build-wide policy — every recipe
       * in the corpus means the same thing by its absence. K and N are not
       * that. They are a decision about *this* secret and *these* people, made
       * per ceremony, printed on the share cards, and the whole of what the
       * word quorum promises. `2` and `3` are one arbitrary point in a range
       * of 1..16, not a policy.
       *
       * Left droppable, `sss.split threshold=2 shares=3` round-tripped to bare
       * `sss.split`. The security property was then absent from the text a
       * reader reads, from the text two peers compare, and from the manifest
       * they digest — a 2-of-3 and a 2-of-16 were the same recipe, and only
       * the second of them was written down. That is `LANGUAGE.md`'s principle
       * 4, and this is the narrow half of its fix: the parameter keeps its
       * spelling and stops being droppable. The designed half makes it the
       * verb's object (`split 2/3`), where it cannot be defaulted away at all.
       *
       * The same reasoning applies verbatim to `vss.split` and to `dkg.run`'s
       * threshold, and only to those — see the audit in the commit that added
       * this. A param whose default is genuinely inert stays droppable,
       * because noise in the text is its own readability cost.
       */
      {
        name: "threshold",
        type: "int",
        default: 2,
        min: 1,
        max: 16,
        serialize: "always",
        doc: "Shares required to recover (K)",
      },
      {
        name: "shares",
        type: "int",
        default: 3,
        min: 1,
        max: 16,
        serialize: "always",
        doc: "Total shares to produce (N)",
      },
      /**
       * ## The mask is not written down beside the shares
       *
       * A literal here used to serialize verbatim. `sss.split threshold=2
       * shares=3 passphrase=hunter2` is the text that goes into a `#r=` link,
       * into the workspace saved in `localStorage`, and into `recipeSource` in
       * the run manifest both ends digest — so the one value that makes a
       * stolen share useless travelled in the three places a recipe most
       * reliably travels, beside the recipe that made the shares, to the same
       * custodians the shares go to.
       *
       * **Hiding it on serialize was the wrong fix, and is why this is a slot
       * rather than only a `secret`.** `secret: true` by itself drops a literal
       * at serialization, which leaves the recipe describing a split it no
       * longer performs: a peer who adopts the notebook masks with nothing, so
       * the shares they make are not the shares that were made, and
       * `handoffContext` digests the two texts into manifests that mean
       * different things while agreeing they are the same run. `c33bc16`
       * settled the principle for this exact class of parameter — a value that
       * changes what a recipe *means* stays visible in the text — and a
       * redacted passphrase is precisely that value made invisible.
       *
       * So the recipe names the secret and never carries it. A literal is a
       * parse error, where the author is still there to be told; `$pw` survives
       * every serialization intact. Whoever holds the slot reproduces the split
       * exactly, and whoever holds only the link holds a recipe that names a
       * value they do not have — which is the true state of affairs rather than
       * a quieter false one.
       *
       * The shape is `ssh.encode passphrase=`'s, for its reason: a passphrase
       * that decides *what the artifact is* — masked shares or bare ones — must
       * be named in the recipe, so it can never come from a panel behind the
       * author's back, and must not be spellable as a literal, so it can never
       * ride out in the text. `sss.combine` takes the tray fallback for the
       * same reason `ssh.decode` does; splitting does not.
       *
       * **What this does not close.** Nothing stops `"hunter2" | out $pw` in a
       * cell above: a literal in a `lit` step is indistinguishable from any
       * other text this language can hold, and no rule about parameters can see
       * it. What is closed is the parameter that *invited* one — the field
       * binds from the Inputs tray, and Inputs is the one place this product
       * neither persists nor shares.
       */
      {
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        secret: true,
        default: "",
        emptyMeans: "no mask — the shares are unmasked",
        doc: "Optional share passphrase mask (Basilisk-specific) — `$slot` only, never a literal: bind it from Inputs (`input | out $pw`, then `passphrase=$pw`) so the mask is named in the recipe without travelling in it.",
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
    // public, and `none` would have been the easy wrong answer: this step is
    // shares → shares and reads as pure encoding, but `encodeShareSet` draws
    // fifteen bits for the set id — and every mnemonic it emits then spells
    // that id out in the clear. Its whole job is to stop two splits being
    // mixed at recovery time; the secret's entropy came from `sss.split`, one
    // step upstream, which is where the `keying` refusal belongs.
    entropy: "public",
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
    entropy: "none",
    params: [
      {
        /**
         * The conjugate of `sss.split passphrase=`, and a slot for the same
         * mechanical reason: a recovery recipe is shared at least as widely as
         * the split that made it — it is what a custodian is handed along with
         * their share — so a literal mask here is the mask arriving with the
         * thing it masks.
         *
         * The *design* reason differs from split's, exactly as `ssh.decode`'s
         * differs from `ssh.encode`'s. On the way out the passphrase decides
         * what the shares are, so nothing may supply it but the text. Here it
         * only decides whether recovery succeeds, so the Shares panel may
         * answer — and it does: the `shares` source carries
         * `inputs.shares.passphrase` (headless, `--passphrase-env`) on the
         * value's meta, and the engine falls back to it when the recipe named
         * nothing. That fallback is what
         * `emptyMeans` is naming, and what keeps `input-needs.js` from
         * reporting a binding nobody owes.
         */
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        secret: true,
        default: "",
        emptyMeans: "the mask from the Shares panel, or none",
        doc: "The share passphrase used at split time — `$slot` only, never a literal (`input | out $pw`, then `passphrase=$pw`). Left empty, the Shares panel's passphrase is used.",
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
    doc: "OpenPGP-symmetric encrypt (`gpg -c` style). Dual mode is explicit: default `mode=master` (fresh 32-byte master tip + `envelope.asc` for SSS); `mode=passphrase` + `passphrase=`/`$slot` emits armored ciphertext as the tip (no master). Passphrase alone does not flip modes. Example SSS: `… | pem | gpg.symencrypt mode=master | sss.split …`. Example password: `\"hi\" | utf8 | gpg.symencrypt mode=passphrase passphrase=$pw | out $msg`.",
    input: "text",
    output: "bytes",
    // keying: `mode=master` draws the 32 bytes that *are* the envelope's
    // password, and either mode draws the session key OpenPGP encrypts under.
    entropy: "keying",
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
        /**
         * `gpg -c`'s password, and the whole of what stands between the
         * ciphertext and whoever holds it. `slot: true` let it be written as a
         * literal, and a literal serialized verbatim — into the `#r=` link, the
         * saved workspace and the run manifest — which is the same disclosure
         * `sss.split passphrase=` carried and the same fix, argued at length
         * there. The ciphertext and the notebook that made it travel the same
         * way in this product (`#decrypt&ct=` beside `#r=`), so "the password
         * is in the other document" was never much of a separation.
         *
         * `MESSAGING_STARTERS.symencrypt` has always spelled it the new way,
         * and generates the passphrase into `$pw` rather than asking anyone to
         * type one into the text.
         */
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        secret: true,
        default: "",
        // Blank is the whole of `mode=master`, which is the default and most of
        // the corpus: the SSS path mints its own master and forbids a
        // passphrase outright. Only `mode=passphrase` owes one, and owing it is
        // said by `gpgSymModeTypeError` in a sentence, before the run.
        emptyMeans: "mode=master — the envelope's own master, no passphrase",
        doc: "User passphrase as a `$slot` of text (`input | out $pw`, then `passphrase=$pw`) — required with mode=passphrase, forbidden with mode=master. Never a literal: the recipe text is shared, saved and digested.",
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
    doc: "Decrypt OpenPGP-symmetric ciphertext. Dual mode is explicit: default `mode=master` (tip is 16/32-byte master; bound `envelope.asc` decrypts with hex(master)); `mode=passphrase` + `passphrase=`/`$slot` (tip is armored ciphertext). Passphrase alone does not flip modes. Example: `in $msg | gpg.symdecrypt mode=passphrase passphrase=$pw | utf8`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
    unresolvedInputs: { panel: "envelope", when: { mode: "master" } },
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
        // The conjugate of `gpg.symencrypt passphrase=`, ref-only for the same
        // reason: a recipe that decrypts is shared beside the ciphertext it
        // decrypts, and a literal here would be the password arriving with the
        // message.
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        secret: true,
        default: "",
        emptyMeans: "mode=master — the envelope panel's master, no passphrase",
        doc: "User passphrase as a `$slot` of text (`input | out $pw`, then `passphrase=$pw`) — required with mode=passphrase, forbidden with mode=master. Never a literal.",
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
    doc: "Map a required body over a shares collection. Indent `-` lines or `{ … }`. Optional `foreach :items` / `:values` / `:keys`. Tip is a `bundle` of per-item tips (side effects via `out` / auto-emit) — do not pipe the bundle into cipher/KDF ops; use `$slot`s from the body. Example: `… | blip39 | foreach` / `- out $share` or `- gpg.encrypt`.",
    input: "shares",
    output: "bundle",
    entropy: "none",
    params: [],
  },
  {
    name: "at",
    kind: "transform",
    toolbox: "sss",
    shelf: "split",
    doc: "Select from a shares collection (1-based). Same as `[1]` / `[1:2]`. Example: `… | blip39 | [1] | out $share-1`.",
    input: "shares",
    output: "shares",
    entropy: "none",
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
    doc: "Stem literal (parse/serialize as the literal itself — never written as `lit …`). Strings → text; decimal/hex ints → int; `true`/`false` → bool. Example: `\"hello\" | out $msg`, `0xff | out $n`, or `true | out $ok`.",
    input: "none",
    output: "text",
    entropy: "none",
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
    doc: "Source a prior `out` slot (live typed value). Chains are blank-line separated. Forms: `in $kp`, `in kp`, `in 1`. (`decode` is the alphabet verb; `in` only loads slots.) See docs/RECIPE.md.",
    input: "none",
    output: "bytes",
    entropy: "none",
    params: [
      {
        name: "ref",
        type: "string",
        slot: "required",
        allowIndex: true,
        positional: true,
        doc: "Slot `$label` or 1-based index (`$kp`, `kp`, or `1`)",
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
    entropy: "none",
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
    entropy: "none",
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
        default: "auto",
        doc: "Hash an RSA materializing cast binds (`auto` = the JWK's own `alg`, else sha-256)",
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
    doc: "Generate an OpenPGP Curve25519 keypair (same as My Keys). Pipeline emits `openpgp-key/private`; public key is also written as an artifact. `gpg.genkey email=alice@example.com | out $priv` — an address needs no quoting now that slots are `$`.",
    input: "none",
    output: "openpgp-key",
    entropy: "keying",
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
        // The S2K passphrase is the only thing between the armor this step
        // emits and the private key inside it, so a literal would be the key's
        // protection written into the text that made the key — shared, saved
        // and digested alongside it. Ref-only for `sss.split passphrase=`'s
        // reason, and like `ssh.encode`'s it also decides *what the artifact
        // is*: protected armor or bare armor, which no panel may choose.
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        secret: true,
        default: "",
        emptyMeans: "the private key armor is written unprotected",
        doc: "S2K passphrase protecting the private key — `$slot` only, never a literal (`input | out $pw`, then `passphrase=$pw`).",
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
    doc: "Inspect armored OpenPGP without decrypting (type, recipients, signatures, optional packet map). Example: `input | gpg.inspect | out $report`.",
    input: "text",
    output: "text",
    entropy: "none",
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
    doc: "OpenPGP-encrypt the current value. Prefer `to=$alices` (recipients slot) or `to=email` + lookup; else Run binder. `mode=separate|combined`. `-s` / `key=$me` for sign-then-encrypt.",
    input: "text",
    output: "artifact",
    entropy: "keying",
    params: [
      {
        name: "to",
        type: "string",
        slot: true,
        slotOf: ["recipients", "openpgp-key", "text"],
        default: "",
        emptyMeans: "the recipients picked in the Run binder",
        doc: "`$slot`, `fpr:…`, or email (resolve via lookup)",
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
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        requiredWith: "sign",
        slotOf: ["key", "keypair", "bytes", "text", "openpgp-key"],
        default: "",
        doc: "Signing private-key slot when `-s` (`$me`); omit to use the vault key panel",
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
    doc: "OpenPGP-sign pipeline text/bytes. Prefer `gpg.sign key=$me` (slot from `agent.unlock`); else vault key panel. Default cleartext; `format=detached` for detached sig. Distinct from WebCrypto `sign`.",
    input: "text",
    output: "text",
    // keying: an RFC 9580 signature carries a random salt, and an ECDSA key
    // signs with a nonce. Neither is a value this step publishes on purpose.
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text", "openpgp-key"],
        default: "",
        doc: "Live private-key slot (`$me`); omit to use the vault key panel",
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
    doc: "Verify an OpenPGP cleartext or detached signature. Prefer `gpg.verify key=$pub`. Detached: `signature=$slot`. Fail-loud by default; `soft`/`-q` → bool true|false. Distinct from WebCrypto `verify`.",
    input: "text",
    output: "bool",
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text", "openpgp-key"],
        default: "",
        doc: "Live public (or private) key slot (`$pub`); omit to use vault key / recipients",
      },
      {
        name: "signature",
        type: "string",
        slot: true,
        slotOf: ["bytes", "text"],
        default: "",
        emptyMeans: "a cleartext signature on the stem, or the run-time binding",
        doc: "Detached armored signature or `$slot`",
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
    doc: "Encode a keypair/key as OpenSSH — `format=public` (default) emits the one-line public form (`ssh-ed25519 AAAA… comment`) for authorized_keys / GitHub; `format=private` emits an openssh-key-v1 block, **unencrypted unless you bind `passphrase=$slot`** (`aes256-ctr` + `bcrypt_pbkdf` at 24 rounds, the pair `ssh-keygen` writes). The passphrase is never taken from the Inputs panel behind your back: the same recipe must always emit the same kind of file, so the encryption has to be named in the recipe (`… | ssh.encode format=private passphrase=$pw`). ed25519, ec/p256|384|521, rsa. The leading key-type name is fixed by the key's algorithm and curve, not chosen here: a P-256 key is always `ecdsa-sha2-nistp256` (RFC 5656), where the `sha2` is part of that name rather than a digest you can set. The bytes match `ssh-keygen`. Example: `genkey ed25519 | ssh.encode comment=\"you@host\" | out $pub`.",
    input: "keypair",
    output: "text",
    // keying: `format=private` writes an OPENSSH PRIVATE KEY block, whose
    // random check bytes and (with `passphrase=`) bcrypt salt are the two
    // things standing between the file and the private half it contains.
    entropy: "keying",
    params: [
      {
        name: "format",
        type: "enum",
        default: "public",
        enum: ["public", "private"],
        doc: "public = one-line public key; private = openssh-key-v1 (explicit only, never a default) — bare unless passphrase= is bound",
      },
      {
        name: "comment",
        type: "string",
        default: "",
        doc: "Trailing comment on the public line (openssh-key-v1 carries it too)",
      },
      {
        // `slot` + `secret`, the shape `rtc.ice credential=` uses, and for its
        // reason: the UI offers only "Bind a value from Inputs…", and
        // `serializeStep` drops anything that is not an `$ref` before a recipe
        // becomes a share link. So the passphrase is *named* in the recipe
        // while its bytes stay in the session.
        //
        // Named, and never implicit. `ssh.decode` may read the Inputs panel
        // because a passphrase there only decides whether a run gets off the
        // ground; here it decides what the file *is*. Sourcing it from panel
        // state would mean one recipe emitting a protected key on one machine
        // and a bare one on the next, with nothing in the text to say which.
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
        secret: true,
        default: "",
        emptyMeans: "the private block is written unencrypted",
        doc: "format=private only: $slot holding the passphrase to encrypt the block with (aes256-ctr + bcrypt_pbkdf, 24 rounds).",
      },
    ],
    overloads: [
      // `format=private` first — matchOverload takes the first hit, and the
      // runtime has always stamped `kind: "ssh-private"` here (execSshEncode).
      // Without this guard the table called an openssh-key-v1 block
      // "ssh-public", so `ssh.encode format=private | ssh.decode` typed as a
      // public `key` while producing a keypair, and ssh.decode's own
      // `ssh-private → keypair` overload was unreachable.
      {
        when: { base: "keypair" },
        whenParams: { format: "private" },
        output: { base: "text", kind: "ssh-private" },
      },
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
    doc: "Decode OpenSSH key text into a live key/keypair — `format=public` (default) reads a one-line public key and yields a public `key`; `format=private` reads an openssh-key-v1 block and yields a keypair. The recipe names which, because the two produce different types and the file cannot be consulted before the run: a block handed to `format=public` is refused rather than quietly typed as the other thing. Passphrase-protected blocks open too — bind the passphrase to a slot and name it with `passphrase=$slot`; a wrong one is named as such rather than reported as a corrupt file. Example: `input | ssh.decode | ssh.fingerprint | out $fp`, or `input | out $pw` then `… | ssh.decode format=private passphrase=$pw`.",
    input: "text",
    output: "key",
    entropy: "none",
    effectiveIo(params) {
      return {
        input: "text",
        output: String(params?.format || "public") === "private" ? "keypair" : "key",
      };
    },
    overloads: [
      // Keyed on the *param*, not on the input's `kind` — the kind is known
      // only when the text came from `ssh.encode`, and every other route in
      // (a paste, `file.read`, a slot) arrives as plain text. The table used
      // to fall back to `keypair` there, so `input | ssh.decode | export
      // pkcs8` compiled clean on a public line and shipped SPKI under a
      // recipe that said pkcs8. `format=` is the one thing present in every
      // case, so it is the only honest source for the type.
      //
      // A `kind` that contradicts the param is caught earlier, in
      // `inferParamDrivenType`, where it can say so in a sentence.
      { when: { base: "text" }, whenParams: { format: "private" }, output: { base: "keypair" } },
      { when: { base: "text" }, output: { base: "key", which: "public" } },
    ],
    params: [
      {
        /**
         * Mirrors `ssh.encode format=`, values and default alike: the two are
         * conjugates and a round trip should read the same word twice.
         *
         * `public` is the default on both sides for the same reason — a
         * public line is the form that gets pasted around, and reading a
         * private key is the act that should have to be written down.
         */
        name: "format",
        type: "enum",
        default: "public",
        enum: ["public", "private"],
        doc: "public = a one-line public key → `key` (the default); private = an openssh-key-v1 block → `keypair`. The output type follows this word, so a file of the other form is refused by name rather than decoded into a type the recipe did not declare.",
      },
      {
        name: "hash",
        type: "enum",
        default: "sha512",
        enum: ["sha512", "sha256"],
        doc: "Digest an RSA key binds on import — `ssh-rsa` names none, so `sign`/`verify` on the result are stuck with this one (ignored for ed25519/ECDSA)",
      },
      {
        /**
         * The conjugate of `ssh.encode passphrase=`, and a slot for the same
         * mechanical reason: `serializeStep` drops anything that is not an
         * `$ref` before a recipe becomes a share link, so a literal would
         * either travel in the text or vanish from it.
         *
         * The *design* reason differs from encode's, and the difference is
         * why this took until now to exist. On encode the passphrase decides
         * what the file is, so it must be named. Here it only decides whether
         * an already-protected file opens, so the Inputs panel would have
         * been legitimate — and `ssh.decode`'s doc told people to use it.
         * There is no such field: `buildBindings` never sets
         * `inputs.gpg.passphrase`, so the panel path was unreachable and the
         * refusal pointed at a control that does not exist.
         */
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
        secret: true,
        default: "",
        // Most blocks are not protected, and a protected one can still be
        // opened with the Inputs passphrase `execSshDecode` falls back to. So
        // blank is a choice with an outcome, which is what this field is for —
        // and what keeps `input-needs.js` from calling it a missing binding.
        emptyMeans: "no passphrase, or the one in Inputs",
        doc: "$slot holding the passphrase for a protected openssh-key-v1 block (`input | out $pw` then `passphrase=$pw`). Ignored for public lines and unencrypted blocks.",
      },
    ],
  },
  {
    name: "ssh.fingerprint",
    kind: "transform",
    toolbox: "ssh",
    shelf: "sshwire",
    glyph: "fingerprint",
    doc: "SHA-256 fingerprint of an SSH public key — `SHA256:` + base64, byte-identical to `ssh-keygen -lf`. Accepts a keypair, a key, or a public line. Example: `input | ssh.decode | ssh.fingerprint | out $fp`.",
    input: "keypair",
    output: "text",
    entropy: "none",
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
    doc: "Sign the payload in sshsig format (`ssh-keygen -Y sign`) — also how git signs commits with SSH keys. `namespace=` is part of what is signed: a `git` signature can never verify as a `file` signature. Key from a slot. Example: `input | utf8 | ssh.sign key=$id namespace=git | out $sig`.",
    input: "text",
    output: "text",
    // keying: an SSH signature over the same WebCrypto primitives `sign` uses,
    // so the same ECDSA nonce argument applies.
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
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
    doc: "Verify an sshsig signature over the pipeline payload (`ssh-keygen -Y verify`). `signature=$slot` holds the sshsig block, `key=` the public line or a slot; `namespace=` must match the signer's. Fail-loud; `-q` emits bool false instead. Example: `in $msg | ssh.verify key=$pub signature=$sig namespace=git | out $ok`.",
    input: "text",
    output: "bool",
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Signer's public key — slot, or the literal public line",
      },
      {
        name: "signature",
        type: "string",
        // Text only, because `execSshVerify` says so outright:
        // `if (sigVal?.type !== "text") throw "signature slot must hold sshsig
        // text"`. The wider set this used to carry came from the validator's
        // okBase table -- what a slot ref may resolve to *in general* -- not
        // from what this op accepts. Every other value reached that throw.
        slot: "required",
        slotOf: ["text"],
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
  // ── OTP — HOTP (RFC 4226) and TOTP (RFC 6238) over the primitives already
  // on the shelf: an HMAC, RFC 4648 Base32, and the `qr` sink. No new
  // dependency, and every op runs headlessly in the CLI.
  {
    name: "otp.uri",
    kind: "transform",
    toolbox: "otp",
    shelf: "enrolment",
    conjugate: "otp.parse",
    pairCaption: "Build / read a Key URI",
    pairLabels: { forward: "Build", reverse: "Read" },
    glyph: "qr",
    doc: "Build the `otpauth://` enrolment URI an authenticator scans, from a Base32 secret (or raw secret bytes, which are encoded for you). `algorithm=`, `digits=` and `period=` are always written into the URI even at their defaults — they are optional in the format, but the defaults readers assume are not uniform, and a URI that states them cannot be read two ways. The output is **masked**: this string is the shared secret plus a label, so it is a credential exactly as a private key is. Example: `random 20 | otp.uri issuer=\"Big Corp\" account=you@example.com | qr`.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "issuer",
        type: "string",
        default: "",
        doc: "Who the account is with — shown as the heading in the authenticator, and written into both the label and issuer=",
      },
      {
        name: "account",
        type: "string",
        default: "",
        doc: "The account name (required) — the line listed under the issuer",
      },
      ...OTP_TOKEN_PARAMS,
    ],
    overloads: [
      { when: { base: "bytes" }, output: { base: "text", kind: "otpauth-uri" } },
      { when: { base: "text" }, output: { base: "text", kind: "otpauth-uri" } },
    ],
  },
  {
    name: "otp.parse",
    kind: "transform",
    toolbox: "otp",
    shelf: "enrolment",
    conjugateOf: "otp.uri",
    glyph: "qr",
    doc: "Read one field out of a pasted `otpauth://` URI — `field=secret` (default) is the conjugate of `otp.uri` and round-trips. The ambiguous URIs are refused rather than guessed: an `issuer=` that disagrees with the label's issuer is two accounts, and an `hotp` URI with no `counter=` cannot make a code at all. The label is split on the *encoded* separator, so an account name containing `%3A` does not sprout a phantom issuer. Only `field=secret` comes out masked. Example: `qr.scan | otp.parse | out $secret`.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "field",
        type: "enum",
        positional: true,
        default: "secret",
        enum: [
          "secret",
          "issuer",
          "account",
          "algorithm",
          "digits",
          "period",
          "counter",
          "mode",
        ],
        doc: "Which part of the URI to emit",
      },
    ],
    overloads: [
      { when: { base: "text", kind: "otpauth-uri" }, output: { base: "text" } },
      { when: { base: "text" }, output: { base: "text" } },
    ],
  },
  {
    name: "otp.code",
    kind: "transform",
    toolbox: "otp",
    shelf: "otpcode",
    conjugate: "otp.verify",
    pairCaption: "Code / verify",
    pairLabels: { forward: "Code", reverse: "Verify" },
    glyph: "otp",
    doc: "The code showing right now, from a Base32 secret, raw secret bytes, **or** a whole `otpauth://` URI. Handed a URI it takes `mode`, `algorithm`, `digits`, `period` and `counter` from the URI and ignores its own — the URI is what the other side is holding. `at=` pins the instant, which is how the RFC 6238 vectors are stated. The code itself is *not* masked: it expires in one step and exists to be read. Example: `in $secret | otp.code | out $code`.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [...OTP_TOKEN_PARAMS, OTP_AT_PARAM],
    overloads: [
      { when: { base: "bytes" }, output: { base: "text", kind: "otp-code" } },
      { when: { base: "text" }, output: { base: "text", kind: "otp-code" } },
    ],
  },
  {
    name: "otp.verify",
    kind: "transform",
    toolbox: "otp",
    shelf: "otpcode",
    conjugateOf: "otp.code",
    glyph: "otp",
    doc: "Check the code on the stem against the secret in `secret=$slot` (a Base32 secret or a whole `otpauth://` URI). `window=` is the part naive implementations get wrong: clocks drift and users type slowly, so a TOTP code is accepted within **±window** steps — while a HOTP window only ever looks *ahead*, because a server counter that went backwards would accept a code already spent. Fail-loud; `-q` emits bool false instead. Example: `input | otp.verify secret=$enrol window=1 | out $ok`.",
    input: "text",
    output: "bool",
    entropy: "none",
    params: [
      {
        name: "secret",
        type: "string",
        // `base32From` accepts exactly these two and throws on anything else:
        // raw secret bytes, or Base32/otpauth text. A key or keypair never
        // reached the base32 decoder -- it reached the throw beneath it.
        slot: "required",
        slotOf: ["bytes", "text"],
        default: "",
        doc: "Slot holding the Base32 secret or the otpauth:// URI",
      },
      {
        name: "window",
        type: "int",
        default: 1,
        min: 0,
        doc: "Steps of drift to allow — ±window for totp, look-ahead only for hotp. 0 accepts only the current step",
      },
      ...OTP_TOKEN_PARAMS,
      OTP_AT_PARAM,
      {
        name: "soft",
        type: "bool",
        flag: "-q",
        default: false,
        doc: "Soft mode: emit bool true|false (never throw on a wrong code)",
      },
    ],
    overloads: [
      { when: { base: "text" }, output: { base: "bool" } },
      { when: { base: "int" }, output: { base: "bool" } },
    ],
  },
  // ── Boundary (§26f) — the key is used without entering the pipeline.
  {
    name: "agent.sign",
    kind: "transform",
    toolbox: "agent",
    shelf: "boundary",
    glyph: "agent-sign",
    doc: "Sign the pipeline payload with a My Keys key — the private key never enters the pipeline; the unlock happens inside the vault with per-use approval. `format=auto` follows the key's kind: PGP → OpenPGP signature, SSH → sshsig (`namespace=` names the domain, `git` for git). Prefer this over `agent.unlock | gpg.sign`. Example: `input | utf8 | agent.sign AABB… | out $sig`.",
    input: "text",
    output: "text",
    // keying: the same OpenPGP signing path as `gpg.sign`, with a stored key.
    entropy: "keying",
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
    doc: "Decrypt an OpenPGP message with a My Keys key — ciphertext in, plaintext out; the private key never enters the pipeline (per-use approval). PGP-kind keys only: SSH signing keys cannot decrypt. Example: `input | agent.decrypt AABB… | out $plain`.",
    input: "text",
    output: "text",
    entropy: "none",
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
    // `execAgentUnlock` reads `inputs.gpg.passphrase`, and nothing said so.
    // Unguarded, unlike `agent.save`'s: there the mode is a param the recipe
    // writes, so a `when:` can read it; here whether a passphrase is owed is a
    // property of the key in the vault, which no declaration can see. So the
    // panel is offered whenever this op is present and the panel's own copy
    // says it is only needed for passphrase-protected keys. Undeclared, the
    // field never appeared at all — the reader existed and had no writer, and
    // a passphrase-protected key (the recommended mode) could not sign
    // anything from this app.
    unresolvedInputs: "gpgPass",
    entropy: "none",
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
    doc: "Emit stored `publicArmored` for a My Keys fingerprint — no unlock. Example: `agent.pub AABB… | out $pub`.",
    input: "none",
    output: "openpgp-key",
    entropy: "none",
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
    entropy: "none",
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
    doc: "Writes to the keyring of *whoever runs the recipe* — a shared link containing `agent.save` saves into the reader's vault, and nothing in the recipe undoes it. Reach for it when the write is the point: a `foreach` over generated keys, or a workspace you re-run yourself. Not available headlessly — `basilisk run` refuses the `agent` toolbox at pre-flight (exit 4), because Node has no vault. Save the pipeline's private key into My Keys. OpenPGP armor saves as kind pgp; a WebCrypto keypair saves as kind ssh (ed25519/ec/rsa — id is the SSH SHA256 fingerprint) or raw (x25519). `protection=device|passphrase|passkey`; passphrase applies to pgp only (non-PGP payloads have no S2K yet). Example: `genkey ed25519 | agent.save | out $id`.",
    input: "openpgp-key",
    output: "openpgp-key",
    // keying: re-protecting a stored key draws the S2K salt and IV that are
    // the only thing between the passphrase and the private key.
    entropy: "keying",
    overloads: [
      { when: { base: "openpgp-key" }, output: { base: "openpgp-key" } },
      { when: { base: "keypair" }, output: { base: "keypair" } },
    ],
    // The passphrase this wrap is performed under is typed at run time and has
    // no param to be bound to — it is the step, not a slot, that needs it.
    unresolvedInputs: { panel: "gpgPass", when: { protection: "passphrase" } },
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
    doc: "Fetch a public key by fingerprint (device cache → This site `/pks/lookup` → optional explicit upstream). Example: `hkp.get AABB… | out $bob`.",
    input: "none",
    output: "openpgp-key",
    entropy: "none",
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
        emptyMeans: "This site only (page origin /pks/lookup)",
        doc: "An allowlisted host to override on miss (signed-in + upstream enabled).",
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
    entropy: "none",
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
        emptyMeans: "This site only — no silent upstream",
        doc: "An allowlisted host to search upstream on miss.",
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
    entropy: "none",
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
    entropy: "none",
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
    doc: "Merge pipeline recipients with `with=$slot` (dedupe by fingerprint).",
    input: "recipients",
    output: "recipients",
    entropy: "none",
    params: [
      {
        name: "with",
        type: "string",
        slot: "required",
        slotOf: ["recipients", "openpgp-key", "text"],
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
    entropy: "none",
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
    doc: "Emit a signable receipt for this run: recipe source, per-cell input/output **digests** (never the values), timestamps, and the op-registry version. Sign it with the vault key — `run.receipt | gpg.sign key=$me | out $receipt` — and check it later with `run.verify`.",
    input: "none",
    output: "text",
    // none — and it still re-runs to a different document, because it stamps
    // `createdAt`. That is the clock, which a manifest declares on its own
    // axis; differing output is not by itself evidence of entropy.
    entropy: "none",
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
    name: "run.manifest",
    kind: "source",
    toolbox: "io",
    shelf: "receipt",
    doc: "Emit the run manifest for this notebook — the commitment `run.receipt` is the observation of: recipe source and its digest, one row per cell (index, `@peer`, publish, recipe text and digest), and the op-registry version. Sign it and hand it round *before* the run — `run.manifest | gpg.sign key=$me | out $manifest` — then check the receipt against it. Example: `run.manifest \"Thursday ceremony\" | out $manifest`.",
    input: "none",
    output: "text",
    // none, on the same reading as `run.receipt`: canonical JSON over recipe
    // text and digests, drawing nothing. It re-runs to a different document
    // only where the recipe changed.
    entropy: "none",
    params: [
      {
        name: "title",
        type: "string",
        positional: true,
        default: "",
        doc: "Notebook title recorded in the manifest (defaults to the notebook title)",
      },
    ],
  },
  {
    name: "run.attest",
    kind: "transform",
    toolbox: "io",
    shelf: "receipt",
    doc: "Attest a run manifest: takes manifest text (signed or plain) and emits a small document saying *I saw this manifest* — its digest and a claimed time, with no name and no fingerprint, because the signature around it is what says who. Attesting is not consenting to run, and a claimed time is nobody's evidence but the signer's. Example: `input | run.attest | gpg.sign key=$me | out $attestation`.",
    input: "text",
    output: "text",
    // none — it digests text it was handed and stamps the clock. The clock is
    // the manifest's other declared axis, not entropy.
    entropy: "none",
    params: [],
  },
  {
    name: "run.verify",
    kind: "transform",
    toolbox: "io",
    shelf: "receipt",
    conjugateOf: "run.receipt",
    doc: "Check a receipt (signed or plain JSON) against the run happening now — digests only, so neither side reveals a secret. Fail-loud by default; `run.verify -q` emits a bool instead. Example: `input | run.verify -q | out $ok`.",
    input: "text",
    output: "bool",
    entropy: "none",
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
    name: "playbook",
    kind: "source",
    toolbox: "io",
    shelf: "receipt",
    conjugate: "playbook.verify",
    pairCaption: "Recipe playbook",
    pairLabels: { forward: "Write", reverse: "Verify" },
    doc: "Write a signed playbook for a procedure — what somebody follows when nobody is left to ask. Carries the canonical recipe text (not a digest of it: in a recovery there is nowhere else to get the text from), a `purpose` sentence, and the op-registry version. `recipe=` names the procedure and defaults to the notebook this runs in — a *recovery* playbook usually names the recovery, not the ceremony that would mint a new secret. Sign it and put it in the envelope with the printed cards — `playbook \"Board key recovery\" purpose=\"…\" | gpg.sign key=$me | out $playbook`. Unlike a run manifest it carries no peers, no vault key ids and no pinned inputs, because it is meant to be handed to somebody who was never in the room. Example: `playbook \"Board key recovery\" | out $playbook`.",
    input: "none",
    output: "text",
    // none, on `run.manifest`'s reading: canonical JSON over recipe text and a
    // digest of it. It re-runs to a different document only where the recipe
    // changed — or where the clock did, which is a declared axis and not entropy.
    entropy: "none",
    params: [
      {
        name: "title",
        type: "string",
        positional: true,
        default: "",
        doc: "What this procedure is called (defaults to the notebook title)",
      },
      {
        name: "purpose",
        type: "string",
        default: "",
        doc: "What a stranger holding one card is meant to do — kept beside the recipe rather than as a `#` comment inside it, so rewording the instruction does not change the recipe digest",
      },
      {
        name: "split",
        type: "string",
        default: "",
        doc: "Split label these cards belong to (`share-check.js`'s `A1B2-C3D4-E5F6`), so a custodian holding two envelopes can tell which playbook is which",
      },
      {
        name: "recipe",
        type: "string",
        slot: true,
        slotOf: ["text"],
        default: "",
        doc: "The procedure to vouch for — recipe text, or a `$slot` holding some. Defaults to the notebook this runs in. Refused if it does not compile: a playbook nobody can follow is worse than none",
      },
    ],
  },
  {
    name: "playbook.verify",
    kind: "transform",
    toolbox: "io",
    shelf: "receipt",
    conjugateOf: "playbook",
    doc: "Check a signed playbook against a key and emit the recipe it vouches for. Fail-loud with no soft mode, on `jose.verify`'s reasoning — an unverified procedure is attacker-chosen, and there is nothing to branch on. The document is parsed out of the bytes the signature covered, never out of the armor separately. Paste the result into a notebook and read it before running it. Example: `input | playbook.verify key=$author | out $recipe`.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text", "openpgp-key"],
        default: "",
        doc: "The author's public key slot (`$pub`); omit to use the vault key / recipients",
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
    entropy: "none",
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
      // Same count-driven shape `quorum.recv` established: one code stays `text`
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
    entropy: "none",
    params: [],
  },
  {
    name: "clipboard.write",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    doc: "Copy the current value to the system clipboard and pass it through — text verbatim, bytes as base64, structured values as JSON. Toast-weight confirm, no dialog: you just ran the recipe that produced the value. Example: `… | out $invite | clipboard.write`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
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
    doc: "Chunked AES-GCM in the STREAM construction — the way to encrypt a *file*, since `SubtleCrypto.encrypt` is one-shot and its single tag only verifies after the last byte. Each 64 KiB chunk carries its own tag and its index in the nonce, so reorder, splice, and truncation are all detected. A fresh file key is wrapped under `key=$slot`, which is what makes counter nonces safe with a reused key. **Not age** — same construction, different AEAD and header (see `age.encrypt` for files the `age` CLI can read). Example: `file.read | stream.seal key=$cek | file.save name=doc.bskstrm`.",
    input: "bytes",
    output: "bytes",
    // keying: a fresh 32-byte file key, wrapped under the bound key. Seeding
    // it would let every peer decrypt the stream.
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live AES key slot (`$cek`) used to wrap the per-file key; omit to use the key panel",
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
    doc: "Open a `stream.seal` file. Distinguishes its failures: a bad tag means the file was modified or its chunks reordered; a missing final-chunk flag means it was truncated. Chunk size is read from the header, so `chunk=` is not repeated here. Example: `file.read | stream.open key=$cek | file.save`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        unresolvedInput: true,
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live AES key slot (`$cek`) the file was sealed under; omit to use the key panel",
      },
    ],
  },
  {
    name: "age.keygen",
    kind: "source",
    toolbox: "age",
    shelf: "keys",
    doc: "Generate an age X25519 identity (`AGE-SECRET-KEY-1…`) — the same thing `age-keygen` writes. Secret: the tile stays masked until you reveal it. Its public half comes from `age.recipient`. Example: `age.keygen | out $id`.",
    input: "none",
    output: "text",
    entropy: "keying",
    params: [],
  },
  {
    name: "age.recipient",
    kind: "transform",
    toolbox: "age",
    shelf: "keys",
    doc: "Identity → recipient (`age1…`): the publishable half, derived and not invertible. An `age1…` already on the stem passes through, so this is safe to write when you are unsure which half you hold. Example: `in $id | age.recipient | out $pub`.",
    input: "text",
    output: "text",
    entropy: "none",
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
    doc: "Encrypt to age recipients — real `age-encryption.org/v1`, produced by typage (age's author's implementation), so `age -d` reads it. `to=` takes one or more `age1…` recipients or an `$slot`; `passphrase=` is the scrypt mode instead (never both). `armor=true` for the PEM-style text form. CLI: `age -r age1… -o doc.age doc`. Example: `file.read | age.encrypt to=$pub | file.save`.",
    input: "bytes",
    output: "bytes",
    // keying: an age file key plus, for a recipient, an ephemeral X25519
    // keypair — the two values the recipient's key is used to protect.
    entropy: "keying",
    params: [
      {
        // `string`, not `slot`, so a literal `age1…` parses — a recipient is
        // public, and `age -r age1…` is how everyone writes it. `key=` on the
        // decrypt side stays a `slot` for the opposite reason.
        name: "to",
        type: "string",
        slot: true,
        slotOf: ["bytes", "text"],
        positional: true,
        default: "",
        doc: "Recipients: `age1…` (space/comma separated) or an `$slot` holding them",
      },
      {
        // `secret: true` says the UI binds this to a slot and that serialize
        // drops any literal — and until `slot` existed, nothing said the
        // runtime had to *resolve* one. It did not: `passphrase=$pw` encrypted
        // under the four characters `$pw`. Declaring it is what found that.
        //
        // `"required"`, not `true`, since the sweep that fixed `sss.split`: a
        // literal here was legal, ran, and then *disappeared* on serialize, so
        // the recipe a peer opened said `age.encrypt` with no mode at all and
        // failed at the run with nothing in the text explaining what had been
        // taken out of it. Dropping a value the recipe's meaning depends on is
        // the option that fix rejected; refusing it at the parser is the one it
        // took, and this param is the reason the drop existed.
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        default: "",
        secret: true,
        emptyMeans: "encrypt to the `to=` recipients instead — one of the two is required",
        doc: "Passphrase (scrypt) mode instead of recipients — `age -p`. `$slot` only, never a literal (`input | out $pw`, then `passphrase=$pw`).",
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
    doc: "Decrypt an age file with `key=$identity` (or `passphrase=`). Accepts binary and armored input, including an armored file read as bytes. CLI: `age -d -i key.txt doc.age`. Example: `file.read | age.decrypt key=$id | file.save`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
    params: [
      {
        // Deliberately a `slot` and not a string: a literal identity in `key=`
        // would be a private key sitting in recipe text, which is exactly what
        // Copy link, Export, and the workspace library then carry off.
        name: "key",
        type: "string",
        // An age identity is the *text* `AGE-SECRET-KEY-1…`, not a CryptoKey.
        // `paramText` decodes a Uint8Array and stringifies anything else, so a
        // key or keypair arrived at `IDENTITY_RE` as "[object Object]" and
        // failed there, one layer too late to say why.
        slot: "required",
        slotOf: ["bytes", "text"],
        positional: true,
        default: "",
        // The one param here that is required *or* — `execAgeDecrypt` takes an
        // identity or a passphrase and refuses only when it has neither. Said
        // as a phrase rather than a `requiredWith`, which can only name a
        // sibling that arms a need, not one that answers it instead.
        emptyMeans: "decrypt with passphrase= instead — one of the two is required",
        doc: "Slot holding an `AGE-SECRET-KEY-1…` identity (never write the identity inline — recipe text is shareable)",
      },
      {
        // Ref-only for `age.encrypt passphrase=`'s reason — see there.
        name: "passphrase",
        type: "string",
        slot: "required",
        slotOf: ["bytes", "text"],
        default: "",
        secret: true,
        emptyMeans: "decrypt with key= instead — one of the two is required",
        doc: "Passphrase for a file encrypted with `age -p` — `$slot` only, never a literal (`input | out $pw`, then `passphrase=$pw`).",
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
    doc: "Open a file from disk into the pipeline. The browser's own picker is the consent — no extra prompt (unlike `clipboard.read`, where the page chooses when to look). Arrives as `bytes`; write `as=text` when the recipe wants it decoded as UTF-8. **The type is read from the recipe, never sniffed from the file** — a source that picked its own type would make every compile-time answer downstream a guess. Filename and MIME ride along in meta, so `file.read | age.encrypt to=$pub | file.save` names the output for you. Main-thread only. Example: `file.read accept=.pem | inspect`.",
    input: "none",
    output: "bytes",
    entropy: "none",
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
        default: "bytes",
        // Two values, and no third. `auto` was retired (migrateRecipe rewrites
        // it to `bytes`) because it sniffed MIME/extension at run time while
        // this `effectiveIo` — which has no file to sniff — declared `bytes`,
        // so `file.read accept=.pem | base64` compiled clean and threw.
        enum: ["bytes", "text"],
        doc: "Pipeline type — bytes never guesses an encoding; text decodes as UTF-8. Read from the recipe, never from the file",
      },
    ],
    effectiveIo(params) {
      // Total over the enum, so the declared type is a promise the run keeps:
      // `execFileRead` makes exactly this decision from exactly this param.
      return { input: "none", output: String(params?.as) === "text" ? "text" : "bytes" };
    },
  },
  {
    name: "file.save",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    conjugateOf: "file.read",
    doc: "Write the current value to disk and pass it through, like `out`. Uses the File System Access API's Save dialog where present, otherwise a plain download. The name comes from `name=`, else the value's own meta (a `file.read` upstream, or `age.encrypt`), else `output.bin`. Example: `… | age.encrypt to=$pub | file.save name=doc.age`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "",
        emptyMeans: "inherit the name from the value",
        doc: "Filename to suggest",
      },
      {
        name: "mime",
        type: "string",
        default: "",
        emptyMeans: "infer the type from the value",
        doc: "MIME type override",
      },
    ],
  },
  {
    name: "text",
    kind: "sink",
    toolbox: "io",
    shelf: "ports",
    doc: "Emit a message tile (no filename; Encrypt compose). Prefer `out $label` when you need a file tile + reusable slot. (Legacy aliases `print`/`echo` migrate via Upgrade recipe.)",
    input: "text",
    output: "text",
    entropy: "none",
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
    doc: "Emit a file tile, register a live `$slot` for later `in`, and pass through. Prefer `out $public` (bare `out public` rewrites to `$`). File paths reserved — not supported yet.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "$output",
        doc: "Slot / filename stem — `$label` (canonical); bare ident rewrites to `$ident`",
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
        emptyMeans: "infer the extension from the value",
        doc: "File extension (e.g. pem, asc, bin)",
      },
      {
        name: "mime",
        type: "string",
        default: "",
        emptyMeans: "infer the type from the value",
        doc: "MIME type override",
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
    entropy: "none",
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
    // keying: `createPasskeyPrf` draws the 32-byte PRF salt that the
    // authenticator evaluates its PRF over, and this step's output *is* that
    // PRF's result. The drawn value becomes an input to key material.
    entropy: "keying",
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
    // public: a 32-byte assertion challenge, which the authenticator echoes
    // verbatim in clientDataJSON. It must be unpredictable to a third party —
    // a pooled value is, since the pool is not published — and it never
    // touches the credential's private key, which lives in the authenticator
    // and is not derived from anything this step draws. Contrast
    // `webauthn.create`, which draws the PRF salt.
    entropy: "public",
    params: [],
  },
  {
    name: "webauthn.prf",
    kind: "source",
    toolbox: "webauthn",
    shelf: "essentials",
    doc: "Unlock PRF IKM from a vault passkey enrolment (same ceremony as My Keys unlock; offers every enrolled credential, and the authenticator answers for the one it holds). Pipe into `hkdf` / `aes-gcm`. Main-thread only. Example: `webauthn.prf | hkdf length=32 | …`.",
    input: "none",
    output: "bytes",
    // keying by the safe default rather than by a settled argument: the only
    // value this step draws is an assertion challenge (the PRF salt is the
    // stored one from enrolment), which would read as `public` — but the step
    // hands back IKM, and `keying` is the answer that costs nothing to be
    // wrong about.
    entropy: "keying",
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
    entropy: "none",
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
    entropy: "none",
    params: [
      {
        name: "aaguid",
        type: "string",
        positional: true,
        default: "",
        emptyMeans: "read the AAGUID from the JSON on the stem",
        doc: "AAGUID UUID",
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
    doc: "Inspect a compact JWS/JWE **without verifying it** — header plus claims, marked unverified. This is the safe first move on a token you were handed: it never checks a signature, so it never implies one was valid. Example: `input | jose.decode | out $claims`. To trust the contents, use `jose.verify`.",
    input: "text",
    output: "text",
    entropy: "none",
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
    doc: "Sign the pipeline payload into a compact JWS (a JWT when the payload is JSON claims). `alg=auto` reads the algorithm off the key; naming one is checked against the key, never trusted. Example: `input | jose.sign key=$k alg=es256 | out $token`.",
    input: "text",
    output: "text",
    // keying: ES256 is ECDSA, so the nonce argument on `sign` applies here too.
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live signing key slot (`$k`) — private half or HMAC secret",
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
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
        default: "",
        doc: "Live verification key slot (`$pub`) — public half or HMAC secret",
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
    doc: "Encrypt the payload into a compact JWE. AES-GCM content encryption only (`enc=a128gcm|a192gcm|a256gcm`); key management is `dir` (the slot key *is* the CEK), AES-KW, or RSA-OAEP-256. Example: `input | jose.encrypt key=$cek | out $jwe`.",
    input: "text",
    output: "text",
    // keying: every `alg=` but `dir` mints a fresh content-encryption key
    // (`crypto.subtle.generateKey`) and wraps it. `dir` draws only the GCM IV,
    // but one declaration covers the step, so it takes the worse mode.
    entropy: "keying",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
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
    entropy: "none",
    params: [
      {
        name: "key",
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text"],
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
    entropy: "none",
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
    entropy: "none",
    params: [],
  },
  {
    name: "peek",
    kind: "transform",
    toolbox: "flow",
    shelf: "control",
    doc: "Side inspect snapshot; stem unchanged. Use instead of an empty `tee`. Example: `genkey ec/p256 | peek keypair | export pkcs8 | pem | out $private`.",
    input: "bytes",
    output: "bytes",
    entropy: "none",
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
  // ── WebRTC: ICE and STUN (design v2 §22b/23a/23c) ──
  {
    name: "rtc.ice",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "ICE server config for a quorum exchange — STUN for reflexive discovery, optional TURN relay with credentials. Emits JSON consumed by `quorum.offer`/`quorum.join` via `ice=$slot`. `credential=` takes a **slot**, not a literal, so the secret never rides out through Copy link or an exported notebook. A STUN binding request tells whoever answers it your public address, so `stun=none` declines every third party — the exchange then gathers host candidates only, which reaches peers on your own network and not across NAT. Example: `rtc.ice turn=turn:relay.example.org:3478 username=u credential=$turncred | out $ice`.",
    input: "none",
    output: "endpoint",
    entropy: "none",
    params: [
      {
        name: "stun",
        type: "string",
        positional: true,
        default: "",
        emptyMeans: "Cloudflare + Google STUN — write none for no third party",
        doc: "Comma-separated stun: URLs, or `none` for no STUN server at all (host candidates only).",
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
        type: "string",
        // A TURN credential is a shared secret string the relay operator
        // issued. `engine.js` reads a text slot with String() and everything
        // else through `TextDecoder().decode(slot.data)` -- which on a
        // CryptoKey throws a TypeError naming neither the op nor the param.
        slot: "required",
        slotOf: ["bytes", "text"],
        secret: true,
        default: "",
        // A credential authenticates to a relay, so there is nothing to supply
        // until `turn=` names one — the STUN-only config every quorum exchange
        // starts from wants no credential at all. Declaring the gate is what
        // stops `input-needs.js` reporting a missing binding on the common case.
        requiredWith: "turn",
        doc: "TURN credential — bind an $slot from Inputs; never stored/shared as literal text",
      },
    ],
  },
  {
    name: "stun.check",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "One-shot NAT diagnostic: gathers ICE candidates against a STUN server and reports the server-reflexive (public) address, candidate mix, and gather time as JSON. Not publishable — a plain output row. Example: `stun.check | out $nat`.",
    input: "none",
    output: "endpoint",
    // keying: probing a STUN server means constructing an RTCPeerConnection,
    // and a peer connection mints a DTLS certificate and ICE credentials
    // before it sends anything. The endpoint it reports is public; the
    // keypair made along the way is not.
    entropy: "keying",
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
  // ── Peer connection manager (§55) ──
  // The layer between raw `rtc.*` and the identity-bound `quorum.*` mesh: named
  // connections that outlive the op that made them. `rtc.offer`/`rtc.answer`
  // were retired into `peer.offer`/`peer.answer` because they closed the very
  // `RTCPeerConnection` whose SDP they returned, which made the two shipped
  // hand-carried templates describe a flow that could not complete.
  {
    name: "peer.offer",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    doc: "Open a **managed** peer connection and emit its SDP offer. Unlike the retired `rtc.offer`, the connection stays live under `name=` — carry the offer to the other browser, bring their answer back to `peer.accept`, and `peer.wait` for it to connect. No PGP audience, no room, no relay. The channel is DTLS-encrypted but the far end is **not authenticated**: whoever received the offer is on the other side. Use `quorum.offer` when the peer's identity has to be proven. Example: `peer.offer a | out $offer`.",
    input: "none",
    output: "sdp",
    // keying: `new RTCPeerConnection` mints the DTLS certificate and ICE
    // credentials this link is authenticated by. The SDP that comes out
    // carries only their fingerprint, which is why the *output* is public and
    // the *draw* is not.
    entropy: "keying",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "default",
        doc: "Connection name — how later steps and cells refer to this link",
      },
      {
        name: "ice",
        type: "string",
        slot: "required",
        slotOf: ["endpoint", "text"],
        default: "",
        emptyMeans: "built-in Cloudflare + Google STUN",
        doc: "$slot holding `rtc.ice` output. Bind one from `rtc.ice stun=none` to contact no third party at all — the empty list is carried through and honoured, not replaced.",
      },
      {
        name: "label",
        type: "string",
        default: "basilisk",
        doc: "Data-channel label carried in the SDP",
      },
      {
        name: "timeout",
        type: "int",
        default: 5000,
        doc: "How long to gather candidates before emitting the offer (ms) — a hand-carried offer with no candidates is useless to the far side",
      },
    ],
  },
  {
    name: "peer.answer",
    kind: "transform",
    toolbox: "webrtc",
    shelf: "peer",
    doc: "Answer a remote **offer** and keep the resulting managed connection under `name=`. The conjugate of `peer.offer`: send the answer back, then `peer.wait` on both sides. Refuses an SDP that is already an answer — that one goes to `peer.accept`. Example: `in $remoteOffer | peer.answer b | out $answer`.",
    input: "sdp",
    output: "sdp",
    // keying: the answering side builds its own RTCPeerConnection, so it mints
    // its own DTLS certificate — same reasoning as `peer.offer`.
    entropy: "keying",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "default",
        doc: "Connection name for the link this creates",
      },
      {
        name: "ice",
        type: "string",
        slot: "required",
        slotOf: ["endpoint", "text"],
        default: "",
        emptyMeans: "built-in Cloudflare + Google STUN",
        doc: "$slot holding `rtc.ice` output. Bind one from `rtc.ice stun=none` to contact no third party at all — the empty list is carried through and honoured, not replaced.",
      },
      {
        name: "timeout",
        type: "int",
        default: 5000,
        doc: "Candidate-gathering timeout before the answer is emitted (ms)",
      },
    ],
  },
  {
    name: "peer.accept",
    kind: "transform",
    toolbox: "webrtc",
    shelf: "peer",
    doc: "Apply the remote **answer** to a connection this notebook offered, completing the exchange. Signalling only — it does not wait for ICE, so that \"this is not an answer\" and \"no candidate pair worked\" stay separate errors with separate fixes; `peer.wait` owns the second. Example: `in $remoteAnswer | peer.accept a | out $state`.",
    input: "sdp",
    output: "connstate",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "default",
        doc: "Connection that made the offer this answers",
      },
    ],
  },
  {
    name: "peer.wait",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    doc: "Pause the run until a managed connection is connected and its data channel open, then emit the live channel. This is the step that tells you ICE succeeded: if it fails, the error is the same sentence the Connections panel shows, including what to do about it. Example: `peer.wait a | out $link`.",
    input: "none",
    output: "channel",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "default",
        doc: "Connection to wait for",
      },
      {
        name: "wait",
        type: "int",
        default: 60000,
        doc: "How long to wait for the connection to come up (ms)",
      },
    ],
  },
  {
    name: "peer.send",
    kind: "transform",
    toolbox: "webrtc",
    shelf: "channel",
    doc: "Write the pipeline text to a managed connection's data channel, passing the value through. **Not `quorum.send`**: that op encrypts under the exchange's pairwise session key, which a direct connection does not have. What protects this traffic is DTLS alone, and DTLS does not tell you who the far end is. Example: `\"ping\" | peer.send a`.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "default",
        doc: "Connection to write to",
      },
    ],
  },
  {
    name: "peer.recv",
    kind: "source",
    toolbox: "webrtc",
    shelf: "channel",
    doc: "Read from a managed connection's data channel. `count=1` (default) waits for one message and emits it as text; `count=3` or `count=all` collects several and emits a bundle for `foreach`. Pauses the run until enough arrive or `wait` expires. Example: `peer.recv b | out $msg`.",
    input: "none",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "default",
        doc: "Connection to read from",
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
        default: 60000,
        doc: "Receive timeout (ms)",
      },
    ],
    effectiveIo(params) {
      // Same rule as `quorum.recv`: the output *type* changes with `count`, and it
      // does so on a parameter the checker can read before the run — which is
      // the permitted form of a varying type. A type that depended on what the
      // run produced would not be.
      const count = String(params?.count ?? "1").trim().toLowerCase();
      return { input: "none", output: count === "1" ? "text" : "bundle" };
    },
  },
  {
    name: "peer.close",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    doc: "Close a managed connection and forget it, or every direct connection when `name=` is empty. Never touches the quorum mesh's links even when closing everything — those belong to `quorum.close`, which also has session keys to zeroize. Example: `peer.close a | out $state`.",
    input: "none",
    output: "connstate",
    entropy: "none",
    params: [
      {
        name: "name",
        type: "string",
        positional: true,
        default: "",
        emptyMeans: "close every direct connection",
        doc: "Connection to close — one name, or `all` for the same sweep the empty field does",
      },
    ],
  },

  // ── WebRTC primitives (design v2 §23a/23b/26a/26b/29a/29d/30d) ──
  // The raw layer under `peer.*` and `quorum.*`: each wraps one browser WebRTC
  // capability so ICE/DTLS/SCTP are debuggable outside a live session.
  {
    name: "rtc.gather",
    kind: "source",
    toolbox: "webrtc",
    shelf: "ice",
    glyph: "ports",
    doc: "Gather ICE candidates against the configured servers and emit one row per candidate — `host` (local NIC), `srflx` (server-reflexive, via STUN), `relay` (via TURN), plus any `prflx` peer-reflexive found by trickle. Each row carries protocol (`udp`/`tcp`). A missing `relay` row is informational, not an error — it just means no TURN is configured. This is what `quorum.offer` consumes internally; run it standalone to see why a later connection failed. Example: `rtc.ice turn=… | out $ice` then `rtc.gather ice=$ice | out $cands`.",
    input: "none",
    output: "candidate",
    // keying: gathering needs a live RTCPeerConnection, which mints a DTLS
    // certificate to gather with even though only candidates are reported.
    entropy: "keying",
    params: [
      {
        name: "ice",
        type: "string",
        slot: "required",
        slotOf: ["endpoint", "text"],
        default: "",
        emptyMeans: "built-in Cloudflare + Google STUN",
        doc: "$slot holding `rtc.ice` output. Bind one from `rtc.ice stun=none` to contact no third party at all — the empty list is carried through and honoured, not replaced.",
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
    doc: "Report the ICE candidate-pair check matrix for the live exchange: one row per local×remote pair with its state (`waiting`/`in-progress`/`succeeded`/`failed`), the nominated pair flagged, plus this peer's `controlling`/`controlled` role. Needs a live `quorum.offer`/`quorum.join` — ICE only checks pairs once both sides have exchanged candidates. Example: `quorum.offer … | out $s` then `rtc.check | out $pairs`.",
    input: "none",
    output: "stats",
    entropy: "none",
    params: [],
  },
  {
    name: "rtc.certificate",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "genkey",
    doc: "Generate a DTLS identity (`RTCCertificate`) — the certificate whose fingerprint the remote peer sees. Mirrors `genkey`'s shape. Most recipes never need this: `quorum.offer` mints a throwaway certificate itself. Use it when you want a stable fingerprint a peer can recognize across sessions. Example: `rtc.certificate | out $id`.",
    input: "none",
    output: "certificate",
    // keying: `RTCPeerConnection.generateCertificate` is key generation. The
    // value that travels the pipe is only the fingerprint, but the private
    // half exists and was drawn here.
    entropy: "keying",
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
    name: "rtc.state",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "ports",
    doc: "Observe-only snapshot of the live exchange's `connectionState`, `iceConnectionState`, `iceGatheringState`, and `signalingState`, per peer. Diagnostic — never bind it as an input to a crypto op. Needs a live `quorum.offer`/`quorum.join`. Example: `rtc.state | out $state`.",
    input: "none",
    output: "connstate",
    entropy: "none",
    params: [],
  },
  {
    name: "rtc.restart",
    kind: "source",
    toolbox: "webrtc",
    shelf: "peer",
    glyph: "ports",
    doc: "Restart ICE on every peer connection of the live exchange and report the resulting per-peer state. Renegotiates in place — room, invite, and roster survive. The chainable form of the Connections panel's Restart button. Example: `rtc.restart | out $state`.",
    input: "none",
    output: "connstate",
    // keying: an ICE restart's whole purpose is fresh ICE credentials.
    entropy: "keying",
    params: [],
  },
  {
    name: "rtc.stats",
    kind: "source",
    toolbox: "webrtc",
    shelf: "channel",
    glyph: "ports",
    doc: "Data-channel back-pressure and counters for the live exchange: `bufferedAmount` against its low-water threshold, ready state, and messages/bytes sent+received per peer. Use it to see whether `quorum.send` is queueing behind a slow link. Example: `rtc.stats | out $bp`.",
    input: "none",
    output: "stats",
    entropy: "none",
    params: [],
  },
  {
    name: "rtc.quality",
    kind: "source",
    toolbox: "webrtc",
    shelf: "rtcstats",
    glyph: "ports",
    doc: "Live `getStats()` quality numbers for the exchange — round-trip time and bytes/packets each way, per connected peer. **Packet loss is not reported**: loss statistics come from RTP, and this transport is SCTP data channels, so there is no RTP on the connection to lose any. The panel says so rather than showing a zero. Example: `rtc.quality | out $quality`.",
    input: "none",
    output: "stats",
    entropy: "none",
    params: [],
  },

  // ── Quorum: session management for RTC peers (design v2 §21a, §8) ──
  // Its own toolbox, not a shelf of WebRTC. Nothing below is a browser
  // built-in: the room is derived from an OpenPGP audience, the invite is
  // signed and posted through a relay, and the traffic is encrypted under a
  // pairwise key `derivePairwiseSessionKey` mints over a transcript binding
  // both DTLS fingerprints. WebRTC is what this layer *uses* — `lib/webrtc/`
  // holds the link inventory, the ICE defaults, the negotiation rule and the
  // peer-connection driver itself, and quorum registers into them the same way
  // `peer.*` does.
  //
  // The names do not change and were never in question: `quorum.send` owns its
  // name because it owns the key (4fe3322). That is a fact about the
  // *namespace*; which drawer the op is filed in is a different question, and
  // this is the answer to the second one only.
  {
    name: "quorum.offer",
    kind: "source",
    toolbox: "quorum",
    shelf: "exchange",
    doc: "Open a run-scoped p2p exchange as creator: derives the room from the audience, publishes a PGP-signed invite through the encrypted relay, then PAUSES the run at this cell until a peer meshes (or `wait` expires). Output is the session summary JSON; `quorum.send`/`quorum.recv`/`quorum.close` downstream use the live session. Example: `quorum.offer to=\"AABB…,CCDD…\" key=$me | out $session`. Main-thread (WebRTC).",
    input: "none",
    output: "session",
    // keying: forming the mesh mints a throwaway DTLS certificate per link.
    entropy: "keying",
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
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text", "openpgp-key"],
        secret: true,
        default: "",
        doc: "$slot holding your armored private key (`agent.unlock … | out $me`)",
      },
      {
        name: "ice",
        type: "string",
        default: "",
        emptyMeans: "built-in Cloudflare + Google STUN",
        doc: "$slot holding `rtc.ice` output. Bind one from `rtc.ice stun=none` to contact no third party at all — the empty list is carried through and honoured, not replaced.",
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
    toolbox: "quorum",
    shelf: "exchange",
    doc: "Join a run-scoped exchange as peer: verifies the creator's signed invite, then meshes with per-peer ephemeral ECDH (data-channel PFS). Pauses the run at this cell until connected. Same audience + site = same room, no code to paste. Example: `quorum.join to=\"AABB…,CCDD…\" key=$me | out $session`. Main-thread (WebRTC).",
    input: "none",
    output: "session",
    // keying: joining the mesh mints a throwaway DTLS certificate per link.
    entropy: "keying",
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
        type: "bytes",
        slot: "required",
        slotOf: ["key", "keypair", "bytes", "text", "openpgp-key"],
        secret: true,
        default: "",
        doc: "$slot holding your armored private key",
      },
      {
        name: "ice",
        type: "string",
        default: "",
        emptyMeans: "built-in Cloudflare + Google STUN",
        doc: "$slot holding `rtc.ice` output. Bind one from `rtc.ice stun=none` to contact no third party at all — the empty list is carried through and honoured, not replaced.",
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
    name: "quorum.close",
    kind: "transform",
    toolbox: "quorum",
    shelf: "exchange",
    doc: "End the exchange now: closes every peer connection and zeroizes session keys. Runs implicitly at Clear session — close early when the exchange is done mid-notebook. Passes the value through.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [],
  },
  {
    name: "quorum.send",
    kind: "transform",
    toolbox: "quorum",
    shelf: "channel",
    doc: "Write the pipeline text to the exchange's data channels (per-peer session keys; key-confirmed channels only). `to=` addresses one peer by fingerprint; empty broadcasts to every verified peer, which is the exchange's own policy. Passes the value through unchanged. Requires a `quorum.offer`/`quorum.join` earlier in this run — for a channel with no exchange behind it, use `peer.send`.",
    input: "text",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "to",
        type: "string",
        positional: true,
        default: "",
        emptyMeans: "broadcast to every verified peer",
        doc: "Recipient fingerprint (prefix ok) — one peer instead of all of them",
      },
    ],
  },
  {
    name: "quorum.recv",
    kind: "source",
    toolbox: "quorum",
    shelf: "channel",
    doc: "Read from the exchange's data channels, decrypting under each peer's session key. `count=1` (default) waits for one message and emits it as text (`meta.from` = sender fingerprint); `count=3` or `count=all` collects several and emits a bundle for `foreach`. Pauses the run until enough arrive or `wait` expires. **Messages are matched by arrival order and `from=` alone** — two reads of one sender take whatever landed first, so what a read emits is the next message from that peer, not a particular one. Where that matters, use values that say what they are: `shares` reads each mnemonic's own share index, so a recovery recombines whichever order they arrived in. Example: `quorum.recv | gpg.verify`, or `quorum.recv count=2 | shares | blip39 -d | sss.combine`.",
    input: "none",
    output: "text",
    entropy: "none",
    params: [
      {
        name: "from",
        type: "string",
        default: "",
        emptyMeans: "accept from any verified peer",
        doc: "Only accept from this fingerprint (prefix ok)",
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
  "otp.uri": "qr",
  "otp.parse": "qr",
  "otp.code": "otp",
  "otp.verify": "otp",
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
 * The declared entropy kinds, worst last.
 * @type {readonly EntropyKind[]}
 */
export const ENTROPY_KINDS = /** @type {readonly EntropyKind[]} */ (
  Object.freeze(["none", "public", "keying"])
);

/**
 * Output types whose value can carry a secret, and therefore the steps
 * `registryIssues` requires an `entropy` declaration from.
 *
 * Not every type: `bool` is an answer, `recipients` is a set of public keys,
 * and the WebRTC vocabulary (`endpoint`, `candidate`, `sdp`, `connstate`,
 * `stats`, `session`, `channel`) describes a connection rather than material —
 * an SDP's DTLS fingerprint is published by design. What is left is the set a
 * reader would be alarmed to find in a screenshot.
 *
 * `certificate` is in the list because the type names a keypair even though the
 * value carries only its fingerprints: the question "what randomness made this"
 * is one `rtc.certificate` must answer.
 * @type {readonly IoType[]}
 */
export const SECRET_BEARING_OUTPUTS = /** @type {readonly IoType[]} */ (
  Object.freeze([
    "bytes",
    "text",
    "key",
    "keypair",
    "shares",
    "artifact",
    "bundle",
    "item",
    "openpgp-key",
    "certificate",
  ])
);

/**
 * What kind of randomness a step draws — the *only* correct way to ask.
 *
 * An undeclared step reads as `keying`, so an op nobody has audited is refused
 * by a mirrored run rather than seeded by one. Reading `spec.entropy` directly
 * would turn `undefined` into a falsy "no entropy", which is the exact
 * inversion this default exists to prevent.
 *
 * @param {StepSpec|null|undefined} spec
 * @returns {EntropyKind}
 */
export function stepEntropy(spec) {
  const declared = String(spec?.entropy ?? "");
  return /** @type {EntropyKind} */ (
    ENTROPY_KINDS.includes(/** @type {EntropyKind} */ (declared)) ? declared : "keying"
  );
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

