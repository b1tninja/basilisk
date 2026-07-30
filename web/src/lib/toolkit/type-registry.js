/**
 * Documentation and constructors for the pipeline type system.
 *
 * `types.js` decides whether a value *fits* a step; this module explains what
 * each type **is** and, where the type can be written down, how to make one.
 *
 * Two ideas live here and they are deliberately not the same thing:
 *
 *  1. **Documentation** — every `IoType` gets an entry, including types that
 *     no step currently touches. Producers and consumers are *derived* from
 *     STEPS rather than listed by hand, so this file cannot drift out of sync
 *     with the registry the way a prose doc would.
 *
 *  2. **Construction** — a type that a user can simply *type out* carries a
 *     `literal`. Without it the only way to get (say) a byte string into a
 *     pipeline is `input | hex -d`: an input step, a cast, and a cell that
 *     re-prompts on every run. A literal collapses that to a source step.
 *
 * Only four types have literals, and that is a finding rather than a
 * limitation: a `keypair` is whatever `genkey` returned, a `session` is a live
 * RTCPeerConnection, and a `stats` is a measurement. None of those are
 * writable — they can only be *produced*, so their cards point at the ops that
 * produce them instead of offering an editor that could not work.
 */

import { listSteps, getStep } from "./registry.js";
import { hexToBytes, base64ToBytes } from "./encode.js";

/**
 * @typedef {object} TypeLiteral
 * @property {"string"|"int"|"bool"|"bytes"} form   editor widget to render
 * @property {string} placeholder
 * @property {string} example
 * @property {string} hint                          accepted syntax, one line
 * @property {(raw: string) => LiteralParse} parse
 * @property {(raw: string) => { name: string, params: Record<string, *> }} build
 */

/**
 * @typedef {object} LiteralParse
 * @property {boolean} ok
 * @property {*} [value]        parsed value (for preview only)
 * @property {string} [error]
 * @property {string} [note]    e.g. "0xff → 255" — shown under the field
 */

/**
 * One way a type can come into existence, when there is more than one and the
 * choice is the user's (§31c). Each origin is an ordinary registry step, so
 * picking one inserts that step with its own real param form — "Generate" is
 * literally `genkey`, not a reimplementation of it.
 * @typedef {object} TypeOrigin
 * @property {string} id
 * @property {string} label
 * @property {string} step   registry step name this origin inserts
 * @property {string} hint
 */

/**
 * @typedef {object} TypeMeta
 * @property {string} base
 * @property {string} label
 * @property {string} summary   one line, for the grid tile
 * @property {string} doc       full paragraph, for the card
 * @property {{url: string, label: string}} [ref]
 * @property {TypeLiteral} [literal]  present ⟺ directly instantiable
 * @property {TypeOrigin[]} [origins]  present ⟺ more than one way to make one
 */

const MDN = "https://developer.mozilla.org/en-US/docs/Web/API";

// ── Literal parsers ─────────────────────────────────────────────────────────

/**
 * Parse an integer literal in any of the forms a programmer expects to be able
 * to type: decimal, `0x` hex, `0b` binary, `0o` octal, with `_` separators.
 *
 * Deliberately stricter than `Number()`, which the engine ultimately uses:
 * `Number("")` is 0, `Number("1e3")` is 1000, and `Number(" 12 ")` is 12. Those
 * silently accept things that are not integer literals, so a typo becomes a
 * wrong key length rather than an error. Validation happens here; the engine
 * still coerces, it just never sees input this rejected.
 *
 * @param {string} raw
 * @returns {LiteralParse}
 */
export function parseIntLiteral(raw) {
  const src = String(raw ?? "").trim();
  if (!src) return { ok: false, error: "Enter a number" };

  const neg = src.startsWith("-");
  const body = (neg || src.startsWith("+") ? src.slice(1) : src).replace(/_/g, "");
  if (!body) return { ok: false, error: "Enter a number" };

  /** @type {[RegExp, number, string][]} */
  const radices = [
    [/^0[xX][0-9a-fA-F]+$/, 16, "hex"],
    [/^0[bB][01]+$/, 2, "binary"],
    [/^0[oO][0-7]+$/, 8, "octal"],
  ];
  for (const [re, radix, name] of radices) {
    if (!re.test(body)) continue;
    const n = Number.parseInt(body.slice(2), radix);
    if (!Number.isSafeInteger(n)) return { ok: false, error: "Number is too large" };
    const value = neg ? -n : n;
    return { ok: true, value, radix: name, note: describeInt(value, name) };
  }

  if (!/^[0-9]+$/.test(body)) {
    return { ok: false, error: "Use decimal, or 0x / 0b / 0o" };
  }
  const n = Number.parseInt(body, 10);
  if (!Number.isSafeInteger(n)) return { ok: false, error: "Number is too large" };
  const value = neg ? -n : n;
  return { ok: true, value, radix: "decimal", note: describeInt(value, "decimal") };
}

/**
 * Bytes needed to serialize an integer's magnitude — 42 → 1, 256 → 2.
 * @param {number} value
 * @returns {number}
 */
export function intByteLength(value) {
  const n = Math.abs(value);
  if (n === 0) return 1;
  return Math.ceil((Math.floor(Math.log2(n)) + 1) / 8);
}

/**
 * The §31b readout: what the user typed rendered the *other* way, plus how it
 * will serialize. The point is that "what I typed" and "what the pipeline
 * holds" are never in question — so a hex entry reports its decimal value and
 * a decimal entry reports its hex.
 * @param {number} value
 * @param {string} radix  the notation the user typed in
 * @returns {string}
 */
function describeInt(value, radix) {
  const bytes = intByteLength(value);
  const hex = `0x${Math.abs(value).toString(16).toUpperCase()}`;
  const alt = radix === "decimal" ? `= ${value < 0 ? "-" : ""}${hex} hex` : `= ${value} decimal`;
  return `${alt} · ${bytes} byte${bytes === 1 ? "" : "s"} · big-endian`;
}

/**
 * @param {string} raw
 * @returns {LiteralParse}
 */
export function parseBoolLiteral(raw) {
  const s = String(raw ?? "").trim().toLowerCase();
  if (s === "true" || s === "1" || s === "yes") return { ok: true, value: true };
  if (s === "false" || s === "0" || s === "no") return { ok: true, value: false };
  return { ok: false, error: "Expected true or false" };
}

/**
 * @param {string} raw
 * @param {string} encoding  hex | base64 | utf8
 * @returns {LiteralParse}
 */
export function parseBytesLiteral(raw, encoding = "hex") {
  const src = String(raw ?? "").trim();
  if (!src) return { ok: false, error: "Enter a value" };
  try {
    let bytes;
    if (encoding === "utf8") bytes = new TextEncoder().encode(src);
    else if (encoding === "base64") bytes = base64ToBytes(src);
    else bytes = hexToBytes(src.replace(/^0[xX]/, ""));
    if (!bytes.length) return { ok: false, error: "Enter a value" };
    return {
      ok: true,
      value: bytes,
      note: `${bytes.length} byte${bytes.length === 1 ? "" : "s"}`,
    };
  } catch {
    return { ok: false, error: `Not valid ${encoding}` };
  }
}

// ── The registry ────────────────────────────────────────────────────────────

/** @type {Record<string, TypeMeta>} */
export const TYPE_META = {
  none: {
    base: "none",
    label: "none",
    summary: "No value — the start of a pipeline.",
    doc: "The empty input of a source step. Nothing produces `none`; it is what a pipeline holds before its first step runs, which is why sources such as `genkey` and `random` declare it as their input.",
  },

  bytes: {
    base: "bytes",
    label: "bytes",
    summary: "Raw binary buffer.",
    doc: "An octet string, carried as a Uint8Array. The pipeline's most common currency: ciphertext, digests, signatures, exported key material, and IVs are all bytes. Encoding steps convert between bytes and their textual forms rather than changing the value.",
    ref: { url: `${MDN}/Uint8Array`, label: "MDN · Uint8Array" },
    literal: {
      form: "bytes",
      placeholder: "deadbeef",
      example: "0xdeadbeef",
      hint: "hex, base64, or UTF-8 text",
      parse: (raw) => parseBytesLiteral(raw, "hex"),
      build: (raw) => ({
        name: "bytes",
        params: { value: String(raw ?? "").trim(), encoding: "hex" },
      }),
    },
  },

  text: {
    base: "text",
    label: "text",
    summary: "A Unicode string.",
    doc: "A JavaScript string. Armored keys, PEM blocks, base64, JSON, and passphrases are all text — the refinement on the type (`text/pem`, `text/base64`) records which, so a step can require armored input without re-sniffing the value.",
    ref: { url: "https://www.rfc-editor.org/rfc/rfc3629", label: "RFC 3629 · UTF-8" },
    literal: {
      form: "string",
      placeholder: "hello",
      example: '"hello"',
      hint: "any text",
      parse: (raw) =>
        String(raw ?? "").length
          ? { ok: true, value: String(raw) }
          : { ok: false, error: "Enter some text" },
      build: (raw) => ({ name: "lit", params: { kind: "text", value: String(raw ?? "") } }),
    },
  },

  int: {
    base: "int",
    label: "int",
    summary: "A whole number.",
    doc: "An integer, used for lengths, counts, thresholds, and indexes — `random 32`, `sss.split threshold=3`, `[0:4]`. Written in decimal or in any base a programmer would reach for; the pipeline stores the number, so `0x20` and `32` are the same value.",
    literal: {
      form: "int",
      placeholder: "32",
      example: "0x20",
      hint: "decimal, 0x hex, 0b binary, 0o octal, _ separators",
      parse: parseIntLiteral,
      build: (raw) => {
        const parsed = parseIntLiteral(raw);
        return {
          name: "lit",
          params: { kind: "int", value: parsed.ok ? String(parsed.value) : String(raw ?? "") },
        };
      },
    },
  },

  bool: {
    base: "bool",
    label: "bool",
    summary: "True or false.",
    doc: "A boolean. Produced by the verification steps — `verify` and `gpg.verify` answer whether a signature checked out — and consumed as a flag. A failed verification is `false`, not an error, so the pipeline can branch on it.",
    literal: {
      form: "bool",
      placeholder: "true",
      example: "true",
      hint: "true or false",
      parse: parseBoolLiteral,
      build: (raw) => {
        const parsed = parseBoolLiteral(raw);
        return { name: "lit", params: { kind: "bool", value: parsed.ok ? String(parsed.value) : "false" } };
      },
    },
  },

  key: {
    base: "key",
    label: "key",
    summary: "A single WebCrypto CryptoKey.",
    doc: "One symmetric or asymmetric CryptoKey, as returned by `importKey` or `unwrapKey`. The refinement records its algorithm and usages, which is how a card can tell you an AES-GCM key cannot be handed to `sign` before you run it.",
    ref: { url: `${MDN}/CryptoKey`, label: "MDN · CryptoKey" },
  },

  keypair: {
    base: "keypair",
    label: "keypair",
    summary: "A CryptoKeyPair — public and private half.",
    doc: "What `generateKey` returns for an asymmetric algorithm: `{ publicKey, privateKey }`. Steps that need only one half (`export format=spki`) select it themselves, so the pair travels together until something splits it.",
    ref: { url: `${MDN}/CryptoKeyPair`, label: "MDN · CryptoKeyPair" },
    origins: [
      {
        id: "generate",
        label: "Generate",
        step: "genkey",
        hint: "Make a new pair — genkey's own form, unchanged.",
      },
      {
        id: "import",
        label: "Import",
        step: "keypair",
        hint: "Bring a pair you already have; paste it at run time.",
      },
    ],
  },

  shares: {
    base: "shares",
    label: "shares",
    summary: "A set of secret-sharing shares.",
    doc: "The output of `sss.split` or `blip39`: N shares of which any `threshold` will reconstruct the secret. Carried as a collection so `foreach` can operate on each share and `sss.combine` can consume the set.",
    ref: {
      url: "https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing",
      label: "Shamir's Secret Sharing",
    },
  },

  artifact: {
    base: "artifact",
    label: "artifact",
    summary: "A named, downloadable output.",
    doc: "A materialized result — content plus a filename, MIME type, and sensitivity flag. This is what an output row renders. Terminal steps produce artifacts; nothing consumes one, because it is the end of the pipeline.",
  },

  bundle: {
    base: "bundle",
    label: "bundle",
    summary: "Several values travelling together.",
    doc: "The collection `foreach` produces — one entry per iteration, kept together so downstream steps see a single value. Index into it with `[n]` or flatten it with a sink.",
  },

  item: {
    base: "item",
    label: "item",
    summary: "One element of a collection.",
    doc: "The per-iteration value inside a `foreach` body. Reserved: no step declares `item` in its signature today, because the loop rebinds the pipeline tip to the element type directly.",
  },

  recipients: {
    base: "recipients",
    label: "recipients",
    summary: "Resolved OpenPGP recipients.",
    doc: "A set of public keys an encryption step will encrypt to, each with its fingerprint and capabilities. Produced by keyserver lookups and merges; `gpg.encrypt` consumes it. The capability data is what decides SEIPD v2 versus v1.",
  },

  "openpgp-key": {
    base: "openpgp-key",
    label: "openpgp-key",
    summary: "An OpenPGP key or certificate.",
    doc: "A parsed OpenPGP transferable key — the packet structure of RFC 9580, not the armored text around it. Distinct from `key` because OpenPGP keys carry user IDs, subkeys, and self-signatures that a WebCrypto CryptoKey has no room for.",
    ref: { url: "https://www.rfc-editor.org/rfc/rfc9580", label: "RFC 9580 · OpenPGP" },
  },

  // ── Network types ─────────────────────────────────────────────────────────

  host: {
    base: "host",
    label: "host",
    summary: "A hostname or IP address.",
    doc: "A network host — IPv4, IPv6, or a DNS name — with the family recorded as a refinement. Reserved: declared in the type union so address-valued results have somewhere to land, but no step currently produces or consumes one on its own; addresses travel inside `endpoint` and `candidate` instead.",
  },

  endpoint: {
    base: "endpoint",
    label: "endpoint",
    summary: "A host plus a port and protocol.",
    doc: "An addressable service: a STUN/TURN server from `rtc.ice`, or the public address `stun.check` discovered for you. Carries the transport protocol as a refinement, since a TURN server reachable over UDP may not be over TCP.",
    ref: { url: "https://www.rfc-editor.org/rfc/rfc8489", label: "RFC 8489 · STUN" },
  },

  candidate: {
    base: "candidate",
    label: "candidate",
    summary: "ICE candidates gathered for a connection.",
    doc: "The list `rtc.gatherCandidates` collects: host, server-reflexive, peer-reflexive, and relay routes that ICE will try. Browsers redact the local address of host candidates behind an mDNS name, so what you see is what the peer would see.",
    ref: { url: `${MDN}/RTCIceCandidate`, label: "MDN · RTCIceCandidate" },
  },

  sdp: {
    base: "sdp",
    label: "sdp",
    summary: "A session description — offer or answer.",
    doc: "The negotiated media and transport description exchanged between peers, refined by `which` into offer or answer. Text on the wire, but typed distinctly so an offer cannot be fed where an answer belongs.",
    ref: { url: "https://www.rfc-editor.org/rfc/rfc8866", label: "RFC 8866 · SDP" },
  },

  certificate: {
    base: "certificate",
    label: "certificate",
    summary: "A DTLS certificate for a peer connection.",
    doc: "The self-signed certificate that identifies one end of a WebRTC connection, with its fingerprint. Comparing fingerprints out of band is what makes a data channel authenticated rather than merely encrypted.",
    ref: { url: `${MDN}/RTCCertificate`, label: "MDN · RTCCertificate" },
  },

  session: {
    base: "session",
    label: "session",
    summary: "A live quorum session. Handle — not storable.",
    doc: "An open connection with its peers and room state. A handle to something live: it only means anything inside the run that opened it, so steps other than `out`/`inspect` refuse it rather than let you save a reference that will be dead by the next run.",
    ref: { url: `${MDN}/RTCPeerConnection`, label: "MDN · RTCPeerConnection" },
  },

  channel: {
    base: "channel",
    label: "channel",
    summary: "An open data channel. Handle — not storable.",
    doc: "A single RTCDataChannel within a session, with its reliability settings and buffer state. Like `session`, a live handle: observe it, but do not expect it to survive the run.",
    ref: { url: `${MDN}/RTCDataChannel`, label: "MDN · RTCDataChannel" },
  },

  peer: {
    base: "peer",
    label: "peer",
    summary: "One remote participant.",
    doc: "A single member of a session — identity, connection state, and channels. Reserved: peers are currently reported inside `session` and `connstate` values rather than flowing as their own type.",
  },

  connstate: {
    base: "connstate",
    label: "connstate",
    summary: "Connection state per peer. Observe-only.",
    doc: "Where each peer sits in the new → connecting → connected → disconnected → closed progression. A diagnostic snapshot: it tells you what was true when you looked, so the type system only lets you display it.",
    ref: { url: `${MDN}/RTCPeerConnection/connectionState`, label: "MDN · connectionState" },
  },

  stats: {
    base: "stats",
    label: "stats",
    summary: "A WebRTC statistics report. Observe-only.",
    doc: "Measurements from `getStats` — candidate pairs, round-trip time, packet loss, data-channel buffering. Refined by `kind` so the right reader renders it. Observe-only for the same reason as `connstate`: it is a measurement, not a value to compute with.",
    ref: { url: `${MDN}/RTCPeerConnection/getStats`, label: "MDN · getStats()" },
  },
};

// ── Derived data ────────────────────────────────────────────────────────────

/**
 * Normalize whatever a step declared as an I/O type down to a base name.
 * Overloads may carry refined type objects (`{ base, ... }`) rather than
 * strings; without this the scan buckets them all under "[object Object]".
 * @param {*} t
 * @returns {string|null}
 */
function baseOf(t) {
  if (!t) return null;
  if (typeof t === "string") return t;
  if (typeof t === "object" && typeof t.base === "string") return t.base;
  return null;
}

/**
 * Every (input, output) pair a step can present: its declared signature, both
 * directions of `effectiveIo`, and each overload.
 * @param {*} step
 * @returns {{ input: string|null, output: string|null }[]}
 */
function signaturesOf(step) {
  const out = [{ input: baseOf(step.input), output: baseOf(step.output) }];
  if (typeof step.effectiveIo === "function") {
    for (const params of [{}, { decode: true }]) {
      try {
        const io = step.effectiveIo(params);
        if (io) out.push({ input: baseOf(io.input), output: baseOf(io.output) });
      } catch {
        // effectiveIo may reject param combinations it does not model; the
        // declared signature above already covers the step either way.
      }
    }
  }
  for (const ov of step.overloads || []) {
    out.push({ input: baseOf(ov.input), output: baseOf(ov.output) });
  }
  return out;
}

/** @type {{ producers: Map<string, string[]>, consumers: Map<string, string[]> }|null} */
let usageCache = null;

function typeUsage() {
  if (usageCache) return usageCache;
  /** @type {Map<string, Set<string>>} */
  const producers = new Map();
  /** @type {Map<string, Set<string>>} */
  const consumers = new Map();
  /** Steps declaring `any` — they consume every type, so they are fanned out. */
  const universal = new Set();
  for (const step of listSteps()) {
    for (const sig of signaturesOf(step)) {
      if (sig.output && sig.output !== "any") {
        if (!producers.has(sig.output)) producers.set(sig.output, new Set());
        producers.get(sig.output).add(step.name);
      }
      if (sig.input === "any") universal.add(step.name);
      else if (sig.input && sig.input !== "none") {
        if (!consumers.has(sig.input)) consumers.set(sig.input, new Set());
        consumers.get(sig.input).add(step.name);
      }
    }
  }
  // Every documented type is consumable by the universal passthroughs, which
  // is exactly what makes an observe-only `stats` still displayable.
  for (const base of Object.keys(TYPE_META)) {
    if (base === "none") continue;
    if (!consumers.has(base)) consumers.set(base, new Set());
    for (const name of universal) consumers.get(base).add(name);
  }
  const freeze = (m) =>
    new Map([...m].map(([k, v]) => [k, [...v].sort((a, b) => a.localeCompare(b))]));
  usageCache = { producers: freeze(producers), consumers: freeze(consumers) };
  return usageCache;
}

/**
 * Step names that output this type.
 * @param {string} base
 * @returns {string[]}
 */
export function producersOf(base) {
  return typeUsage().producers.get(String(base)) || [];
}

/**
 * Step names that accept this type as input.
 * @param {string} base
 * @returns {string[]}
 */
export function consumersOf(base) {
  return typeUsage().consumers.get(String(base)) || [];
}

/**
 * @param {string} base
 * @returns {TypeMeta|null}
 */
export function getTypeMeta(base) {
  return TYPE_META[String(base)] || null;
}

/**
 * All types, in a stable reading order: the values you build pipelines out of
 * first, then key material, then collections, then the network types.
 * @returns {TypeMeta[]}
 */
export function listTypes() {
  const order = [
    "bytes", "text", "int", "bool",
    "key", "keypair", "openpgp-key", "recipients",
    "shares", "bundle", "item", "artifact",
    "endpoint", "candidate", "sdp", "certificate",
    "session", "channel", "peer", "host",
    "connstate", "stats", "none",
  ];
  const seen = new Set(order);
  return [...order, ...Object.keys(TYPE_META).filter((k) => !seen.has(k))]
    .map((k) => TYPE_META[k])
    .filter(Boolean);
}

/**
 * Types a user can write down directly.
 * @returns {TypeMeta[]}
 */
export function listConstructibleTypes() {
  return listTypes().filter((t) => t.literal);
}

/**
 * Build the step that constructs a literal of this type.
 *
 * Mirrors `instantiateFormatPick`/`instantiateCipherPick`: a pick resolves to a
 * real registry step with params, so the constructed value flows through the
 * ordinary append/serialize path instead of needing a parallel one.
 *
 * @param {string} base
 * @param {string} raw  what the user typed
 * @returns {{ name: string, params: Record<string, *> }}
 */
export function instantiateTypeLiteral(base, raw) {
  const meta = getTypeMeta(base);
  if (!meta?.literal) throw new Error(`Type "${base}" cannot be written as a literal`);
  const parsed = meta.literal.parse(raw);
  if (!parsed.ok) throw new Error(parsed.error || `Invalid ${base} literal`);
  const step = meta.literal.build(raw);
  if (!getStep(step.name)) throw new Error(`Missing step ${step.name}`);
  return step;
}
