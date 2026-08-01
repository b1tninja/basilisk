/**
 * Refined pipeline types for toolkit recipes.
 *
 * Coarse IoType (bytes/text/keypair/…) is the `base`. Optional refinements
 * (kind, alg, length, …) let validation and step overloads distinguish e.g.
 * bytes/scalar from bytes/pem without inventing ad-hoc special cases.
 */

/** @typedef {import("./registry.js").IoType} IoType */

import { slotLabelKey } from "./recipe-parse.js";
import { BASE_ENCODINGS as BASE_ENCODING_LIST } from "./step-names.js";

/**
 * @typedef {object} RefinedType
 * @property {IoType} base
 * @property {string} [kind]  scalar | master | der | pem | armored | mnemonic | opaque | …
 *   For `candidate` this is the ICE type: host | srflx | prflx | relay.
 * @property {string} [alg]
 * @property {number} [length]  byte length, or element count for list-shaped
 *   values (`candidate`, `peer`)
 * @property {"public"|"private"|"secret"|"offer"|"answer"} [which]
 *   Key half, or — for `sdp` — which side of the offer/answer exchange.
 * @property {string} [encoding]
 * @property {"v4"|"v6"|"name"} [family]  `host` address family
 * @property {"udp"|"tcp"} [protocol]  `endpoint`/`candidate` transport
 */

/**
 * @typedef {object} StepOverload
 * @property {Partial<RefinedType>} [when]  required refinements on the pipeline value
 * @property {Record<string, string|string[]>} [whenParams]  required step params
 * @property {RefinedType | ((current: RefinedType, params: Record<string, *>) => RefinedType)} output
 * @property {string} [hint]  shown when this overload is the intended fix
 */

/**
 * @param {IoType} base
 * @param {Omit<RefinedType, "base">} [ref]
 * @returns {RefinedType}
 */
export function typeOf(base, ref = {}) {
  return { base, ...ref };
}

/** @returns {RefinedType} */
export function tNone() {
  return typeOf("none");
}

/**
 * Network/WebRTC value types (design v2 §25a). Split three ways because the
 * distinction is what the type system is *for*:
 *  - DATA — inert, serializable, safe to copy/publish/pipe onward.
 *  - HANDLE — a live browser object. Meaningful only inside the run that
 *    created it; never publishable, never a crypto op's input.
 *  - OBSERVE — a diagnostic read-out. Displayable, but not an input to
 *    anything (a stats snapshot isn't a value you compute with).
 * @type {ReadonlySet<string>}
 */
export const NETWORK_DATA_TYPES = new Set([
  "host",
  "endpoint",
  "candidate",
  "sdp",
  "certificate",
  "peer",
]);
/** @type {ReadonlySet<string>} */
export const NETWORK_HANDLE_TYPES = new Set(["session", "channel"]);
/** @type {ReadonlySet<string>} */
export const NETWORK_OBSERVE_TYPES = new Set(["connstate", "stats"]);

/** Every network type, whatever its class. @type {ReadonlySet<string>} */
export const NETWORK_TYPES = new Set([
  ...NETWORK_DATA_TYPES,
  ...NETWORK_HANDLE_TYPES,
  ...NETWORK_OBSERVE_TYPES,
]);

/**
 * Types whose `length` refinement counts elements, not bytes. `bundle` and
 * `shares` are collections, so "3B" would be actively misleading — a bundle of
 * three messages is not three bytes.
 */
const LIST_TYPES = new Set(["candidate", "peer", "bundle", "shares"]);

/**
 * Steps that accept any pipeline value — display/plumbing, not computation.
 * @param {string} name
 */
/** Base alphabets `encode`/`decode` accept — one list, owned by step-names.js. */
export const BASE_ENCODINGS = new Set(BASE_ENCODING_LIST);

export const POLYMORPHIC_STEPS = new Set([
  "out",
  "tee",
  "peek",
  "inspect",
  "text",
  "select",
  "in",
  // Sink-with-passthrough like `out`: copies the value, pipes it on unchanged.
  "clipboard.write",
  // Same contract for disk. Anything worth writing out is worth writing to a
  // file, so restricting it to `bytes` would make `file.save` the one sink you
  // cannot put after a keypair or a shares set.
  "file.save",
]);

export function isPassthroughStep(name) {
  return POLYMORPHIC_STEPS.has(name);
}

/**
 * A live handle or an observe-only read-out can be displayed (`out`,
 * `inspect`, `text`) but must never be consumed as a crypto op's input —
 * this is the rule that makes `session`/`connstate` genuinely different from
 * a JSON blob that merely looks different.
 * @param {IoType} base
 */
export function isObserveOnlyType(base) {
  return NETWORK_HANDLE_TYPES.has(base) || NETWORK_OBSERVE_TYPES.has(base);
}

/**
 * Fixed-length private scalar / seed size for direct SSS (when applicable).
 * @param {string} alg
 * @returns {number|null}
 */
export function scalarLengthForAlg(alg) {
  const a = String(alg || "");
  if (a === "ec/p384") return 48;
  if (a === "ec/p521") return 66;
  if (
    a === "ec/p256" ||
    a === "ed25519" ||
    a === "x25519" ||
    a.startsWith("aes/") ||
    a.startsWith("hmac/")
  ) {
    return 32;
  }
  return null;
}

/**
 * @param {RefinedType|null|undefined} t
 * @returns {string}
 */
export function formatType(t) {
  if (!t || t.base === "none") return "none";
  /** @type {string[]} */
  const parts = [t.base];
  if (t.kind) parts.push(t.kind);
  if (t.alg) parts.push(t.alg);
  // `length` is a byte count for payloads but an element count for the
  // list-shaped network types — "candidate/×3" reads better than "3B".
  if (t.length != null) {
    parts.push(LIST_TYPES.has(t.base) ? `×${t.length}` : `${t.length}B`);
  }
  if (t.which) parts.push(t.which);
  if (t.family) parts.push(t.family);
  if (t.protocol) parts.push(t.protocol);
  if (t.encoding && t.encoding !== t.kind) parts.push(t.encoding);
  return parts.join("/");
}

/**
 * Does `actual` satisfy an overload `when` clause?
 * Base must match. Every refinement set on `expected` must be present and equal on `actual`
 * (unknown on actual → no match — forces explicit producers like export scalar / random 32).
 * @param {RefinedType|null|undefined} actual
 * @param {Partial<RefinedType>|null|undefined} expected
 * @returns {boolean}
 */
export function typeSatisfies(actual, expected) {
  if (!expected || !Object.keys(expected).length) {
    return !!(actual && actual.base && actual.base !== "none");
  }
  if (!actual || actual.base === "none") {
    return expected.base === "none";
  }
  if (expected.base != null && actual.base !== expected.base) return false;
  for (const key of /** @type {const} */ ([
    "kind",
    "alg",
    "length",
    "which",
    "encoding",
  ])) {
    if (expected[key] === undefined) continue;
    if (actual[key] !== expected[key]) return false;
  }
  return true;
}

/**
 * @param {Record<string, *>} params
 * @param {Record<string, string|string[]>|undefined} whenParams
 * @returns {boolean}
 */
export function paramsSatisfy(params, whenParams) {
  if (!whenParams) return true;
  for (const [k, want] of Object.entries(whenParams)) {
    const got = params?.[k];
    if (Array.isArray(want)) {
      if (!want.map(String).includes(String(got))) return false;
    } else if (String(got) !== String(want)) {
      return false;
    }
  }
  return true;
}

/**
 * @param {RefinedType} current
 * @param {StepOverload} ov
 * @param {Record<string, *>} params
 * @returns {RefinedType}
 */
function materializeOutput(current, ov, params) {
  if (typeof ov.output === "function") {
    return ov.output(current, params);
  }
  return { ...ov.output };
}

/**
 * Pick the first matching overload, or null.
 * @param {StepOverload[]} overloads
 * @param {RefinedType} current
 * @param {Record<string, *>} params
 * @returns {StepOverload|null}
 */
export function matchOverload(overloads, current, params) {
  for (const ov of overloads || []) {
    if (!typeSatisfies(current, ov.when || {})) continue;
    if (!paramsSatisfy(params, ov.whenParams)) continue;
    return ov;
  }
  return null;
}

/**
 * Infer refined type produced by a source step.
 * @param {string} name
 * @param {Record<string, *>} params
 * @returns {RefinedType}
 */
/**
 * Byte length of a `bytes` literal, or null when the value is malformed or
 * empty — an unrefined `bytes` type is the honest answer there, since the
 * engine is the layer that reports the decode error.
 * @param {string} raw
 * @param {string} encoding  hex | base64 | utf8
 * @returns {number|null}
 */
function literalByteLength(raw, encoding) {
  const src = String(raw || "").trim();
  if (!src) return null;
  if (encoding === "utf8") return new TextEncoder().encode(src).length;
  if (encoding === "base64") {
    const clean = src.replace(/[\s=]/g, "");
    if (!/^[A-Za-z0-9+/\-_]*$/.test(clean)) return null;
    return Math.floor((clean.length * 3) / 4) || null;
  }
  const hex = src.replace(/^0[xX]/, "").replace(/\s+/g, "");
  if (!hex.length || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) return null;
  return hex.length / 2;
}

export function inferSourceType(name, params = {}) {
  switch (name) {
    case "genkey": {
      const alg = String(params.alg || "ec/p256");
      return typeOf("keypair", { alg, which: "private" });
    }
    case "random": {
      const length = Number(params.length) || 32;
      if (length === 16 || length === 32) {
        return typeOf("bytes", { kind: "master", length });
      }
      return typeOf("bytes", { length });
    }
    case "bytes": {
      // Refine with the literal's length the same way `random` does, so a
      // too-short literal fails where it is written rather than deep inside
      // the step that needed 32 bytes. Computed inline rather than through
      // type-registry.js: registry.js already imports this module, so
      // reaching back through it would close an import cycle.
      const length = literalByteLength(
        String(params.value ?? ""),
        String(params.encoding || "hex")
      );
      if (length == null) return typeOf("bytes");
      if (length === 16 || length === 32) return typeOf("bytes", { kind: "master", length });
      return typeOf("bytes", { length });
    }
    case "keypair": {
      // An SPKI PEM only carries the public half, so the tip is a lone `key`
      // — the same distinction `import` already draws for its formats.
      const alg = String(params.alg || "ec/p256");
      return typeOf("keypair", { alg, which: "private" });
    }
    case "passphrase":
      return typeOf("text", { kind: "opaque" });
    case "gpg.genkey":
      return typeOf("openpgp-key", { which: "private" });
    case "agent.unlock":
      return typeOf("openpgp-key", { which: "private" });
    case "agent.pub":
    case "hkp.get":
      return typeOf("openpgp-key", { which: "public" });
    case "agent.list":
      return typeOf("text", { kind: "opaque" });
    case "hkp.search":
      return typeOf("recipients");
    case "hkp.cache": {
      const action = String(params.action || "list").toLowerCase();
      const format = String(params.format || "recipients").toLowerCase();
      if (action === "clear" || format === "json") {
        return typeOf("text", { kind: "opaque" });
      }
      return typeOf("recipients");
    }
    case "input":
      return typeOf("text", { kind: "opaque" });
    case "run.receipt":
      // Canonical JSON, so the tip is plain opaque text — exactly what
      // `gpg.sign` and `out` already consume. No new type is warranted for it.
      return typeOf("text", { kind: "opaque" });
    case "lit": {
      const kind = String(params.kind || "text");
      if (kind === "int") return typeOf("int");
      if (kind === "bool") return typeOf("bool");
      return typeOf("text");
    }
    case "shares": {
      return typeOf("shares", { kind: "mnemonic" });
    }
    case "gpg.decrypt":
      return typeOf("shares", { kind: "mnemonic" });
    case "webauthn.caps":
    case "webauthn.get":
      return typeOf("text", { kind: "opaque" });
    case "webauthn.create":
    case "webauthn.prf":
      return typeOf("bytes", { kind: "opaque" });
    // ── Network / WebRTC (design v2 §21a/23a/23b/29a/29d/30d) ──
    case "rtc.ice":
      // A list of ICE server addresses — host:port pairs, same shape as any
      // other endpoint, which is why `ice=@slot` can type-check against it.
      return typeOf("endpoint", { kind: "ice-servers" });
    case "stun.check":
      // The peer's own server-reflexive address, as discovered.
      return typeOf("endpoint", { kind: "reflexive" });
    case "rtc.gather":
      return typeOf("candidate");
    case "rtc.certificate":
      return typeOf("certificate", { alg: String(params.alg || "ecdsa") });
    case "rtc.offer":
      return typeOf("sdp", { which: "offer" });
    case "quorum.offer":
    case "quorum.join":
      // A LIVE handle — deliberately not text: it must never be consumable by
      // a crypto op, and it means nothing outside the run that opened it.
      return typeOf("session", {
        which: name === "quorum.offer" ? "offer" : "answer",
      });
    case "rtc.recv": {
      // Received messages really are data — text, not a handle. `count` picks
      // the shape (§30c): one message stays text, several become a bundle so
      // `foreach` can walk them. Must agree with the step's `effectiveIo`.
      const count = String(params.count ?? "1").trim().toLowerCase();
      if (count === "1") return typeOf("text", { kind: "opaque" });
      const n = count === "all" ? undefined : Number(count) || undefined;
      return typeOf("bundle", n ? { length: n } : {});
    }
    case "rtc.state":
      return typeOf("connstate");
    case "rtc.restart":
      // Same observe-only shape as rtc.state — a restart is an action whose
      // only pipeline-visible result is the state it leaves behind.
      return typeOf("connstate");
    case "rtc.check":
      return typeOf("stats", { kind: "candidate-pairs" });
    case "rtc.stats":
      return typeOf("stats", { kind: "data-channel" });
    case "rtc.quality":
      return typeOf("stats", { kind: "quality" });
    case "clipboard.read":
      // Whatever the user last copied — text of unknown provenance.
      return typeOf("text", { kind: "opaque" });
    case "dkg.run":
      // The participant's share plus the joint public key, as JSON. `text`
      // rather than a handle: unlike `session`, this outlives the run — it is
      // the thing you keep.
      return typeOf("text", { kind: "opaque" });
    case "file.read": {
      // `auto` is only resolvable once a file is chosen, so the compile-time
      // answer is the conservative one. Claiming `text` for an unopened picker
      // would type-check a recipe that then meets a PNG.
      const as = String(params.as || "auto").toLowerCase();
      if (as === "text") return typeOf("text", { kind: "opaque" });
      return typeOf("bytes", { kind: "opaque" });
    }
    case "age.keygen":
      // The identity is the secret half; `age.recipient` is the projection.
      return typeOf("text", { kind: "opaque" });
    default:
      return tNone();
  }
}

/**
 * @param {Record<string, *>} params
 * @returns {"master"|"passphrase"}
 */
function gpgSymMode(params) {
  const mode = String(params?.mode ?? "").trim().toLowerCase();
  return mode === "passphrase" ? "passphrase" : "master";
}

/**
 * @param {Record<string, *>} params
 * @param {string} op
 * @returns {string|null}
 */
function gpgSymModeTypeError(params, op) {
  const rawMode = String(params?.mode ?? "").trim().toLowerCase();
  const pw = String(params?.passphrase ?? "").trim();
  if (rawMode && rawMode !== "master" && rawMode !== "passphrase") {
    return `${op} mode= must be master or passphrase (got ${rawMode})`;
  }
  const mode = rawMode || "master";
  if (mode === "master" && pw) {
    return `${op}: passphrase= requires mode=passphrase (default mode=master is the SSS envelope path)`;
  }
  if (mode === "passphrase" && !pw) {
    return `${op} mode=passphrase requires passphrase= or passphrase=@slot`;
  }
  return null;
}

/**
 * Infer refined output for transforms that are param-driven (export/import/pem/…).
 * Returns null when the step should use declared overloads / coarse Io instead.
 * @param {string} name
 * @param {RefinedType} current
 * @param {Record<string, *>} params
 * @returns {{ ok: true, output: RefinedType } | { ok: false, error: string } | null}
 */
/**
 * `qr.scan`'s output shape, which its `count` param decides — mirroring
 * `rtc.recv` (§30c). Must agree with the step's `effectiveIo`: the caret
 * consults one and the type walker the other, and disagreement is how an op
 * gets offered after a read that really produced a collection.
 * @param {Record<string, *>} params
 * @returns {RefinedType}
 */
function qrScanOutput(params) {
  const count = String(params?.count ?? "1").trim().toLowerCase();
  return count === "1" ? typeOf("text", { kind: "opaque" }) : typeOf("bundle");
}

export function inferParamDrivenType(name, current, params = {}) {
  if (name === "qr.scan") {
    // Accepts an image from any of its realistic sources: raw bytes off
    // `file.read`, or SVG markup (`text`) — including the markup `qr` itself
    // just produced, which is the first thing anyone tries. Resolved here
    // rather than in the coarse fallback so the `count`-driven bundle shape
    // applies whatever the input was.
    if (
      current.base !== "bytes" &&
      current.base !== "text" &&
      current.base !== "artifact"
    ) {
      return {
        ok: false,
        error: `"qr.scan" expects an image (bytes) or SVG text, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: qrScanOutput(params) };
  }
  if (name === "export") {
    if (current.base !== "keypair" && current.base !== "key") {
      return {
        ok: false,
        error: `"export" expects keypair or key, got ${formatType(current)}`,
      };
    }
    const format = String(params.format || "pkcs8").toLowerCase();
    const alg = current.alg || "ec/p256";
    // Projected `:public` / `:private` / secret tips are `key` — tip which wins over params.
    const tipWhich =
      current.base === "key" &&
      (current.which === "public" ||
        current.which === "private" ||
        current.which === "secret")
        ? current.which
        : null;
    // Projected `key` tip selects the half; `which=` only applies to full keypairs.
    const which = tipWhich || String(params.which || "private");

    if (tipWhich === "public") {
      if (format === "pkcs8" || format === "scalar" || format === "d") {
        return {
          ok: false,
          error: `"export ${format}" needs a private key — tip is ${formatType(current)}`,
        };
      }
    }
    if (tipWhich === "secret") {
      if (format === "spki" || format === "pkcs8" || format === "scalar" || format === "d") {
        return {
          ok: false,
          error: `"export ${format}" is for asymmetric keys — tip is ${formatType(current)}; use export raw or export jwk`,
        };
      }
    }
    if (tipWhich === "private" && format === "spki") {
      return {
        ok: false,
        error: `"export spki" needs a public key — use :public | export spki (tip is ${formatType(current)})`,
      };
    }

    if (format === "jwk") {
      return {
        ok: true,
        output: typeOf("text", {
          kind: "opaque",
          encoding: "jwk",
          which: which === "public" ? "public" : "private",
          alg,
        }),
      };
    }
    if (format === "scalar" || format === "d") {
      const length = scalarLengthForAlg(alg);
      return {
        ok: true,
        output: typeOf("bytes", {
          kind: "scalar",
          alg,
          length: length ?? undefined,
          which: "private",
        }),
      };
    }
    if (format === "spki" || which === "public") {
      return {
        ok: true,
        output: typeOf("bytes", { kind: "der", which: "public", alg }),
      };
    }
    if (format === "raw") {
      return {
        ok: true,
        output: typeOf("bytes", {
          kind: "opaque",
          which: which === "public" ? "public" : "private",
          alg,
        }),
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", { kind: "der", which: "private", alg }),
    };
  }

  if (name === "import") {
    const format = String(params.format || "pkcs8").toLowerCase();
    const alg = String(params.alg || "ec/p256");
    if (format === "jwk") {
      if (current.base !== "text") {
        return {
          ok: false,
          error: `"import jwk" expects text, got ${formatType(current)}`,
        };
      }
      return {
        ok: true,
        output: typeOf("keypair", { alg }),
      };
    }
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"import" expects bytes, got ${formatType(current)}`,
      };
    }
    if (format === "scalar" || format === "d") {
      if (current.kind && current.kind !== "scalar" && current.kind !== "master") {
        return {
          ok: false,
          error:
            `"import scalar" expects bytes/scalar or bytes/master (from recover), got ${formatType(current)}. ` +
            `Use export scalar before sss, or recover shares of a scalar split.`,
        };
      }
      return {
        ok: true,
        output: typeOf("keypair", { alg, which: "private" }),
      };
    }
    if (format === "spki") {
      if (current.which === "private") {
        return {
          ok: false,
          error: `"import spki" expects public DER (e.g. der of PUBLIC KEY), got ${formatType(current)}`,
        };
      }
      // Public-only import — a projected key tip, not a full keypair.
      return {
        ok: true,
        output: typeOf("key", { alg, which: "public" }),
      };
    }
    if (current.which === "public") {
      return {
        ok: false,
        error: `"import ${format}" expects private DER — tip is ${formatType(current)}; use import spki`,
      };
    }
    return {
      ok: true,
      output: typeOf("keypair", { alg, which: "private" }),
    };
  }

  if (name === "pem") {
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"pem" expects bytes, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("text", {
        kind: "pem",
        encoding: "pem",
        which: current.which,
        alg: current.alg,
      }),
    };
  }

  if (name === "der") {
    if (current.base !== "text") {
      return {
        ok: false,
        error: `"der" expects text/pem, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", {
        kind: "der",
        which: current.which,
        alg: current.alg,
      }),
    };
  }

  if (name === "base64" || name === "base32") {
    if (params.decode) {
      if (current.base !== "text") {
        return {
          ok: false,
          error: `"${name} -d" expects text, got ${formatType(current)}`,
        };
      }
      return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
    }
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"${name}" expects bytes, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("text", {
        kind: "opaque",
        encoding: name === "base32" ? "base32" : "base64",
      }),
    };
  }

  if (name === "encode") {
    const enc = String(params.encoding || "hex").toLowerCase();
    if (!BASE_ENCODINGS.has(enc)) {
      return { ok: false, error: `"encode ${enc}" is not a base alphabet` };
    }
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"encode ${enc}" expects bytes, got ${formatType(current)}`,
      };
    }
    // Carry the encoding as a refinement so a later `from` — or an artifact
    // renderer — knows which alphabet the text is in without sniffing it.
    return {
      ok: true,
      output: typeOf("text", { kind: "opaque", encoding: enc }),
    };
  }

  if (name === "decode") {
    const enc = String(params.encoding || "hex").toLowerCase();
    if (!BASE_ENCODINGS.has(enc)) {
      return { ok: false, error: `"decode ${enc}" is not a base alphabet` };
    }
    if (current.base !== "text") {
      return {
        ok: false,
        error: `"decode ${enc}" expects text, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
  }

  if (name === "base64url") {
    if (params.decode) {
      if (current.base !== "text") {
        return {
          ok: false,
          error: `"base64url -d" expects text, got ${formatType(current)}`,
        };
      }
      return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
    }
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"base64url" expects bytes, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("text", { kind: "opaque", encoding: "base64url" }),
    };
  }

  if (name === "as") {
    const t = String(params.type || "opaque").toLowerCase();
    const alg = String(params.alg || current.alg || "ec/p256");

    // Coerce scalars
    if (t === "int") {
      if (
        current.base !== "int" &&
        current.base !== "text" &&
        current.base !== "bytes" &&
        current.base !== "bool"
      ) {
        return {
          ok: false,
          error: `"as int" expects int, text, bytes, or bool, got ${formatType(current)}`,
        };
      }
      return { ok: true, output: typeOf("int") };
    }
    if (t === "bool") {
      if (
        current.base !== "bool" &&
        current.base !== "int" &&
        current.base !== "text" &&
        current.base !== "bytes"
      ) {
        return {
          ok: false,
          error: `"as bool" expects bool, int, text, or bytes, got ${formatType(current)}`,
        };
      }
      return { ok: true, output: typeOf("bool") };
    }

    // Materialize → CryptoKey tips
    if (t === "key" || t === "keypair") {
      const fromPem = current.base === "text";
      const fromDer = current.base === "bytes";
      if (!fromPem && !fromDer) {
        return {
          ok: false,
          error: `"as ${t}" expects bytes/der or text/pem, got ${formatType(current)}`,
        };
      }
      const which = current.which;
      if (t === "keypair") {
        if (which === "public") {
          return {
            ok: false,
            error: `"as keypair" needs private material — tip is ${formatType(current)}; use as key`,
          };
        }
        return {
          ok: true,
          output: typeOf("keypair", { alg, which: "private" }),
        };
      }
      // as key
      if (which !== "public" && which !== "private") {
        return {
          ok: false,
          error: `"as key" needs which (as public / as private, or PEM label) — tip is ${formatType(current)}`,
        };
      }
      return {
        ok: true,
        output: typeOf("key", { alg, which }),
      };
    }

    // Retag which on der/pem
    if (t === "public" || t === "private") {
      if (current.base === "text") {
        const kind = current.kind || current.encoding || "";
        if (kind && kind !== "pem" && kind !== "opaque") {
          return {
            ok: false,
            error: `"as ${t}" expects text/pem, got ${formatType(current)}`,
          };
        }
        if (current.which && current.which !== t) {
          return {
            ok: false,
            error: `"as ${t}" conflicts with tip which=${current.which}`,
          };
        }
        return {
          ok: true,
          output: typeOf("text", {
            kind: current.kind || "pem",
            encoding: current.encoding || "pem",
            which: t,
            alg: current.alg,
          }),
        };
      }
      if (current.base === "bytes") {
        if (current.which && current.which !== t) {
          return {
            ok: false,
            error: `"as ${t}" conflicts with tip which=${current.which}`,
          };
        }
        return {
          ok: true,
          output: typeOf("bytes", {
            kind: current.kind || "der",
            which: t,
            alg: current.alg,
            length: current.length,
          }),
        };
      }
      return {
        ok: false,
        error: `"as ${t}" expects bytes/der or text/pem, got ${formatType(current)}`,
      };
    }

    // Byte kind retags
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"as" expects bytes, got ${formatType(current)}`,
      };
    }
    if (t === "master") {
      const len = current.length;
      if (len != null && len !== 16 && len !== 32) {
        return {
          ok: false,
          error: `"as master" requires 16 or 32 bytes, got ${len}B`,
        };
      }
      return {
        ok: true,
        output: typeOf("bytes", {
          kind: "master",
          length: len,
          alg: current.alg,
        }),
      };
    }
    if (t === "scalar") {
      return {
        ok: true,
        output: typeOf("bytes", {
          kind: "scalar",
          length: current.length,
          alg: current.alg,
        }),
      };
    }
    if (t === "opaque") {
      return {
        ok: true,
        output: typeOf("bytes", {
          kind: "opaque",
          length: current.length,
          alg: current.alg,
        }),
      };
    }
    return {
      ok: false,
      error: `"as" type must be master, scalar, opaque, public, private, key, keypair, int, or bool — got "${t}"`,
    };
  }

  // ── JOSE (RFC 7515 / 7516 / 7519) ──
  //
  // Modeled as refined `text`, not as new base types. A compact JWS *is* a
  // string on the wire, and every op that already accepts text — `out`,
  // `clipboard.write`, `digest`, `encode` — should keep accepting one. A new
  // base would have bought a stricter arrow at the cost of making every
  // existing text consumer refuse a token, and `resolveStepType` would then
  // need a route for it everywhere. The `kind` refinement carries the
  // distinction that matters (`text/jws` vs `text/jwe`), which is exactly
  // what refinements are for — the same call `text/pem` already makes.
  if (name === "jose.sign" || name === "jose.encrypt") {
    if (current.base !== "text" && current.base !== "bytes") {
      return {
        ok: false,
        error: `"${name}" expects the payload as text or bytes, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("text", {
        kind: name === "jose.sign" ? "jws" : "jwe",
        encoding: "jose",
      }),
    };
  }

  if (name === "jose.decode" || name === "jose.verify" || name === "jose.decrypt") {
    if (current.base !== "text") {
      return {
        ok: false,
        error: `"${name}" expects a compact JOSE token as text, got ${formatType(current)}`,
      };
    }
    if (name === "jose.verify" && current.kind === "jwe") {
      return {
        ok: false,
        error: `"jose.verify" expects text/jws — a JWE is encrypted, not signed; use "jose.decrypt"`,
      };
    }
    if (name === "jose.decrypt" && current.kind === "jws") {
      return {
        ok: false,
        error: `"jose.decrypt" expects text/jwe — a JWS is signed, not encrypted; use "jose.verify"`,
      };
    }
    // `jose.decode` always reports JSON; the other two emit whatever the
    // token carried, which is JSON for a JWT and opaque otherwise. `json` is
    // the honest common answer — nothing downstream branches on it, and
    // claiming `opaque` would understate what a JWT payload is.
    return { ok: true, output: typeOf("text", { kind: "json" }) };
  }

  if (name === "utf8") {
    if (current.base === "bytes") {
      return { ok: true, output: typeOf("text", { kind: current.kind || "opaque" }) };
    }
    if (current.base === "text") {
      return { ok: true, output: typeOf("bytes", { kind: current.kind || "opaque" }) };
    }
    return {
      ok: false,
      error: `"utf8" expects bytes or text, got ${formatType(current)}`,
    };
  }

  if (name === "sss.combine") {
    if (current.base !== "shares") {
      return {
        ok: false,
        error: `"sss.combine" expects shares, got ${formatType(current)}`,
      };
    }
    if (current.kind === "mnemonic") {
      return {
        ok: false,
        error:
          `"sss.combine" expects shares/raw — decode mnemonics first with "blip39.decode"`,
      };
    }
    // Recovered secret is always 16/32-byte master-sized material (scalar or random).
    return {
      ok: true,
      output: typeOf("bytes", { kind: "master" }),
    };
  }

  if (name === "blip39") {
    if (current.base !== "shares") {
      return {
        ok: false,
        error: `"blip39" expects shares, got ${formatType(current)}`,
      };
    }
    const decode = !!params.decode;
    if (decode) {
      if (current.kind === "raw") {
        return {
          ok: false,
          error: `"blip39.decode" expects shares/mnemonic, got shares/raw`,
        };
      }
      return { ok: true, output: typeOf("shares", { kind: "raw" }) };
    }
    if (current.kind === "mnemonic") {
      return {
        ok: false,
        error: `"blip39" encode expects shares/raw, got shares/mnemonic (use -d to decode)`,
      };
    }
    return { ok: true, output: typeOf("shares", { kind: "mnemonic" }) };
  }

  if (name === "hkp.filter" || name === "recipients.merge") {
    if (current.base !== "recipients" && current.base !== "text") {
      return {
        ok: false,
        error: `"${name}" expects recipients, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: typeOf("recipients") };
  }

  if (name === "agent.save") {
    // §28 gave `agent.save` the multi-kind path — a WebCrypto keypair saves as
    // vault kind ssh/raw (see execAgentSave, agent-multikind.test.js) and the
    // registry declares the `keypair → keypair` overload. This table was never
    // told, so the op's own documented example (`genkey ed25519 | agent.save`)
    // failed validation while running fine.
    if (current.base === "keypair") {
      return { ok: true, output: typeOf("keypair", { alg: current.alg }) };
    }
    if (
      current.base !== "openpgp-key" &&
      current.base !== "text"
    ) {
      return {
        ok: false,
        error: `"agent.save" expects openpgp-key/private or a keypair, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: typeOf("openpgp-key", { which: "private" }) };
  }

  if (name === "gpg.symencrypt") {
    if (current.base !== "text" && current.base !== "bytes") {
      return {
        ok: false,
        error: `"gpg.symencrypt" expects text or bytes, got ${formatType(current)}`,
      };
    }
    if (current.kind === "master" || current.kind === "scalar") {
      return {
        ok: false,
        error:
          `"gpg.symencrypt" is for PEM/arbitrary payloads — got ${formatType(current)}. ` +
          `Pipe that to sss directly (already 16/32 bytes).`,
      };
    }
    const modeErr = gpgSymModeTypeError(params, "gpg.symencrypt");
    if (modeErr) return { ok: false, error: modeErr };
    if (gpgSymMode(params) === "passphrase") {
      return {
        ok: true,
        output: typeOf("text", { kind: "armored", encoding: "openpgp" }),
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", { kind: "master", length: 32 }),
    };
  }

  if (name === "gpg.symdecrypt") {
    const modeErr = gpgSymModeTypeError(params, "gpg.symdecrypt");
    if (modeErr) return { ok: false, error: modeErr };
    if (gpgSymMode(params) === "passphrase") {
      if (current.base !== "text" && current.base !== "bytes") {
        return {
          ok: false,
          error: `"gpg.symdecrypt mode=passphrase" expects armored text/bytes, got ${formatType(current)}`,
        };
      }
      return {
        ok: true,
        output: typeOf("bytes", { kind: "opaque" }),
      };
    }
    if (current.base !== "bytes" || current.kind !== "master") {
      return {
        ok: false,
        error:
          `"gpg.symdecrypt" expects bytes/master from sss.combine, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", { kind: "opaque" }),
    };
  }

  if (name === "in") {
    // Concrete type is resolved in validateRecipe / engine from the slot registry.
    // walkPipelineTypes has no slot map — opaque is an honest "unknown until validate".
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
  }

  if (name === "lit") {
    const kind = String(params.kind || "text");
    if (kind === "int") return { ok: true, output: typeOf("int") };
    if (kind === "bool") return { ok: true, output: typeOf("bool") };
    return { ok: true, output: typeOf("text") };
  }

  if (
    name === "tee" ||
    name === "peek" ||
    name === "out" ||
    name === "clipboard.write" ||
    name === "file.save"
  ) {
    if (!current || current.base === "none") {
      return {
        ok: false,
        error: `"${name}" needs a pipeline value`,
      };
    }
    return { ok: true, output: { ...current } };
  }

  if (name === "select") {
    if (!current || current.base === "none") {
      return { ok: false, error: `"select" needs a pipeline value` };
    }
    const sel = String(params.selector || "");
    const m = sel.replace(/^[.:]/, "").toLowerCase();
    if (
      m === "private" ||
      m === "public"
    ) {
      if (current.base !== "keypair") {
        return {
          ok: false,
          error: `selector ":${m}" requires keypair, got ${formatType(current)}`,
        };
      }
      const which = m === "public" ? "public" : "private";
      // Project to a real `key` tip (half), not keypair+which folklore.
      return {
        ok: true,
        output: typeOf("key", { alg: current.alg, which }),
      };
    }
    if (m === "key") {
      if (current.base !== "item") {
        return {
          ok: false,
          error: `selector ":key" requires item, got ${formatType(current)}`,
        };
      }
      return { ok: true, output: typeOf("text", { kind: "opaque" }) };
    }
    if (m === "value") {
      if (current.base !== "item") {
        return {
          ok: false,
          error: `selector ":value" requires item, got ${formatType(current)}`,
        };
      }
      if (current.kind === "raw") {
        return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
      }
      return { ok: true, output: typeOf("text", { kind: "mnemonic" }) };
    }
    return {
      ok: false,
      error: `Unknown or unsupported stem selector "${sel}"`,
    };
  }

  if (name === "at") {
    if (current.base !== "shares") {
      return {
        ok: false,
        error: `"at" expects shares, got ${formatType(current)}`,
      };
    }
    const sel = String(params.selector || "1").trim();
    const range = sel.match(/^(\d+):(\d+)$/);
    const single = sel.match(/^(\d+)$/);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      if (a < 1 || b < a) {
        return { ok: false, error: `"at" slice must be 1-based with start ≤ end` };
      }
      return { ok: true, output: { ...current } };
    }
    if (single) {
      const n = Number(single[1]);
      if (n < 1) {
        return { ok: false, error: `"at" index must be ≥ 1` };
      }
      // One share: mnemonic text or raw bytes
      if (current.kind === "raw") {
        return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
      }
      return { ok: true, output: typeOf("text", { kind: "mnemonic" }) };
    }
    return {
      ok: false,
      error: `"at" selector must be N or N:M (got "${sel}")`,
    };
  }

  if (name === "text") {
    if (!current || current.base === "none") {
      return { ok: false, error: `"text" needs a pipeline value` };
    }
    if (current.base === "bytes") {
      return {
        ok: true,
        output: typeOf("text", { kind: current.kind || "opaque" }),
      };
    }
    return { ok: true, output: { ...current } };
  }

  if (name === "inspect") {
    if (!current || current.base === "none") {
      return { ok: false, error: `"inspect" needs a pipeline value` };
    }
    return { ok: true, output: typeOf("text", { kind: "opaque" }) };
  }

  if (name === "digest") {
    if (current.base !== "bytes" && current.base !== "text") {
      return {
        ok: false,
        error: `"digest" expects bytes or text, got ${formatType(current)}`,
      };
    }
    const alg = String(params.alg || "sha-256").toLowerCase();
    const length =
      alg === "sha-512"
        ? 64
        : alg === "sha-384"
          ? 48
          : alg === "sha-1"
            ? 20
            : 32;
    return { ok: true, output: typeOf("bytes", { kind: "opaque", length }) };
  }

  if (
    name === "sign" ||
    name === "aes-gcm" ||
    name === "aes-cbc" ||
    name === "aes-ctr" ||
    name === "rsa-oaep" ||
    name === "rsa-pkcs1"
  ) {
    if (current.base !== "bytes" && current.base !== "text") {
      return {
        ok: false,
        error: `"${name}" expects bytes or text, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
  }

  if (name === "hkdf" || name === "pbkdf2") {
    if (current.base !== "bytes" && current.base !== "text") {
      return {
        ok: false,
        error: `"${name}" expects bytes or text, got ${formatType(current)}`,
      };
    }
    const as = String(params.as || "bytes");
    if (as !== "bytes") {
      return {
        ok: true,
        output: typeOf("key", { alg: as, which: "secret" }),
      };
    }
    const length = Number(params.length) || 32;
    return {
      ok: true,
      output: typeOf("bytes", { kind: "opaque", length }),
    };
  }

  if (name === "verify") {
    if (current.base !== "bytes" && current.base !== "text") {
      return {
        ok: false,
        error: `"verify" expects bytes or text, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: typeOf("bool") };
  }

  if (name === "ecdh") {
    const as = String(params.as || "bytes");
    if (as !== "bytes") {
      return {
        ok: true,
        output: typeOf("key", { alg: as, which: "secret" }),
      };
    }
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
  }

  if (name === "wrap") {
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
  }

  if (name === "unwrap") {
    if (current.base !== "bytes" && current.base !== "text") {
      return {
        ok: false,
        error: `"unwrap" expects bytes, got ${formatType(current)}`,
      };
    }
    const alg = String(params.alg || "aes/256");
    return {
      ok: true,
      output: typeOf("key", { alg, which: "secret" }),
    };
  }

  return null;
}

/**
 * Resolve the refined output type of a step given the current pipeline type.
 * @param {{ name: string, overloads?: StepOverload[], input?: IoType, output?: IoType, kind?: string }} spec
 * @param {RefinedType} current
 * @param {Record<string, *>} [params]
 * @returns {{ ok: true, output: RefinedType, overload?: StepOverload } | { ok: false, error: string }}
 */
export function resolveStepType(spec, current, params = {}) {
  const name = spec.name;

  if (spec.kind === "source") {
    return { ok: true, output: inferSourceType(name, params) };
  }

  // Live handles (`session`/`channel`) and observe-only read-outs
  // (`connstate`/`stats`) may be displayed but never consumed. `out`, `tee`,
  // `peek`, `inspect`, `text`, `select`, and `in` are the universal
  // passthroughs that legitimately accept anything.
  // `quorum.close` is a control op that tears down the ambient exchange and
  // passes its input straight through, so it legitimately sees a session.
  if (
    current &&
    isObserveOnlyType(current.base) &&
    !isPassthroughStep(name) &&
    name !== "quorum.close"
  ) {
    return {
      ok: false,
      error: `"${name}" cannot consume ${formatType(current)} — ${
        NETWORK_HANDLE_TYPES.has(current.base)
          ? "a live handle is only valid inside the run that opened it"
          : "this is an observe-only diagnostic"
      }. Use out / inspect / text to display it.`,
    };
  }

  const driven = inferParamDrivenType(name, current, params);
  if (driven) return driven;

  if (spec.overloads?.length) {
    const ov = matchOverload(spec.overloads, current, params);
    if (!ov) {
      const accepted = spec.overloads
        .map((o) => formatType(/** @type {RefinedType} */ (o.when || { base: spec.input })))
        .filter(Boolean);
      const uniq = [...new Set(accepted)];
      let error = `"${name}" does not accept ${formatType(current)}`;
      if (uniq.length) error += ` (accepted: ${uniq.join(" | ")})`;
      if (name === "sss.split") {
        error +=
          '. For EC keys use "export scalar"; for PEM/arbitrary data use "gpg.symencrypt" first.';
      }
      return { ok: false, error };
    }
    return {
      ok: true,
      output: materializeOutput(current, ov, params),
      overload: ov,
    };
  }

  // Coarse fallback: base IoType only
  const want = spec.input || "none";
  if (want !== "none" && current.base !== want) {
    if (name === "gpg.encrypt" && (current.base === "text" || current.base === "bytes")) {
      return { ok: true, output: typeOf("artifact") };
    }
    if (name === "qr" && current.base === "text") {
      return { ok: true, output: typeOf("artifact") };
    }
    return {
      ok: false,
      error:
        current.base === "bundle"
          ? `Type mismatch: "${name}" expects ${want}, got bundle (foreach tip — use @slots from the body, not the bundle tip).`
          : `Type mismatch: "${name}" expects ${want}, got ${formatType(current)}.`,
    };
  }
  // `rtc.answer` consumes an offer and produces the other half of the
  // exchange — keep the two distinguishable rather than both being bare `sdp`.
  if (name === "rtc.answer") {
    return { ok: true, output: typeOf("sdp", { which: "answer" }) };
  }
  return {
    ok: true,
    output: typeOf(/** @type {IoType} */ (spec.output || "none")),
  };
}

/**
 * Whether a step can accept the current refined type (for builder suggestions).
 * @param {{ name: string, overloads?: StepOverload[], input?: IoType, kind?: string, params?: * }} spec
 * @param {RefinedType|IoType|null|undefined} from
 * @returns {boolean}
 */
export function stepAcceptsRefined(spec, from) {
  const current =
    typeof from === "string" || !from
      ? typeOf(/** @type {IoType} */ (from || "none"))
      : from;

  if (!current || current.base === "none") {
    return spec.kind === "source" || spec.input === "none";
  }

  if (POLYMORPHIC_STEPS.has(spec.name)) return true;
  if (spec.name === "foreach") return current.base === "shares" || current.base === "bundle";
  if (spec.name === "export") {
    return current.base === "keypair" || current.base === "key";
  }
  if (spec.name === "sss.combine") {
    return current.base === "shares" && current.kind !== "mnemonic";
  }
  if (spec.name === "blip39") {
    return current.base === "shares";
  }
  if (spec.name === "hkp.filter" || spec.name === "recipients.merge") {
    return current.base === "recipients";
  }
  if (spec.name === "agent.save") {
    return (
      (current.base === "openpgp-key" && current.which === "private") ||
      current.base === "keypair" ||
      (current.base === "text" && !!current)
    );
  }
  if (
    spec.name === "digest" ||
    spec.name === "sign" ||
    spec.name === "verify" ||
    spec.name === "aes-gcm" ||
    spec.name === "aes-cbc" ||
    spec.name === "aes-ctr" ||
    spec.name === "rsa-oaep" ||
    spec.name === "rsa-pkcs1" ||
    spec.name === "hkdf" ||
    spec.name === "pbkdf2" ||
    spec.name === "unwrap"
  ) {
    if (current.base === "bytes") return true;
    // PEM / JWK tips want decode (or import) first — not crypto-as-payload.
    if (current.base === "text") {
      const kind = String(current.kind || current.encoding || "");
      if (kind === "pem" || kind === "jwk") return false;
      return true;
    }
    return false;
  }
  if (spec.name === "ecdh" || spec.name === "wrap") {
    return (
      !current ||
      current.base === "none" ||
      current.base === "keypair" ||
      current.base === "key"
    );
  }

  // Recipients / OpenPGP keys are side inputs for encrypt — not stem payload.
  if (
    (current.base === "recipients" || current.base === "openpgp-key") &&
    spec.name === "gpg.encrypt"
  ) {
    return false;
  }

  if (spec.overloads?.length) {
    return !!matchOverload(spec.overloads, current, {});
  }

  const driven = inferParamDrivenType(spec.name, current, {});
  if (driven?.ok) return true;
  // Encode direction failed — try decode twin before giving up (base64/…).
  // Note: pem↔der and to↔from are conjugate pairs, not decodeTwin.
  if (
    driven &&
    !driven.ok &&
    (spec.decodeTwin || spec.params?.some((p) => p.flag === "-d"))
  ) {
    const decoded = inferParamDrivenType(spec.name, current, { decode: true });
    if (decoded?.ok) return true;
  }
  // `import` defaults to pkcs8 — try tip-driven format when DER half is known.
  if (spec.name === "import" && current.base === "bytes") {
    /** @type {string[]} */
    const formats =
      current.which === "public"
        ? ["spki"]
        : current.which === "private"
          ? ["pkcs8", "scalar"]
          : current.kind === "der"
            ? ["spki", "pkcs8"]
            : [];
    for (const format of formats) {
      const alt = inferParamDrivenType("import", current, { format });
      if (alt?.ok) return true;
    }
  }
  // `as` defaults to opaque — try retag / materialize targets for the tip.
  if (spec.name === "as") {
    for (const type of [
      "key",
      "keypair",
      "public",
      "private",
      "master",
      "scalar",
      "opaque",
      "int",
      "bool",
    ]) {
      const alt = inferParamDrivenType("as", current, { type });
      if (alt?.ok) return true;
    }
  }

  const want = spec.input;
  if (!want || want === "none") return false;
  if (current.base === want) return true;
  if (spec.name === "gpg.encrypt" && (current.base === "text" || current.base === "bytes")) {
    return true;
  }
  if (spec.name === "utf8" && (current.base === "text" || current.base === "bytes")) {
    return true;
  }
  // Decode variants suggested when holding opaque text
  if (current.base === "text" && spec.params?.some((p) => p.flag === "-d")) {
    return true;
  }
  return false;
}

/**
 * Every role an artifact may carry (§32c, design_handoff_artifact_actions).
 *
 * One frozen list because there were two vocabularies: `engine.js` hand-wrote
 * `public-key`, `envelope`, `qr` and `inspect` at its emit sites, while
 * `artifactMetaFromType` below emitted `recipients` and `secret` — and neither
 * side could produce the other's. A registry that matches on `role` cannot be
 * built on two disagreeing lists, so this is the reconciliation, and
 * `artifact-roles.test.js` greps the engine to keep it honest.
 */
export const ARTIFACT_ROLES = Object.freeze([
  "text", // anything with no better description
  "secret", // sensitive bytes with no richer identity (scalars, masters)
  "key", // keypair / key / openpgp-key, public or private
  "public-key", // an armored OpenPGP *public* key — the publishable one
  "share", // one share of a split
  "recipients", // a recipient list
  "ciphertext", // an encrypted message
  "envelope", // the recovery envelope of a ceremony (not a share)
  "sshsig", // an sshsig signature block
  /**
   * The two halves of an SSH key, as they exist *on the wire* — a one-line
   * `type base64 comment` public line, and an openssh-key-v1 private block.
   *
   * Two words rather than one for the same reason `public-key` is not
   * `key`: what may be done with an artifact is a property of which half it
   * is. One is written into `authorized_keys` and pasted into GitHub; the
   * other is the secret that must never leave masked, downloads under a
   * different name, and is the one artifact where "publish" must not exist
   * even as a disabled button (§33d).
   *
   * They are not served by `text`/`secret` plus a tag, which was tried
   * first: `role` is stamped from *sensitivity* at both text emit sites, so
   * the same private block came out `secret` through `out @priv` and `text`
   * through a dangling tip, and `ArtifactMatch.role` is exact. A kind
   * matching one spelling silently disowned the other — a masked private key
   * rendering as untyped text, which is the tile §35d already fixed once.
   * `sshsig` and `token` hit precisely this and were fixed precisely this
   * way (engine.js's `TYPE_OWNED_ROLES`); this follows them.
   */
  "ssh-public", // an SSH public line — `ssh-ed25519 AAAA… comment`
  "ssh-private", // an openssh-key-v1 private block
  "token", // JOSE: jws / jwe
  "netvalue", // candidate / sdp / stats / connstate / endpoint / certificate / session
  "diagnostic", // stun.check and friends — a read-out with a verdict
  "inspect", // an explicit `inspect` snapshot
  "receipt", // a run receipt
  "qr", // an SVG QR rendering of another artifact
]);

/**
 * Network value bases that share the `netvalue` role. The base rides along as
 * a tag, so a kind can match all of them or exactly one.
 */
const NETWORK_BASES = Object.freeze([
  "candidate",
  "sdp",
  "stats",
  "connstate",
  "endpoint",
  "certificate",
  "session",
]);

/**
 * Project a refined type into artifact role/tags for UI (single source of truth).
 * @param {RefinedType} t
 * @returns {{ role: string, tags: string[] }}
 */
export function artifactMetaFromType(t) {
  if (!t) return { role: "text", tags: [] };
  // Refined text kinds that have a dedicated role. Without these they fall
  // through to `text`, which is what forced the UI to grow parallel
  // discriminators (`jose`, `netType`) for a discriminator it already had.
  if (t.kind === "sshsig") return { role: "sshsig", tags: ["ssh", "signature"] };
  // The tags are the ones `ssh.encode` already produced through the fallback
  // branch below, and `ssh-format.test.js` pins that the two halves share
  // **none** — a single tag on both is the whole failure mode (7d563cd), so
  // no common "ssh" tag is added here however tempting the symmetry with
  // sshsig above is. What changes is the role: it is the type's to give, not
  // the emit site's to guess from sensitivity.
  if (t.kind === "ssh-public") return { role: "ssh-public", tags: ["ssh-public"] };
  if (t.kind === "ssh-private") return { role: "ssh-private", tags: ["ssh-private"] };
  if (t.kind === "jws") return { role: "token", tags: ["jose", "jws"] };
  if (t.kind === "jwe") return { role: "token", tags: ["jose", "jwe"] };
  if (NETWORK_BASES.includes(t.base)) {
    return { role: "netvalue", tags: ["network", t.base] };
  }
  if (t.base === "shares" && t.kind === "raw") {
    return { role: "share", tags: ["sss", "raw"] };
  }
  if (t.base === "shares" || t.kind === "mnemonic") {
    return { role: "share", tags: ["mnemonic", "blip39"] };
  }
  if (t.kind === "scalar") {
    return { role: "secret", tags: ["private", "scalar"] };
  }
  if (t.kind === "master") {
    return { role: "secret", tags: ["master"] };
  }
  if (t.kind === "pem" || t.kind === "der") {
    return {
      role: "key",
      tags: [t.which === "public" ? "public" : "private", t.kind],
    };
  }
  if (t.base === "keypair") {
    return { role: "key", tags: ["keypair"] };
  }
  if (t.base === "key") {
    return {
      role: "key",
      tags: [
        t.which === "public"
          ? "public"
          : t.which === "secret"
            ? "secret"
            : "private",
      ],
    };
  }
  if (t.base === "recipients") {
    return { role: "recipients", tags: ["openpgp", "directory"] };
  }
  if (t.base === "openpgp-key") {
    return {
      role: "key",
      tags: ["openpgp", t.which === "public" ? "public" : "private"],
    };
  }
  return { role: "text", tags: t.kind ? [t.kind] : [] };
}

/**
 * Whether Encrypt should open an artifact as a compose message vs a file.
 *
 * Recipe sinks decide this explicitly (memory-safety.js rule 4 — do not regress):
 *   - `text` / `print` → disposition "message" (compose; string unavoidable)
 *   - `out @label` → disposition "file" (attachment; keep wipeable `artifact.bytes`)
 *
 * Do NOT reintroduce content sniffing (hex / base64 / armor → “message”). That
 * encouraged treating secrets as display strings, which cannot be zeroed in JS.
 *
 * @param {{
 *   disposition?: string,
 *   role?: string,
 *   shareIndex?: number,
 *   mime?: string,
 * }} a
 * @returns {boolean}
 */
export function artifactIsTextualForEncrypt(a) {
  if (!a) return false;
  if (a.disposition === "message") return true;
  if (a.disposition === "file") return false;
  // Bare terminal tiles without an explicit sink: message only for plain text role.
  if (a.role === "share" || a.shareIndex) return false;
  if (a.role === "qr" || a.mime === "image/svg+xml") return false;
  if (a.role === "envelope" || a.role === "ciphertext") return false;
  return a.role === "text";
}

/**
 * Walk recipe steps and compute refined input→output types per step.
 * Tracks `out @label` within the walk so later `in` / bare `@label` resolve
 * to the registered tip (ghost chips); unbound `in` stays opaque.
 *
 * @param {{ name: string, params?: Record<string, *>, body?: *, branches?: *, foreachSelector?: string }[]} steps
 * @param {{ getStep: (name: string) => { name: string, kind?: string, overloads?: StepOverload[], input?: IoType, output?: IoType } | null }} deps
 * @param {Map<string, RefinedType>} [slotTypes]  mutable map shared across chains/bodies
 * @returns {{
 *   edges: { index: number, name: string, input: RefinedType, output: RefinedType|null, ok: boolean, error?: string }[],
 *   final: RefinedType,
 * }}
 */
export function walkPipelineTypes(steps, deps, slotTypes = new Map()) {
  /** @type {RefinedType} */
  let current = tNone();
  /** @type {{ index: number, name: string, input: RefinedType, output: RefinedType|null, ok: boolean, error?: string, body?: { index: number, name: string, input: RefinedType, output: RefinedType|null, ok: boolean, error?: string }[] }[]} */
  const edges = [];

  for (let i = 0; i < (steps || []).length; i++) {
    const step = steps[i];
    const input = { ...current };
    const spec = deps.getStep(step.name);
    if (!spec) {
      edges.push({
        index: i,
        name: step.name,
        input,
        output: null,
        ok: false,
        error: `Unknown step "${step.name}"`,
      });
      continue;
    }
    if (step.name === "in") {
      const ref = String(step.params?.ref || "");
      const key = slotLabelKey(ref);
      /** @type {RefinedType} */
      const loaded =
        key && slotTypes.has(key)
          ? { ...slotTypes.get(key) }
          : typeOf("bytes", { kind: "opaque" });
      current = loaded;
      edges.push({
        index: i,
        name: step.name,
        input,
        output: { ...current },
        ok: true,
      });
      continue;
    }
    if (step.name === "foreach") {
      const mode = String(step.foreachSelector || ":values").replace(/^[.:]/, "");
      /** @type {RefinedType} */
      let itemType;
      if (mode === "items") {
        itemType = typeOf("item", { kind: input.kind || "mnemonic" });
      } else if (mode === "keys") {
        itemType = typeOf("text", { kind: "opaque" });
      } else {
        itemType =
          input.kind === "raw"
            ? typeOf("bytes", { kind: "opaque" })
            : typeOf("text", { kind: "mnemonic" });
      }
      const bodyEdges = step.body?.length
        ? walkBodyTypes(step.body, itemType, deps, slotTypes)
        : [];
      current = typeOf("bundle");
      edges.push({
        index: i,
        name: step.name,
        input,
        output: { ...current },
        ok: input.base === "shares" && !!step.body?.length,
        error:
          input.base !== "shares"
            ? `"foreach" expects shares, got ${formatType(input)}`
            : step.body?.length
              ? undefined
              : "foreach requires a body",
        body: bodyEdges,
      });
      continue;
    }
    if (
      step.name === "tee" &&
      (step.body?.length || step.branches?.length)
    ) {
      const bodyEdges = step.body?.length
        ? walkBodyTypes(step.body, current, deps, slotTypes)
        : [];
      /** @type {{ member: string, edges: ReturnType<typeof walkBodyTypes> }[]} */
      const branchEdges = [];
      for (const br of step.branches || []) {
        const m = String(br.member || br.selector || "")
          .replace(/^[.:]/, "")
          .toLowerCase();
        const which =
          m === "private" || m === "priv" || m === "secret"
            ? "private"
            : m === "public" || m === "pub"
              ? "public"
              : null;
        const projected =
          current.base === "keypair" && which
            ? typeOf("key", { alg: current.alg, which })
            : current;
        branchEdges.push({
          member: which || m,
          edges: walkBodyTypes(br.body || [], projected, deps, slotTypes),
        });
      }
      edges.push({
        index: i,
        name: step.name,
        input,
        output: { ...current },
        ok: current.base !== "none",
        error:
          current.base !== "none" ? undefined : `"tee" needs a pipeline value`,
        body: bodyEdges,
        branches: branchEdges,
      });
      continue;
    }
    const resolved = resolveStepType(spec, current, step.params || {});
    if (!resolved.ok) {
      edges.push({
        index: i,
        name: step.name,
        input,
        output: null,
        ok: false,
        error: resolved.error,
      });
      break;
    }
    current = resolved.output;
    if (step.name === "out") {
      const key = slotLabelKey(String(step.params?.name || "@output"));
      if (key) slotTypes.set(key, { ...current });
    }
    edges.push({
      index: i,
      name: step.name,
      input,
      output: { ...current },
      ok: true,
    });
  }

  return { edges, final: current };
}

/**
 * @param {{ name: string, params?: Record<string, *> }[]} body
 * @param {RefinedType} start
 * @param {{ getStep: (name: string) => { name: string, kind?: string, overloads?: StepOverload[], input?: IoType, output?: IoType } | null }} deps
 * @param {Map<string, RefinedType>} [slotTypes]
 */
function walkBodyTypes(body, start, deps, slotTypes = new Map()) {
  /** @type {RefinedType} */
  let current = start;
  /** @type {{ index: number, name: string, input: RefinedType, output: RefinedType|null, ok: boolean, error?: string }[]} */
  const edges = [];
  for (let i = 0; i < (body || []).length; i++) {
    const step = body[i];
    const input = { ...current };
    const spec = deps.getStep(step.name);
    if (!spec) {
      edges.push({
        index: i,
        name: step.name,
        input,
        output: null,
        ok: false,
        error: `Unknown step "${step.name}"`,
      });
      continue;
    }
    if (step.name === "in") {
      const ref = String(step.params?.ref || "");
      const key = slotLabelKey(ref);
      current =
        key && slotTypes.has(key)
          ? { ...slotTypes.get(key) }
          : typeOf("bytes", { kind: "opaque" });
      edges.push({
        index: i,
        name: step.name,
        input,
        output: { ...current },
        ok: true,
      });
      continue;
    }
    const resolved = resolveStepType(spec, current, step.params || {});
    if (!resolved.ok) {
      edges.push({
        index: i,
        name: step.name,
        input,
        output: null,
        ok: false,
        error: resolved.error,
      });
      break;
    }
    current = resolved.output;
    if (step.name === "out") {
      const key = slotLabelKey(String(step.params?.name || "@output"));
      if (key) slotTypes.set(key, { ...current });
    }
    edges.push({
      index: i,
      name: step.name,
      input,
      output: { ...current },
      ok: true,
    });
  }
  return edges;
}

/**
 * Terminal sinks that handle the pipeline value (no auto-emitted dangling tile).
 * @param {string} name
 * @returns {boolean}
 */
export function isTerminalSink(name) {
  return (
    name === "out" || name === "text" || name === "gpg.encrypt" || name === "qr"
  );
}
