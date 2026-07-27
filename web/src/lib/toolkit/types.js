/**
 * Refined pipeline types for toolkit recipes.
 *
 * Coarse IoType (bytes/text/keypair/…) is the `base`. Optional refinements
 * (kind, alg, length, …) let validation and step overloads distinguish e.g.
 * bytes/scalar from bytes/pem without inventing ad-hoc special cases.
 */

/** @typedef {import("./registry.js").IoType} IoType */

/**
 * @typedef {object} RefinedType
 * @property {IoType} base
 * @property {string} [kind]  scalar | master | der | pem | armored | mnemonic | opaque | …
 * @property {string} [alg]
 * @property {number} [length]
 * @property {"public"|"private"} [which]
 * @property {string} [encoding]
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
  if (t.length != null) parts.push(`${t.length}B`);
  if (t.which) parts.push(t.which);
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
    default:
      return tNone();
  }
}

/**
 * Infer refined output for transforms that are param-driven (export/import/pem/…).
 * Returns null when the step should use declared overloads / coarse Io instead.
 * @param {string} name
 * @param {RefinedType} current
 * @param {Record<string, *>} params
 * @returns {{ ok: true, output: RefinedType } | { ok: false, error: string } | null}
 */
export function inferParamDrivenType(name, current, params = {}) {
  if (name === "export") {
    if (current.base !== "keypair") {
      return {
        ok: false,
        error: `"export" expects keypair, got ${formatType(current)}`,
      };
    }
    const format = String(params.format || "pkcs8").toLowerCase();
    const which = String(params.which || "private");
    const alg = current.alg || "ec/p256";
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
      return {
        ok: true,
        output: typeOf("keypair", { alg, which: "public" }),
      };
    }
    return {
      ok: true,
      output: typeOf("keypair", { alg, which: "private" }),
    };
  }

  if (name === "pem") {
    if (params.decode) {
      if (current.base !== "text") {
        return {
          ok: false,
          error: `"pem -d" expects text/pem, got ${formatType(current)}`,
        };
      }
      return {
        ok: true,
        output: typeOf("bytes", { kind: "der" }),
      };
    }
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

  if (name === "base64" || name === "hex" || name === "base32") {
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
        encoding:
          name === "hex" ? "hex" : name === "base32" ? "base32" : "base64",
      }),
    };
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
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"as" expects bytes, got ${formatType(current)}`,
      };
    }
    const t = String(params.type || "opaque").toLowerCase();
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
      error: `"as" type must be master, scalar, or opaque — got "${t}"`,
    };
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

  if (name === "der") {
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"der" expects bytes, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", {
        kind: current.kind || "der",
        alg: current.alg,
        which: current.which,
      }),
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
          `"sss.combine" expects shares/raw — decode mnemonics first with "blip39 -d"`,
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
          error: `"blip39 -d" expects shares/mnemonic, got shares/raw`,
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
    if (
      current.base !== "openpgp-key" &&
      current.base !== "text"
    ) {
      return {
        ok: false,
        error: `"agent.save" expects openpgp-key/private, got ${formatType(current)}`,
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
    return {
      ok: true,
      output: typeOf("bytes", { kind: "master", length: 32 }),
    };
  }

  if (name === "gpg.symdecrypt") {
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
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
  }

  if (name === "tee" || name === "peek" || name === "out") {
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
    const m = sel.replace(/^\./, "").toLowerCase();
    if (m === "private" || m === "public") {
      if (current.base !== "keypair") {
        return {
          ok: false,
          error: `selector ".${m}" requires keypair, got ${formatType(current)}`,
        };
      }
      return {
        ok: true,
        output: typeOf("keypair", { ...current, which: m }),
      };
    }
    if (m === "key") {
      if (current.base !== "item") {
        return {
          ok: false,
          error: `selector ".key" requires item, got ${formatType(current)}`,
        };
      }
      return { ok: true, output: typeOf("text", { kind: "opaque" }) };
    }
    if (m === "value") {
      if (current.base !== "item") {
        return {
          ok: false,
          error: `selector ".value" requires item, got ${formatType(current)}`,
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
        output: typeOf("keypair", { alg: as, which: "private" }),
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
    return { ok: true, output: typeOf("text", { kind: "opaque" }) };
  }

  if (name === "ecdh") {
    const as = String(params.as || "bytes");
    if (as !== "bytes") {
      return {
        ok: true,
        output: typeOf("keypair", { alg: as, which: "private" }),
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
    return { ok: true, output: typeOf("bytes", { kind: "opaque" }) };
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
      error: `Type mismatch: "${name}" expects ${want}, got ${formatType(current)}.`,
    };
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

  if (
    spec.name === "tee" ||
    spec.name === "peek" ||
    spec.name === "inspect" ||
    spec.name === "out" ||
    spec.name === "text" ||
    spec.name === "select" ||
    spec.name === "in"
  ) {
    return true;
  }
  if (spec.name === "foreach") return current.base === "shares";
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
      current.base === "openpgp-key" && current.which === "private"
    ) || (current.base === "text" && !!current);
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
    return current.base === "bytes" || current.base === "text";
  }
  if (spec.name === "ecdh" || spec.name === "wrap") {
    return true;
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
  if (driven) return driven.ok;

  const want = spec.input;
  if (!want || want === "none") return false;
  if (current.base === want) return true;
  if (spec.name === "gpg.encrypt" && (current.base === "text" || current.base === "bytes")) {
    return true;
  }
  if (spec.name === "utf8" && (current.base === "text" || current.base === "bytes")) {
    return true;
  }
  // Decode variants suggested when holding text
  if (current.base === "text" && spec.params?.some((p) => p.flag === "-d")) {
    return true;
  }
  return false;
}

/**
 * Project a refined type into artifact role/tags for UI (single source of truth).
 * @param {RefinedType} t
 * @returns {{ role: string, tags: string[] }}
 */
export function artifactMetaFromType(t) {
  if (!t) return { role: "text", tags: [] };
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
 *
 * @param {{ name: string, params?: Record<string, *>, body?: *, branches?: *, foreachSelector?: string }[]} steps
 * @param {{ getStep: (name: string) => { name: string, kind?: string, overloads?: StepOverload[], input?: IoType, output?: IoType } | null }} deps
 * @returns {{
 *   edges: { index: number, name: string, input: RefinedType, output: RefinedType|null, ok: boolean, error?: string }[],
 *   final: RefinedType,
 * }}
 */
export function walkPipelineTypes(steps, deps) {
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
    if (step.name === "foreach") {
      const mode = String(step.foreachSelector || ".values").replace(/^\./, "");
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
        ? walkBodyTypes(step.body, itemType, deps)
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
        ? walkBodyTypes(step.body, current, deps)
        : [];
      /** @type {{ member: string, edges: ReturnType<typeof walkBodyTypes> }[]} */
      const branchEdges = [];
      for (const br of step.branches || []) {
        const m = String(br.member || br.selector || "")
          .replace(/^\./, "")
          .toLowerCase();
        const which =
          m === "private" || m === "priv" || m === "secret"
            ? "private"
            : m === "public" || m === "pub"
              ? "public"
              : null;
        const projected =
          current.base === "keypair" && which
            ? typeOf("keypair", { ...current, which })
            : current;
        branchEdges.push({
          member: which || m,
          edges: walkBodyTypes(br.body || [], projected, deps),
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
 */
function walkBodyTypes(body, start, deps) {
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
