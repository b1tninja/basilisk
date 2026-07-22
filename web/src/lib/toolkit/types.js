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
    case "input":
      return typeOf("text", { kind: "opaque" });
    case "recombine": {
      const kind = String(params.kind || "shares");
      if (kind === "text") return typeOf("text", { kind: "opaque" });
      return typeOf("shares", { kind: "mnemonic" });
    }
    case "decrypt":
      return typeOf("shares", { kind: "mnemonic" });
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
    if (current.base !== "bytes") {
      return {
        ok: false,
        error: `"import" expects bytes, got ${formatType(current)}`,
      };
    }
    const format = String(params.format || "pkcs8").toLowerCase();
    const alg = String(params.alg || "ec/p256");
    if (format === "scalar" || format === "d") {
      if (current.kind && current.kind !== "scalar" && current.kind !== "master") {
        return {
          ok: false,
          error:
            `"import scalar" expects bytes/scalar or bytes/master (from combine), got ${formatType(current)}. ` +
            `Use export scalar before slip39, or combine shares of a scalar split.`,
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

  if (name === "base64" || name === "hex") {
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
        encoding: name === "hex" ? "hex" : "base64",
      }),
    };
  }

  if (name === "base64url") {
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

  if (name === "combine") {
    if (current.base !== "shares") {
      return {
        ok: false,
        error: `"combine" expects shares, got ${formatType(current)}`,
      };
    }
    // Recovered secret is always 16/32-byte master-sized material (scalar or random).
    return {
      ok: true,
      output: typeOf("bytes", { kind: "master" }),
    };
  }

  if (name === "symencrypt") {
    if (current.base !== "text" && current.base !== "bytes") {
      return {
        ok: false,
        error: `"symencrypt" expects text or bytes, got ${formatType(current)}`,
      };
    }
    if (current.kind === "master" || current.kind === "scalar") {
      return {
        ok: false,
        error:
          `"symencrypt" is for PEM/arbitrary payloads — got ${formatType(current)}. ` +
          `Pipe that to slip39 directly (already 16/32 bytes).`,
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", { kind: "master", length: 32 }),
    };
  }

  if (name === "symdecrypt") {
    if (current.base !== "bytes" || current.kind !== "master") {
      return {
        ok: false,
        error:
          `"symdecrypt" expects bytes/master from combine, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      output: typeOf("bytes", { kind: "opaque" }),
    };
  }

  if (name === "fanout") {
    if (current.base !== "keypair") {
      return {
        ok: false,
        error: `"fanout" expects keypair, got ${formatType(current)}`,
      };
    }
    return { ok: true, output: { ...current } };
  }

  if (name === "tee" || name === "out") {
    if (!current || current.base === "none") {
      return {
        ok: false,
        error: `"${name}" needs a pipeline value`,
      };
    }
    return { ok: true, output: { ...current } };
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
      if (name === "slip39") {
        error +=
          '. For EC keys use "export scalar"; for PEM/arbitrary data use "symencrypt" first.';
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
    // Special-cases previously in ioCompatible
    if (name === "encrypt" && (current.base === "text" || current.base === "bytes")) {
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
    spec.name === "inspect" ||
    spec.name === "out" ||
    spec.name === "text"
  ) {
    return true;
  }
  if (spec.name === "fanout") return current.base === "keypair";
  if (spec.name === "foreach") return current.base === "shares";
  if (spec.name === "merge") return true;
  if (spec.name === "combine") return current.base === "shares";

  if (spec.overloads?.length) {
    return !!matchOverload(spec.overloads, current, {});
  }

  const driven = inferParamDrivenType(spec.name, current, {});
  if (driven) return driven.ok;

  const want = spec.input;
  if (!want || want === "none") return false;
  if (current.base === want) return true;
  if (spec.name === "encrypt" && (current.base === "text" || current.base === "bytes")) {
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
  if (t.base === "shares" || t.kind === "mnemonic") {
    return { role: "share", tags: ["mnemonic", "slip39"] };
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
  return { role: "text", tags: t.kind ? [t.kind] : [] };
}

/**
 * Whether Encrypt should open an artifact as a compose message vs a file.
 *
 * Recipe sinks decide this explicitly (memory-safety.js rule 4 — do not regress):
 *   - `text` / `print` → disposition "message" (compose; string unavoidable)
 *   - `out name=…` → disposition "file" (attachment; keep wipeable `artifact.bytes`)
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
