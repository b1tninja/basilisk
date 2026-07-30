/**
 * Type registry — documentation coverage, literal parsing, and constructors.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { getStep, listSteps } from "../lib/toolkit/registry.js";
import { docsUrlFor } from "../lib/toolkit/step-docs.js";
import {
  TYPE_META,
  consumersOf,
  getTypeMeta,
  instantiateTypeLiteral,
  intByteLength,
  listConstructibleTypes,
  listTypes,
  parseBoolLiteral,
  parseBytesLiteral,
  parseIntLiteral,
  producersOf,
} from "../lib/toolkit/type-registry.js";
import {
  BASE_ENCODINGS,
  formatType,
  inferSourceType,
  resolveStepType,
  stepAcceptsRefined,
  typeOf,
} from "../lib/toolkit/types.js";
import { parseRecipeSource } from "../lib/toolkit/recipe-parse.js";
import { serializeRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { parsePemBlocks } from "../lib/toolkit/encode.js";

/** Every `IoType` the registry can mention, gathered from the step signatures. */
function declaredTypes() {
  const seen = new Set();
  for (const step of listSteps()) {
    for (const t of [step.input, step.output]) if (typeof t === "string") seen.add(t);
    for (const ov of step.overloads || []) {
      for (const t of [ov.input, ov.output]) {
        if (typeof t === "string") seen.add(t);
        else if (t && typeof t.base === "string") seen.add(t.base);
      }
    }
  }
  return seen;
}

describe("type documentation coverage", () => {
  it("documents every type any step declares", () => {
    // `any` is a signature marker, not a value — nothing produces one and it
    // never reaches a pipeline tip, so it has no card.
    const undocumented = [...declaredTypes()].filter((t) => t !== "any" && !getTypeMeta(t));
    expect(undocumented).toEqual([]);
  });

  it("keeps `any` out of the browsable type list", () => {
    expect(listTypes().map((t) => t.base)).not.toContain("any");
    expect(producersOf("any")).toEqual([]);
  });

  it("reports the universal passthroughs as consumers of every type", () => {
    // Regression: these declared `input: "bytes"` while the checker special-
    // cased them by name, so the browser claimed nothing at all consumed
    // `stats` or `candidate` — the observe-only types you most need to
    // display.
    for (const base of ["stats", "candidate", "session", "keypair", "sdp"]) {
      expect(consumersOf(base), base).toEqual(
        expect.arrayContaining(["out", "inspect", "tee", "peek", "text"])
      );
    }
  });

  it("does not list `in` as a consumer — it is a source", () => {
    expect(getStep("in").kind).toBe("source");
    expect(getStep("in").input).toBe("none");
    expect(consumersOf("bytes")).not.toContain("in");
  });

  it("gives every type a label, summary, and doc", () => {
    for (const meta of listTypes()) {
      expect(meta.label, `${meta.base} label`).toBeTruthy();
      expect(meta.summary, `${meta.base} summary`).toBeTruthy();
      expect(meta.doc.length, `${meta.base} doc`).toBeGreaterThan(40);
    }
  });

  it("lists each type exactly once", () => {
    const bases = listTypes().map((t) => t.base);
    expect(new Set(bases).size).toBe(bases.length);
    expect(bases.length).toBe(Object.keys(TYPE_META).length);
  });
});

describe("producers and consumers are derived from the registry", () => {
  it("names only steps that exist", () => {
    for (const meta of listTypes()) {
      for (const name of [...producersOf(meta.base), ...consumersOf(meta.base)]) {
        expect(getStep(name), `${meta.base} → ${name}`).toBeTruthy();
      }
    }
  });

  it("finds the obvious producers", () => {
    expect(producersOf("keypair")).toContain("genkey");
    expect(producersOf("bytes")).toContain("random");
    expect(producersOf("bytes")).toContain("bytes");
    expect(producersOf("sdp")).toContain("rtc.offer");
  });

  it("never claims a producer for a reserved type", () => {
    // `host`/`peer` are declared in the type union but unused. If a step ever
    // starts producing one, this failing assertion is the reminder to drop the
    // "reserved" wording from its card.
    expect(producersOf("host")).toEqual([]);
    expect(producersOf("peer")).toEqual([]);
  });
});

describe("int literals", () => {
  it("accepts every base a programmer would type", () => {
    for (const src of ["32", "0x20", "0X20", "0b100000", "0o40", "3_2"]) {
      const r = parseIntLiteral(src);
      expect(r.ok, src).toBe(true);
      expect(r.value, src).toBe(32);
    }
  });

  it("keeps the sign", () => {
    expect(parseIntLiteral("-0x10").value).toBe(-16);
    expect(parseIntLiteral("+8").value).toBe(8);
  });

  it("rejects what Number() would silently accept", () => {
    // Number("") === 0 and Number("1e3") === 1000 — both would turn a typo
    // into a plausible-looking key length.
    for (const src of ["", "   ", "1e3", "abc", "0xZZ", "1.5", "0b2"]) {
      expect(parseIntLiteral(src).ok, src).toBe(false);
    }
  });

  it("rejects integers past exact representation", () => {
    expect(parseIntLiteral("9007199254740993").ok).toBe(false);
  });

  it("reports the other notation, byte length, and endianness (§31b)", () => {
    // The readout exists so "what I typed" and "what the pipeline holds" are
    // never in question — hex in, decimal out; decimal in, hex out.
    expect(parseIntLiteral("0x2A").note).toBe("= 42 decimal · 1 byte · big-endian");
    expect(parseIntLiteral("42").note).toBe("= 0x2A hex · 1 byte · big-endian");
    expect(parseIntLiteral("256").note).toBe("= 0x100 hex · 2 bytes · big-endian");
  });

  it("sizes integers by magnitude", () => {
    expect(intByteLength(0)).toBe(1);
    expect(intByteLength(255)).toBe(1);
    expect(intByteLength(256)).toBe(2);
    expect(intByteLength(65535)).toBe(2);
    expect(intByteLength(65536)).toBe(3);
  });
});

describe("bool and bytes literals", () => {
  it("parses bools", () => {
    expect(parseBoolLiteral("true").value).toBe(true);
    expect(parseBoolLiteral("NO").value).toBe(false);
    expect(parseBoolLiteral("maybe").ok).toBe(false);
  });

  it("parses bytes in each encoding", () => {
    expect(parseBytesLiteral("deadbeef", "hex").value).toHaveLength(4);
    expect(parseBytesLiteral("0xdeadbeef", "hex").value).toHaveLength(4);
    expect(parseBytesLiteral("aGVsbG8=", "base64").value).toHaveLength(5);
    expect(parseBytesLiteral("hello", "utf8").value).toHaveLength(5);
  });

  it("rejects malformed bytes", () => {
    expect(parseBytesLiteral("zzz", "hex").ok).toBe(false);
    expect(parseBytesLiteral("abc", "hex").ok).toBe(false); // odd digit count
    expect(parseBytesLiteral("", "hex").ok).toBe(false);
  });
});

describe("literal constructors", () => {
  it("builds only for constructible types", () => {
    expect(listConstructibleTypes().map((t) => t.base)).toEqual([
      "bytes",
      "text",
      "int",
      "bool",
    ]);
  });

  it("resolves to a step that actually exists", () => {
    for (const meta of listConstructibleTypes()) {
      const step = instantiateTypeLiteral(meta.base, meta.base === "bool" ? "true" : "32");
      expect(getStep(step.name), meta.base).toBeTruthy();
    }
  });

  it("normalizes a hex int to its value", () => {
    expect(instantiateTypeLiteral("int", "0x20")).toEqual({
      name: "lit",
      params: { kind: "int", value: "32" },
    });
  });

  it("refuses a type that cannot be written down", () => {
    expect(() => instantiateTypeLiteral("keypair", "x")).toThrow(/cannot be written/);
  });

  it("refuses an invalid literal rather than building a broken step", () => {
    expect(() => instantiateTypeLiteral("int", "abc")).toThrow();
    expect(() => instantiateTypeLiteral("bytes", "zzz")).toThrow();
  });
});

describe("bytes source step", () => {
  it("carries the literal's length into the pipeline type", () => {
    expect(formatType(inferSourceType("bytes", { value: "deadbeef", encoding: "hex" }))).toBe(
      "bytes/4B"
    );
    expect(formatType(inferSourceType("bytes", { value: "hello", encoding: "utf8" }))).toBe(
      "bytes/5B"
    );
  });

  it("refines a 32-byte literal as master key material, like random 32", () => {
    const t = inferSourceType("bytes", { value: "00".repeat(32), encoding: "hex" });
    expect(t.kind).toBe("master");
    expect(t.length).toBe(32);
  });

  it("stays unrefined when the literal is malformed", () => {
    expect(formatType(inferSourceType("bytes", { value: "zzz", encoding: "hex" }))).toBe("bytes");
  });

  it("has a reference link", () => {
    expect(docsUrlFor("bytes")?.url).toContain("Uint8Array");
  });
});

describe("recipe round-trip for values needing quotes", () => {
  /** Parse → serialize → parse, and compare the first step's params. */
  function roundTrip(src) {
    const first = parseRecipeSource(src);
    expect(first.ast, `${src} should parse`).toBeTruthy();
    const text = serializeRecipe(first.ast);
    const again = parseRecipeSource(text);
    expect(again.ast, `${text} should reparse`).toBeTruthy();
    return {
      text,
      before: first.ast.chains[0].steps[0].params,
      after: again.ast.chains[0].steps[0].params,
    };
  }

  it("survives a positional value holding a space", () => {
    // Regression: positional params were serialized unquoted, so
    // `hkp.search "john doe"` became `hkp.search john doe` — which no longer
    // parsed, silently corrupting Copy recipe, share links, and saves.
    const r = roundTrip('hkp.search "john doe"');
    expect(r.after).toEqual(r.before);
    expect(r.after.query).toBe("john doe");
  });

  it("survives base64 padding in a positional value", () => {
    const r = roundTrip('bytes "aGVsbG8=" encoding=base64');
    expect(r.after).toEqual(r.before);
    expect(r.after.value).toBe("aGVsbG8=");
  });

  it("leaves values that need no quoting alone", () => {
    expect(roundTrip("bytes deadbeef").text).toBe("bytes deadbeef");
    expect(roundTrip("random 32").text).toBe("random 32");
  });
});

describe("keypair import type (§31c)", () => {
  const hex = (b) =>
    [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

  async function pemOf(key, format, label) {
    const der = new Uint8Array(await crypto.subtle.exportKey(format, key));
    const b64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, "$1\n");
    return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
  }

  async function run(src, material) {
    const { ast } = parseRecipeSource(src);
    return runRecipe(ast, { inputs: { keypair: { value: material } } });
  }

  let pair;
  let wantSpki;
  let jwkText;
  beforeAll(async () => {
    pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    wantSpki = hex(await crypto.subtle.exportKey("spki", pair.publicKey));
    jwkText = JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey));
  });

  it("is a source that produces a keypair", () => {
    const spec = getStep("keypair");
    expect(spec.kind).toBe("source");
    expect(spec.input).toBe("none");
    expect(spec.output).toBe("keypair");
    expect(spec.instantiates).toBe("keypair");
  });

  it("takes its material at run time, so it never reaches the recipe text", () => {
    // The whole security argument for §31c: a pasted private key must not be
    // serializable into a share link or a saved workspace.
    expect(getStep("keypair").unresolvedInputs).toBe("keypair");
    const { ast } = parseRecipeSource("keypair jwk alg=ec/p256 | out @k");
    expect(serializeRecipe(ast)).not.toContain("BEGIN");
    expect(serializeRecipe(ast)).toBe("keypair jwk | out @k");
  });

  it("round-trips an EC private JWK back to the identical public key", async () => {
    // Regression: the EC branch of importBoundJwk kept `key_ops` on the copied
    // public JWK, so a WebCrypto-exported private JWK (key_ops:["sign"]) was
    // rejected for requesting "verify" — every other kty already stripped it.
    const out = await run("keypair jwk alg=ec/p256 | export spki | encode hex | out @pub", jwkText);
    expect(out[0].content).toBe(wantSpki);
  });

  it("assembles a full pair from a PKCS#8 + SPKI pair of PEM blocks", async () => {
    const both =
      (await pemOf(pair.privateKey, "pkcs8", "PRIVATE KEY")) +
      "\n" +
      (await pemOf(pair.publicKey, "spki", "PUBLIC KEY"));
    const out = await run("keypair pem alg=ec/p256 | export spki | encode hex | out @pub", both);
    expect(out[0].content).toBe(wantSpki);
  });

  it("cannot invent the public half from a lone private block", async () => {
    // Not a defect — WebCrypto will not recover SPKI from PKCS#8. This is the
    // reason the step accepts two blocks at once.
    const priv = await pemOf(pair.privateKey, "pkcs8", "PRIVATE KEY");
    await expect(
      run("keypair pem alg=ec/p256 | export spki | encode hex | out @pub", priv)
    ).rejects.toThrow(/No public key/i);
  });

  it("refuses to run with nothing pasted", async () => {
    await expect(run("keypair jwk | out @k", "")).rejects.toThrow(/No key material/i);
  });

  it("splits every PEM block, where parsePem takes only the first", async () => {
    const both =
      (await pemOf(pair.privateKey, "pkcs8", "PRIVATE KEY")) +
      "\n" +
      (await pemOf(pair.publicKey, "spki", "PUBLIC KEY"));
    const blocks = parsePemBlocks(both);
    expect(blocks.map((b) => b.format)).toEqual(["pkcs8", "spki"]);
    expect(parsePemBlocks("nothing here")).toEqual([]);
  });
});

describe("encode / decode as the uniform base-alphabet verbs", () => {
  it("offers the same alphabets on both verbs", () => {
    const to = getStep("encode").params.find((p) => p.name === "encoding").enum;
    const from = getStep("decode").params.find((p) => p.name === "encoding").enum;
    expect(to).toEqual(from);
    expect(to).toEqual(["hex", "base64", "base64url", "base32"]);
  });

  it("keeps the checker's copy in step with the registry's", () => {
    // types.js cannot import registry.js (registry imports types), so the set
    // is written twice. This is the guard that they stay identical.
    const declared = getStep("encode").params.find((p) => p.name === "encoding").enum;
    expect([...BASE_ENCODINGS].sort()).toEqual([...declared].sort());
  });

  it("covers every twin step's alphabet, so neither spelling is privileged", () => {
    for (const twin of ["base64", "base64url", "base32"]) {
      expect(BASE_ENCODINGS.has(twin), twin).toBe(true);
    }
    // hex has no twin step at all, which is why `to`/`from` must carry it.
    expect(getStep("hex")).toBeFalsy();
    expect(BASE_ENCODINGS.has("hex")).toBe(true);
  });

  it("carries the alphabet into the tip type", () => {
    const spec = getStep("encode");
    const r = resolveStepType(spec, typeOf("bytes"), { encoding: "base64url" });
    expect(r.ok).toBe(true);
    expect(r.output.encoding).toBe("base64url");
  });

  it("rejects an alphabet it does not implement", () => {
    const r = resolveStepType(getStep("encode"), typeOf("bytes"), { encoding: "rot13" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not a base alphabet/);
  });
});

describe("polymorphic steps declare `any` rather than lying about bytes", () => {
  it("marks every passthrough", () => {
    for (const name of ["out", "inspect", "tee", "peek", "text", "select"]) {
      expect(getStep(name).input, name).toBe("any");
    }
  });

  it("still accepts every tip type at the checker level", () => {
    for (const base of ["bytes", "text", "keypair", "shares", "stats", "session"]) {
      for (const name of ["out", "inspect", "tee", "peek"]) {
        expect(stepAcceptsRefined(getStep(name), typeOf(base)), `${name} ← ${base}`).toBe(true);
      }
    }
  });
});

describe("step reference links", () => {
  it("points every link at a plausible spec host", () => {
    for (const step of listSteps()) {
      const ref = docsUrlFor(step);
      if (!ref) continue;
      expect(ref.url, step.name).toMatch(
        // eprint.iacr.org is on the list for `stream.*`: the STREAM
        // construction is defined in a paper, not an RFC, and pointing at a
        // blog summary of it would be a worse citation than the paper.
        /^https:\/\/(developer\.mozilla\.org|www\.rfc-editor\.org|www\.w3\.org|www\.itu\.int|en\.wikipedia\.org|github\.com|fidoalliance\.org|www\.ietf\.org|eprint\.iacr\.org)\//
      );
      expect(ref.label, step.name).toBeTruthy();
    }
  });

  it("covers the WebCrypto toolbox, which maps one-to-one onto SubtleCrypto", () => {
    for (const step of listSteps().filter((s) => s.toolbox === "webcrypto")) {
      expect(docsUrlFor(step), step.name).toBeTruthy();
    }
  });

  it("links genkey to generateKey", () => {
    expect(docsUrlFor("genkey").url).toBe(
      "https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey"
    );
  });
});
