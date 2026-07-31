/**
 * The artifact role vocabulary (§32c, design_handoff_artifact_actions).
 *
 * There were two vocabularies. `engine.js` hand-wrote roles at its emit sites
 * (`public-key`, `envelope`, `qr`, `inspect`); `artifactMetaFromType` — which
 * had no callers at all — emitted `recipients` and `secret`. Neither side could
 * produce the other's words, so a registry that matches on `role` could not be
 * built on either. These tests exist to keep the reconciliation from quietly
 * coming apart, which is precisely how it came apart the first time.
 *
 * The first test greps the engine source, in the style of
 * `toolbox-dot-css.test.js`: a duplication that a human must remember to
 * maintain is a duplication that will drift, so a machine checks it.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// registry.js first: types.js is imported by recipe-parse.js during registry
// init, so reaching for types.js *before* the registry has finished
// initialising trips a module cycle. Every other test in this repo happens to
// import the registry first; this one has to do it on purpose.
import "../lib/toolkit/registry.js";
import {
  ARTIFACT_ROLES,
  artifactMetaFromType,
  typeOf,
} from "../lib/toolkit/types.js";

const ENGINE = readFileSync(
  fileURLToPath(new URL("../lib/toolkit/engine.js", import.meta.url)),
  "utf8"
);

describe("one vocabulary", () => {
  it("covers every role literal the engine emits", () => {
    const emitted = [...ENGINE.matchAll(/\brole: "([a-z-]+)"/g)].map((m) => m[1]);
    expect(emitted.length).toBeGreaterThan(10);
    const unknown = [...new Set(emitted)].filter((r) => !ARTIFACT_ROLES.includes(r));
    expect(unknown, `engine emits roles absent from ARTIFACT_ROLES: ${unknown}`).toEqual(
      []
    );
  });

  it("covers every role the projection emits", () => {
    const projected = [
      ...readFileSync(
        fileURLToPath(new URL("../lib/toolkit/types.js", import.meta.url)),
        "utf8"
      ).matchAll(/\brole: "([a-z-]+)"/g),
    ].map((m) => m[1]);
    const unknown = [...new Set(projected)].filter((r) => !ARTIFACT_ROLES.includes(r));
    expect(unknown).toEqual([]);
  });

  it("is frozen, so a role cannot be added by accident at a call site", () => {
    expect(Object.isFrozen(ARTIFACT_ROLES)).toBe(true);
  });
});

describe("the projection reaches the types that have a role", () => {
  const cases = [
    [typeOf("keypair"), "key"],
    [typeOf("key", { which: "public" }), "key"],
    [typeOf("openpgp-key", { which: "public" }), "key"],
    [typeOf("shares"), "share"],
    [typeOf("recipients"), "recipients"],
    [typeOf("text", { kind: "sshsig" }), "sshsig"],
    [typeOf("text", { kind: "jws" }), "token"],
    [typeOf("text", { kind: "jwe" }), "token"],
    [typeOf("candidate"), "netvalue"],
    [typeOf("sdp"), "netvalue"],
    [typeOf("stats"), "netvalue"],
    [typeOf("connstate"), "netvalue"],
    [typeOf("certificate"), "netvalue"],
  ];
  for (const [t, role] of cases) {
    it(`${t.base}${t.kind ? "/" + t.kind : ""} → ${role}`, () => {
      expect(artifactMetaFromType(t).role).toBe(role);
    });
  }

  it("tags a network value with its own base, so a kind can match just one", () => {
    expect(artifactMetaFromType(typeOf("candidate")).tags).toContain("candidate");
    expect(artifactMetaFromType(typeOf("sdp")).tags).toContain("sdp");
  });

  it("still falls through to text for a type with no better description", () => {
    expect(artifactMetaFromType(typeOf("text")).role).toBe("text");
    expect(artifactMetaFromType(null).role).toBe("text");
  });
});

describe("the floor does not overwrite a declaration (§32c)", () => {
  it("keeps the engine's `if (!artifact.role)` guard", () => {
    // Role is a property of the artifact, not of the value: `receipt` and
    // `diagnostic` come from *why* the artifact exists, which no projection of
    // a type can know. Losing this guard would silently flatten them.
    expect(ENGINE).toMatch(/if \(!artifact\.role && projected\.role\)/);
  });

  it("still declares the roles a projection could never derive", () => {
    for (const role of ["receipt", "diagnostic", "qr", "envelope", "inspect"]) {
      expect(ENGINE, role).toMatch(new RegExp(`role(?::|\\s*=)\\s*"${role}"`));
    }
  });
});

describe("the cellOutputs projection does not silently drop fields (§32/1.4)", () => {
  const HOOK = readFileSync(
    fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url)),
    "utf8"
  );

  it("carries every field the kind registry needs", () => {
    // This projection copies named fields, so anything the engine adds is
    // invisible downstream until it is listed here. The handoff records that
    // trap costing two debugging rounds; `pipeType` was the third — present on
    // every artifact since the type system landed, dropped at this line, and
    // worked around by inventing netType/jose/inspectSnapshot alongside it.
    const block = HOOK.match(/const cellOutputs[\s\S]*?\n    \);/);
    expect(block, "cellOutputs projection not found").toBeTruthy();
    for (const field of [
      "pipeType",
      "tags",
      "role",
      "traits",
      "shareIndex",
      "mime",
      "encoding",
      "bytes",
      "stepName",
      "disposition",
      "revealable",
      "sensitive",
    ]) {
      expect(block[0], field).toMatch(
        new RegExp(`\\b${field}: (?:!!)?a\\.${field}`)
      );
    }
  });
});
