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
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

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
    [typeOf("text", { kind: "ssh-public" }), "ssh-public"],
    [typeOf("text", { kind: "ssh-private" }), "ssh-private"],
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

describe("`text`/`secret` is a sensitivity ternary, not an identity (§32c)", () => {
  /** Run a recipe and hand back label → role. */
  const rolesFor = async (src) => {
    const { ast, validation } = compileRecipe(src);
    expect(validation.ok, (validation.errors || []).map((e) => e.message).join(" · ")).toBe(
      true
    );
    const arts = await runRecipe(ast, {});
    return Object.fromEntries(arts.map((a) => [a.label, a.role]));
  };

  it("keeps the deference set closed, so widening it is a decision", () => {
    // `pem`/`der` project to `key`, and the key card reads JWK — promoting
    // them today would swap a readable armor body for an emptier card. The
    // set is the place that choice is written down.
    //
    // The SSH halves were written down there for the same reason the two
    // above were, plus one the others did not have: `ssh.encode`'s formats
    // are both `text`, so the sensitivity ternary gave one private block two
    // roles — `secret` from `out @priv`, `text` from a dangling tip — and a
    // kind matches `role` exactly, so it could only ever have claimed one.
    expect(ENGINE).toMatch(
      /const TYPE_OWNED_ROLES = new Set\(\[\s*"sshsig",\s*"token",\s*"ssh-public",\s*"ssh-private",?\s*\]\)/
    );
  });

  it("lets an sshsig block be an sshsig, not text", async () => {
    // It was `text` while carrying tags ["ssh","signature"], which left
    // `role: "sshsig"` in the vocabulary with nothing able to claim it.
    const roles = await rolesFor(
      'genkey ed25519 | out @id\n\n"msg" | utf8 | ssh.sign key=@id namespace=file | out @sig'
    );
    expect(roles.sig).toBe("sshsig");
  }, 60_000);

  it("lets a JOSE token be a token, even though it is sensitive", async () => {
    // A JWS came out `secret` because the payload was, which is a fact about
    // *handling* and not about what the artifact is — `sensitive` already
    // carries that, and carries it without costing the artifact its identity.
    const roles = await rolesFor(
      'genkey ec/p256 | out @k\n\n"hello" | utf8 | jose.sign key=@k | out @tok'
    );
    expect(roles.tok).toBe("token");
  }, 60_000);

  it("leaves the ordinary text and secret cases exactly where they were", async () => {
    expect((await rolesFor('"plain" | utf8 | out @msg')).msg).toBe("text");
    expect((await rolesFor("random 32 | out @s")).s).toBe("secret");
    // The known gap, asserted so it is a decision rather than a surprise: a
    // PEM export still lands as `text`, waiting on a KeyCard that reads PEM.
    expect((await rolesFor("genkey ec/p256 | export spki | pem | out @pub")).pub).toBe(
      "text"
    );
  }, 60_000);
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
