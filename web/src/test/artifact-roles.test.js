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

/**
 * Every string literal the engine writes as a `role:` value.
 *
 * Reads the **whole line** rather than only the literal immediately after the
 * colon, because a role is often a ternary — `role: isShare ? "share" :
 * "ciphertext"` — and the narrower pattern silently saw neither branch. That
 * blindness was invisible until `gpg.symencrypt`'s two modes stopped sharing
 * one role and the guard had nothing to say about either word.
 *
 * The corollary is a constraint on `engine.js`, stated where it can be read:
 * the `role:` line carries role literals and nothing else. A condition that
 * needs a string of its own is hoisted to a variable above the push, which is
 * exactly what `ceremonyEnvelope` is.
 */
const ENGINE_ROLE_LITERALS = [
  ...ENGINE.matchAll(/\brole(?::|\s*=)([^\n]*)/g),
].flatMap((m) => [...m[1].matchAll(/"([a-z-]+)"/g)].map((lit) => lit[1]));

describe("one vocabulary", () => {
  it("covers every role literal the engine emits", () => {
    expect(ENGINE_ROLE_LITERALS.length).toBeGreaterThan(10);
    const unknown = [...new Set(ENGINE_ROLE_LITERALS)].filter(
      (r) => !ARTIFACT_ROLES.includes(r)
    );
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
    // The half names the role, because the badge on a tile *is* the role and
    // a public key that badges the same word as the private half beside it
    // fails at the only job a badge has.
    [typeOf("key", { which: "public" }), "public-key"],
    [typeOf("key", { which: "private" }), "key"],
    // Symmetric is not a half at all — WebCrypto's own `key.type === "secret"`.
    [typeOf("key", { which: "secret" }), "secret-key"],
    // Unchanged: the OpenPGP halves are told apart by their `openpgp` tag and
    // their own two kinds, not by the role.
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
    // Against the extracted literals, not a per-role regex over the file: an
    // engine that stopped writing `envelope` as a bare `role: "envelope"` —
    // which is what happened when the ceremony wrap and a passphrase message
    // stopped sharing a role — would still be declaring it, and a pattern
    // pinned to the old shape failed on a change that kept the property.
    for (const role of ["receipt", "diagnostic", "qr", "envelope", "inspect"]) {
      expect(ENGINE_ROLE_LITERALS, role).toContain(role);
    }
  });

  it("gives the ceremony envelope its word back, and the passphrase mode its own", () => {
    // Both `gpg.symencrypt` modes stamped `role: "envelope"`, so a
    // `mode=passphrase` message badged **ENVELOPE** while its own label called
    // it "OpenPGP symmetric ciphertext" — the badge and the label disagreeing
    // on one tile, in the one word that tells a witness what not to count
    // toward a threshold.
    expect(ENGINE).toMatch(/const ceremonyEnvelope = mode !== "passphrase"/);
    expect(ENGINE).toMatch(/role: ceremonyEnvelope \? "envelope" : "ciphertext"/);
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
    // roles — `secret` from `out $priv`, `text` from a dangling tip — and a
    // kind matches `role` exactly, so it could only ever have claimed one.
    //
    // `public-key` and `secret-key` were written down for the third variant
    // of the same reason: which half a key handle is — or that it is no half,
    // being symmetric — is a fact about the *type* (`key/…/public`,
    // `key/…/secret`), and leaving the sensitivity ternary in charge of it
    // meant the two halves of one `out` wore the same badge.
    expect(ENGINE).toMatch(
      /const TYPE_OWNED_ROLES = new Set\(\[\s*"sshsig",\s*"token",\s*"ssh-public",\s*"ssh-private",\s*"public-key",\s*"secret-key",?\s*\]\)/
    );
  });

  it("lets an sshsig block be an sshsig, not text", async () => {
    // It was `text` while carrying tags ["ssh","signature"], which left
    // `role: "sshsig"` in the vocabulary with nothing able to claim it.
    const roles = await rolesFor(
      'genkey ed25519 | out $id\n\n"msg" | utf8 | ssh.sign key=$id namespace=file | out $sig'
    );
    expect(roles.sig).toBe("sshsig");
  }, 60_000);

  it("lets a JOSE token be a token, even though it is sensitive", async () => {
    // A JWS came out `secret` because the payload was, which is a fact about
    // *handling* and not about what the artifact is — `sensitive` already
    // carries that, and carries it without costing the artifact its identity.
    const roles = await rolesFor(
      'genkey ec/p256 | out $k\n\n"hello" | utf8 | jose.sign key=$k | out $tok'
    );
    expect(roles.tok).toBe("token");
  }, 60_000);

  it("leaves the ordinary text and secret cases exactly where they were", async () => {
    expect((await rolesFor('"plain" | utf8 | out $msg')).msg).toBe("text");
    expect((await rolesFor("random 32 | out $s")).s).toBe("secret");
    // The known gap, asserted so it is a decision rather than a surprise: a
    // PEM export still lands as `text`, waiting on a KeyCard that reads PEM.
    expect((await rolesFor("genkey ec/p256 | export spki | pem | out $pub")).pub).toBe(
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
      // A decrypt's signature verdict. Added here the moment it was added to
      // the projection, because deleting the line reaching the tile changed
      // nothing any test could see — the trap this block exists for, caught by
      // mutation rather than by review.
      "signature",
    ]) {
      expect(block[0], field).toMatch(
        new RegExp(`\\b${field}: (?:!!)?a\\.${field}`)
      );
    }
  });
});

/**
 * The other two projections, and the tile at the end of all three.
 *
 * `useNotebook` feeds the notebook; the shell has two more mappings of its own,
 * and a field listed in one and missed in the others reaches a reader from some
 * panes and not others — which is worse than reaching none, because it looks
 * like the value's fault. The OTP tile shipped three named fields through one
 * of the three and rendered nowhere; the comment above records `pipeType`
 * costing a third debugging round for the same reason.
 *
 * Source-text assertions rather than rendering, which the vitest config keeps
 * out of scope. They are weaker than a render and far stronger than nothing:
 * each one fails if the line that carries the field is deleted, which is
 * exactly the mutation that survived everything else.
 */
describe("a decrypt's verdict survives every projection between engine and tile", () => {
  const read = (rel) =>
    readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

  it("is carried by both of the shell's artifact mappings", () => {
    const shell = read("../toolkit/ToolkitShell.tsx");
    const carried = shell.match(/\bsignature: a\.signature\b/g) || [];
    expect(carried.length, "both shell mappings must carry it").toBe(2);
  });

  it("is drawn by the tile, in `JwtArtifact`'s attribute pattern", () => {
    const tile = read("../toolkit/widgets/ArtifactTile.tsx");
    // The state is an attribute so the styling is an enumerated CSS rule and
    // not a colour chosen in the widget — `style-src 'self'` refuses an inline
    // style, and the *verified* appearance must not be reachable by accident.
    expect(tile).toMatch(/data-signature-verified=\{a\.signature\.state\}/);
    expect(tile).toMatch(/\{a\.signature\.sentence\}/);
    // Never `data-cast`, and never a `CastDot`: that attribute and that dot are
    // the crypto suite's self-test, and a signature verdict wearing either
    // would put one fact where a reader has learned to find another.
    // `cast-indicator.test.js` pins the same boundary from the other side, on
    // `OpsTile`. The `=` matters — the prose above explains the choice and
    // naming it there is not using it.
    expect(tile).not.toMatch(/data-cast=/);
    expect(tile).not.toMatch(/<CastDot/);
  });

  it("has a CSS rule for every state the verdict can hold, and only those", () => {
    const css = read("../css/toolkit.css");
    for (const state of ["verified", "unverified", "unsigned"]) {
      expect(css, state).toContain(`.artifact-signature[data-signature-verified="${state}"]`);
    }
    // A verified signature addressed to a different key outruns its own tone:
    // green on surreptitious forwarding would be the widget agreeing with the
    // forwarder.
    expect(css).toContain('.artifact-signature[data-signature-intended="mismatch"]');
  });
});
