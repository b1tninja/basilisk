/**
 * The artifact-kind table (§32e/§32f, design_handoff_artifact_actions).
 *
 * The resolver's semantics are pinned in `artifact-kinds.test.js`; this file
 * is about the table itself — that it is unambiguous, that it claims the roles
 * it says it claims, and that folding the three existing renderers in did not
 * require changing them.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { ARTIFACT_ROLES } from "../lib/toolkit/types.js";
import {
  ARTIFACT_KINDS,
  FALLBACK_KIND,
} from "../toolkit/artifact-kinds/registry.tsx";
import { ambiguousPairs, resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";
import { KIND_GLYPHS } from "../toolkit/widgets/kind-glyphs.tsx";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const TABLE_SRC = readFileSync(
  fileURLToPath(new URL("../toolkit/artifact-kinds/registry.tsx", import.meta.url)),
  "utf8"
);
/** Source with comments removed, for assertions about what the code *does*. */
const CODE_ONLY = TABLE_SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(
  /\/\/[^\n]*/g,
  ""
);

/**
 * Roles with no kind entry yet. This list may only ever shrink: §35 and §37
 * of the design fill it in, and until then an honest test records the gap
 * rather than asserting a coverage that does not exist. A role added without
 * a kind fails here, which is the point.
 */
const UNCLAIMED_ROLES = [
  "text",
  "secret",
  // "key" is claimed by keypair-public / keypair-private (§35);
  // "public-key" by openpgp-public (§35e).
  "share",
  "recipients",
  "ciphertext",
  "envelope",
  "sshsig",
  "diagnostic",
  "receipt",
  "qr",
];

describe("the table is unambiguous", () => {
  it("has no two entries that could both claim the same artifact", () => {
    expect(ambiguousPairs(ARTIFACT_KINDS)).toEqual([]);
  });

  it("gives every entry a stable id, a label and an empty-state sentence", () => {
    const ids = new Set();
    for (const kind of ARTIFACT_KINDS) {
      expect(kind.id, "id").toBeTruthy();
      expect(ids.has(kind.id), `duplicate id ${kind.id}`).toBe(false);
      ids.add(kind.id);
      expect(typeof kind.view, `${kind.id} view`).toBe("function");
      // An empty state is a sentence explaining what is missing and what would
      // produce it — never "N/A", which tells the reader nothing.
      expect(kind.empty.length, `${kind.id} empty`).toBeGreaterThan(20);
      expect(kind.empty, `${kind.id} empty`).not.toMatch(/^N\/A|^none$/i);
    }
  });

  it("names only glyphs that exist", () => {
    // §32d: a kind's glyph is a KIND_GLYPHS key, and omitting it renders no
    // glyph rather than a guess. A name with no entry would render nothing
    // while looking declared — the worst of both.
    for (const kind of ARTIFACT_KINDS) {
      if (!kind.glyph) continue;
      expect(KIND_GLYPHS[kind.glyph], `${kind.id} names glyph "${kind.glyph}"`).toBeTruthy();
    }
  });

  it("only claims roles that exist in the vocabulary", () => {
    for (const kind of ARTIFACT_KINDS) {
      expect(ARTIFACT_ROLES, kind.id).toContain(kind.match.role);
    }
  });
});

describe("role coverage", () => {
  const claimed = new Set(ARTIFACT_KINDS.map((k) => k.match.role));

  it("claims netvalue, inspect and token", () => {
    for (const role of ["netvalue", "inspect", "token"]) {
      expect(claimed.has(role), role).toBe(true);
    }
  });

  it("records exactly the roles still without a kind", () => {
    // Shrinks as §35/§37 land. If it needs to *grow*, a role was added
    // without a kind and this is where that is caught.
    const unclaimed = ARTIFACT_ROLES.filter((r) => !claimed.has(r));
    expect([...unclaimed].sort()).toEqual([...UNCLAIMED_ROLES].sort());
  });
});

describe("the fallback is a kind, not a crash (§32f)", () => {
  it("claims nothing, so it is only ever reached by falling through", () => {
    expect(ARTIFACT_ROLES).not.toContain(FALLBACK_KIND.match.role);
  });

  it("renders no view of its own, leaving the raw body to show", () => {
    // Deliberately not an error tile and not a warning: the value is real and
    // correct, and only our description of it is missing. Converting an engine
    // metadata omission into a user-visible failure inverts the severity.
    expect(FALLBACK_KIND.view({ artifact: { content: "x" }, masked: false })).toBeNull();
  });

  it("catches an unclaimed role today", () => {
    const kind = resolveArtifactKind(
      { role: "receipt" },
      ARTIFACT_KINDS,
      FALLBACK_KIND
    );
    expect(kind.id).toBe("fallback");
  });
});

describe("the existing renderers were folded in, not rewritten (§32e)", () => {
  it("imports all three unmodified", () => {
    expect(TABLE_SRC).toMatch(/import \{ NetworkArtifact \} from "\.\.\/widgets\/NetworkArtifact"/);
    expect(TABLE_SRC).toMatch(
      /import \{ InspectorArtifact \} from "\.\.\/widgets\/InspectorArtifact"/
    );
    expect(TABLE_SRC).toMatch(
      /import \{ JwtArtifact, hasJoseRenderer \} from "\.\.\/widgets\/JwtArtifact"/
    );
  });

  it("no longer keys the render path off hasNetworkRenderer", () => {
    // The seven network bases are now the definition of role "netvalue" in the
    // type projection, so the list of renderable network types lives with the
    // types instead of being duplicated in a widget.
    // Asserted against the source with comments stripped: the header explains
    // why the predicate is gone, in prose that names and calls it. Forbidding
    // the word outright would delete the explanation along with the thing it
    // explains — the same trap the threat-model and ScrollArea tests hit.
    expect(CODE_ONLY).not.toMatch(/hasNetworkRenderer/);
  });

  it("demotes hasJoseRenderer to a body check inside a view", () => {
    // It answers "is this body shaped like a token body", which is the right
    // question for it — but it is no longer what decides the kind.
    const jose = ARTIFACT_KINDS.find((k) => k.id === "jose-token");
    expect(jose.match.role).toBe("token");
    expect(TABLE_SRC).toMatch(/view: \(\{ artifact \}\) =>\s*hasJoseRenderer/);
  });

  it("renders the empty state rather than a different kind when a body is missing", () => {
    // The if/else chain would have fallen through to raw text here, silently
    // treating a token as untyped. The kind is matched from identity, so a
    // token with no decoded body is still a token.
    const jose = ARTIFACT_KINDS.find((k) => k.id === "jose-token");
    expect(jose.view({ artifact: { content: "eyJ…", jose: undefined }, masked: false })).toBeNull();
    expect(jose.empty).toMatch(/jose\.verify/);
  });
});

describe("real engine artifacts resolve to the right kind", () => {
  /** Run a recipe and resolve every artifact it emits. */
  const kindsFor = async (src) => {
    const { ast, validation } = compileRecipe(src);
    expect(validation.ok, (validation.errors || []).map((e) => e.message).join(" · ")).toBe(
      true
    );
    const arts = await runRecipe(ast, {});
    return arts.map((a) => ({
      label: a.label,
      role: a.role,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id,
    }));
  };

  it("matches an inspect snapshot by identity, not by body presence", async () => {
    // The old chain asked "is there an inspectSnapshot field". This asks what
    // the artifact *is*, so a sensitive value — for which the engine
    // deliberately withholds the snapshot — is still an inspect artifact and
    // shows the kind's empty sentence rather than silently becoming raw text.
    const rows = await kindsFor('"hello" | utf8 | inspect');
    const snap = rows.find((r) => r.role === "inspect");
    expect(snap, `no inspect artifact in ${JSON.stringify(rows)}`).toBeTruthy();
    expect(snap.kind).toBe("inspect-snapshot");
  });

  it("leaves a plain text artifact to the fallback, which still renders it", async () => {
    const rows = await kindsFor('"plain" | utf8 | out @msg');
    expect(rows.every((r) => r.kind === "fallback")).toBe(true);
  });

  it("never throws on anything the engine emits", async () => {
    // Ambiguity is a build error by design; this is the guard that no real
    // artifact trips it.
    const rows = await kindsFor(`genkey ed25519 | out @kp

"x" | utf8 | inspect

"y" | utf8 | out @t`);
    expect(rows.length).toBeGreaterThan(3);
  });
});

describe("key artifacts resolve to the right card (§35)", () => {
  it("splits a keypair into public and private kinds", async () => {
    const { ast } = compileRecipe("genkey ed25519 | out @kp");
    const arts = await runRecipe(ast, {});
    const kinds = arts.map((a) => ({
      label: a.label,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id,
      alg: a.traits?.alg,
    }));
    const priv = kinds.find((k) => /private/.test(k.label));
    const pub = kinds.find((k) => /public/.test(k.label));
    expect(priv.kind).toBe("keypair-private");
    expect(pub.kind).toBe("keypair-public");
    // traits.alg is what KeyCard shows as the algorithm — the tag the recipe
    // named, not a value re-derived from the JWK.
    expect(priv.alg).toBe("ed25519");
    expect(pub.alg).toBe("ed25519");
  });

  it("gives the private half a publicView so a masked tile is not blank", () => {
    const priv = ARTIFACT_KINDS.find((k) => k.id === "keypair-private");
    expect(typeof priv.publicView).toBe("function");
    // The full view must never be the masked renderer.
    expect(priv.publicView).not.toBe(priv.view);
  });

  it("falls to the general key kind when no half is declared", () => {
    // The auto-emitted pipeline tip carries role "key" with no keypair tags.
    expect(
      resolveArtifactKind({ role: "key" }, ARTIFACT_KINDS, FALLBACK_KIND).id
    ).toBe("key");
    // …and the tagged halves still win, regardless of declaration order.
    expect(
      resolveArtifactKind(
        { role: "key", tags: ["keypair", "public"] },
        ARTIFACT_KINDS,
        FALLBACK_KIND
      ).id
    ).toBe("keypair-public");
  });
});

describe("OpenPGP keys resolve to their own kinds (§35e)", () => {
  it("splits gpg.genkey into openpgp-public and openpgp-private", async () => {
    const { ast } = compileRecipe('gpg.genkey email="k@example.com" | out @priv');
    const arts = await runRecipe(ast, {});
    const byKind = arts.map((a) => ({
      label: a.label,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id,
      sensitive: a.sensitive,
    }));
    const pub = byKind.find((k) => /public key/i.test(k.label));
    const priv = byKind.find((k) => k.label === "priv");
    expect(pub.kind).toBe("openpgp-public");
    expect(pub.sensitive).toBe(false);
    // The private half must NOT fall through to the generic key kind, whose
    // card parses JWK and would render an empty read-out for armor.
    expect(priv.kind).toBe("openpgp-private");
    expect(priv.sensitive).toBe(true);
  }, 60_000);

  it("never offers Publish on a private key", () => {
    // Not declared, so there is no button and nothing to reason about at
    // runtime — the strongest form of "this cannot happen".
    const priv = ARTIFACT_KINDS.find((k) => k.id === "openpgp-private");
    expect(priv.actions).not.toContain("key.publish");
    expect(priv.actions).not.toContain("keyring.publish");
  });

  it("gives the private half a publicView, so masked is not blank", () => {
    const priv = ARTIFACT_KINDS.find((k) => k.id === "openpgp-private");
    expect(typeof priv.publicView).toBe("function");
    expect(priv.publicView).not.toBe(priv.view);
  });
});
