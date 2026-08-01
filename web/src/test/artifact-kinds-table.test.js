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
import { actionsFor } from "../lib/toolkit/artifact-actions.js";
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
 *
 * Empty since §37 — every role in the vocabulary is claimed. The constant
 * stays because it is the shape of the gate: a role added to ARTIFACT_ROLES
 * without a kind lands here as a failure, and a future role that is
 * deliberately unclaimed has somewhere to be written down with its reason.
 */
const UNCLAIMED_ROLES = [];

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

  it("declares Download on every kind, because every body is a file", () => {
    // A kind that declares no actions renders no buttons. That is correct for
    // a kind's *own* actions and wrong for a universal one — omitting Copy
    // once already took it off the majority of tiles the moment the bespoke
    // button was replaced by the table. Download is universal by the same
    // test: §33d's "is this meaningful for this object" is yes for any body.
    for (const kind of ARTIFACT_KINDS) {
      expect(kind.actions, kind.id).toContain("download");
    }
  });

  it("declares Copy everywhere but on the QR, whose source nobody wants", () => {
    // §37b called this and deferred it until there was a second affordance to
    // leave behind: nobody reads a QR by reading its path data, but a tile
    // with no button at all is worse than one with an odd button. Download
    // landed, so Copy went — as an omission, not a disabled state.
    const withoutCopy = ARTIFACT_KINDS.filter((k) => !(k.actions || []).includes("copy"));
    expect(withoutCopy.map((k) => k.id)).toEqual(["qr"]);
  });
});

describe("§37 pruned the actions it was offered", () => {
  const declared = new Set(ARTIFACT_KINDS.flatMap((k) => k.actions || []));

  it("declares no action that would compute a new value (§37a)", () => {
    // "A button may move an artifact. It may never compute a new one."
    // Decrypt with…, Verify threshold, Trust…, Send to peer and Save as group
    // all produce a value or a verdict that would exist in the notebook with
    // no derivation behind it, no type, and no place in the recipe or the
    // receipt — a value the CLI cannot reproduce.
    for (const id of [
      "ciphertext.decrypt",
      "share.verifyThreshold",
      "recipients.saveGroup",
      "netvalue.send",
      "sshsig.verify",
      "receipt.verify",
    ]) {
      expect(declared.has(id), id).toBe(false);
    }
  });

  it("names no action the table does not define", () => {
    // A kind naming an action with no definition renders one fewer button and
    // says nothing about it. The tile must not be where that is discovered.
    for (const kind of ARTIFACT_KINDS) {
      expect(actionsFor(kind).length, kind.id).toBe(kind.actions.length);
    }
  });

  it("keeps Publish on exactly one kind (§38b)", () => {
    const withPublish = ARTIFACT_KINDS.filter((k) =>
      (k.actions || []).includes("key.publish")
    );
    expect(withPublish.length).toBeLessThanOrEqual(1);
    for (const k of withPublish) expect(k.match.role).toBe("public-key");
  });
});

describe("§37 kinds show a read-out where there is one, and say so where there is not", () => {
  const kindById = (id) => ARTIFACT_KINDS.find((k) => k.id === id);

  it("gives share the identity line as a publicView, and no view", () => {
    // The share's value *is* its own words, and the tile renders words with a
    // format bar, a Hide button and the auto-hide timer. A widget redrawing
    // the body would have removed all three to add nothing. What was missing
    // is which share this is — public, and therefore drawable while masked.
    const share = kindById("share");
    expect(share.view({ artifact: { content: "away manual" }, masked: false })).toBeNull();
    expect(typeof share.publicView).toBe("function");
  });

  it("gives text and secret no view at all, and an honest sentence instead", () => {
    for (const id of ["text", "secret"]) {
      const kind = kindById(id);
      expect(kind.view({ artifact: { content: "x" }, masked: false }), id).toBeNull();
      expect(kind.empty.length, id).toBeGreaterThan(20);
    }
    // A secret has no public half to draw — unlike a keypair, whose algorithm
    // and fingerprint are facts about the public side. Inventing a line would
    // mean deriving it from the masked material.
    expect(kindById("secret").publicView).toBeUndefined();
  });

  it("never draws a QR while it is masked", () => {
    // A QR *is* the secret, in a form a camera across the room can read.
    expect(kindById("qr").publicView).toBeUndefined();
  });

  it("draws ciphertext and envelope through the same packet read-out", () => {
    // Same body, different artifact: the envelope keeps its "required for
    // recovery (not a share)" label, which the engine already writes.
    for (const id of ["ciphertext", "envelope"]) {
      expect(typeof kindById(id).view, id).toBe("function");
    }
  });
});

describe("the fallback is a kind, not a crash (§32f)", () => {
  it("claims nothing, so it is only ever reached by falling through", () => {
    expect(ARTIFACT_ROLES).not.toContain(FALLBACK_KIND.match.role);
  });

  it("still offers Copy — every artifact can be copied", () => {
    // The fallback claims most artifacts. Without this, replacing the
    // bespoke Copy button with the action table silently removed Copy from
    // the majority of tiles.
    expect(FALLBACK_KIND.actions).toContain("copy");
  });

  it("renders no view of its own, leaving the raw body to show", () => {
    // Deliberately not an error tile and not a warning: the value is real and
    // correct, and only our description of it is missing. Converting an engine
    // metadata omission into a user-visible failure inverts the severity.
    expect(FALLBACK_KIND.view({ artifact: { content: "x" }, masked: false })).toBeNull();
  });

  it("catches an artifact the table does not know about", () => {
    // Since §37 every role in the vocabulary is claimed, so the fallback is
    // reached only by an artifact whose role is outside it — a role-less tile
    // from a path that has not been through `attachPipeMeta`, or a word from a
    // future build. Both must still render their content.
    const kind = resolveArtifactKind(
      { role: "something-later" },
      ARTIFACT_KINDS,
      FALLBACK_KIND
    );
    expect(kind.id).toBe("fallback");
    expect(resolveArtifactKind({}, ARTIFACT_KINDS, FALLBACK_KIND).id).toBe("fallback");
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

  it("claims a plain text artifact, and still draws no widget for it", async () => {
    // §37: `text` is claimed rather than left to the fallback, but with no
    // view of its own — the raw body, its format bar and its reveal gate are
    // already the right rendering of an opaque value. What changed is that the
    // table now says so instead of shrugging.
    const rows = await kindsFor('"plain" | utf8 | out @msg');
    expect(rows.every((r) => r.kind === "text")).toBe(true);
    const text = ARTIFACT_KINDS.find((k) => k.id === "text");
    expect(text.view({ artifact: { content: "plain" }, masked: false })).toBeNull();
  });

  it("resolves the §37 roles the engine really emits", async () => {
    // The design's description of emitted metadata has been wrong before, so
    // these are asserted against a run rather than against the prose. Each one
    // was checked by printing role/tags off `runRecipe` first.
    const shares = await kindsFor("random 32 | sss.split threshold=2 shares=3 | out @s");
    expect(shares.every((r) => r.role === "share" && r.kind === "share")).toBe(true);

    const qr = await kindsFor('"hello" | qr');
    expect(qr.find((r) => r.role === "qr").kind).toBe("qr");

    const env = await kindsFor(
      '"secret data" | utf8 | gpg.symencrypt mode=passphrase passphrase="hunter2"'
    );
    expect(env.find((r) => r.role === "envelope").kind).toBe("envelope");

    const receipt = await kindsFor('run.receipt label="ceremony" | out @r');
    expect(receipt.find((r) => r.role === "receipt").kind).toBe("receipt");
  }, 60_000);

  it("resolves an sshsig block as one, now that the engine says so", async () => {
    // It did not before: the `out` text branch stamped `text`/`secret` from
    // sensitivity, which outranked the type projection, so `role: "sshsig"`
    // sat in the vocabulary with nothing able to claim it (§32c/§37).
    const rows = await kindsFor(
      'genkey ed25519 | out @id\n\n"msg" | utf8 | ssh.sign key=@id namespace=file | out @sig'
    );
    const sig = rows.find((r) => r.label === "sig");
    expect(sig.role).toBe("sshsig");
    expect(sig.kind).toBe("sshsig");
  }, 60_000);

  it("resolves a JOSE token as one, which makes the shipped kind reachable", async () => {
    // Same cause, and the visible symptom was worse: `jose-token` matched
    // `role: "token"`, nothing emitted it, and the JWT reader was unreachable
    // from a notebook while every test passed.
    const rows = await kindsFor(
      'genkey ec/p256 | out @k\n\n"hello" | utf8 | jose.sign key=@k | out @tok'
    );
    const tok = rows.find((r) => r.label === "tok");
    expect(tok.role).toBe("token");
    expect(tok.kind).toBe("jose-token");
  }, 60_000);

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
    // The public half's role is `public-key` now — the badge is the role, and
    // a public key badged KEY beside a private one badged KEY told the reader
    // nothing.
    expect(
      resolveArtifactKind(
        { role: "public-key", tags: ["keypair", "public"] },
        ARTIFACT_KINDS,
        FALLBACK_KIND
      ).id
    ).toBe("keypair-public");
  });

  it("orders the three public-key kinds by specificity, not declaration", () => {
    // One role, three producers. OpenPGP armor and a paired WebCrypto half
    // each carry a tag that narrows them; a lone public key (an `import spki`
    // tip, a projected `:public`) carries neither and must still land on a
    // key card rather than on the OpenPGP one or the fallback.
    const id = (a) => resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id;
    expect(id({ role: "public-key", tags: ["openpgp", "public-key"] })).toBe(
      "openpgp-public"
    );
    expect(id({ role: "public-key", tags: ["keypair", "public"] })).toBe(
      "keypair-public"
    );
    expect(id({ role: "public-key", tags: ["public"] })).toBe("public-key");
    expect(id({ role: "public-key" })).toBe("public-key");
  });

  it("gives a symmetric key its own kind, with no public-material actions", () => {
    // A secret key has no public half, so a fingerprint and a public line are
    // not "disabled" for it — they do not exist (§33d).
    const kind = resolveArtifactKind(
      { role: "secret-key", tags: ["secret"] },
      ARTIFACT_KINDS,
      FALLBACK_KIND
    );
    expect(kind.id).toBe("secret-key");
    expect(kind.actions).not.toContain("key.copyPublicLine");
    expect(kind.actions).not.toContain("key.copyFingerprint");
    expect(kind.actions).not.toContain("keyring.add");
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
