/**
 * The dangling keypair tip (§35g).
 *
 * `genkey ed25519` with no `out` emitted one artifact whose entire body was
 * the string `[keypair — use out or export before emitting]` — a placeholder
 * standing where a value goes, telling the reader to write more recipe. Worse,
 * it carried `tags: ["keypair"]` with no half, so it resolved to the
 * least-specific `key` kind, whose masked body is `keyCardFor(true)`: the
 * *public half* card. A keypair was drawn by the card that means "the public
 * half". The type was never wrong; the rendering was.
 *
 * Three things are pinned here, and they are three different failures:
 *
 *  1. The tip has public facts and **no private material** — asserted against
 *     the JWK's own field names, not against a mask, because a mask is a
 *     rendering and this is about what is in the object at all.
 *  2. It resolves to a kind that says "keypair" in its badge, its label and
 *     its card, and is not the kind a public key resolves to.
 *  3. The two halves of `| out @kp` share **no marker naming a half** — as set
 *     disjointness over every field that carries one, so a marker later added
 *     to both fails here rather than in a tile. `ssh-format.test.js`'s "shares
 *     no tag between the two" is the model, and 7d563cd is why it exists.
 */
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { ARTIFACT_ROLES } from "../lib/toolkit/types.js";
import {
  ARTIFACT_KINDS,
  FALLBACK_KIND,
} from "../toolkit/artifact-kinds/registry.tsx";
import { resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";
import { ARTIFACT_ACTIONS } from "../lib/toolkit/artifact-actions.js";

const artifactsOf = async (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.errors, `fixture should compile: ${src}`).toEqual([]);
  return runRecipe(ast, {});
};

const kindOf = (a) => resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND);
const actionById = (id) => ARTIFACT_ACTIONS.find((a) => a.id === id);

/** Every JWK member that is private material, per RFC 7518 §6. */
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "k"];

describe("a bare genkey tip is a keypair, and says so", () => {
  for (const alg of ["ed25519", "ec/p256", "rsa/2048"]) {
    it(`declares role keypair for ${alg}`, async () => {
      const arts = await artifactsOf(`genkey ${alg}`);
      expect(arts).toHaveLength(1);
      const [tip] = arts;
      expect(tip.role).toBe("keypair");
      expect(ARTIFACT_ROLES).toContain("keypair");
      // The role is what the badge renders, and the badge is the glance.
      expect(kindOf(tip).id).toBe("keypair");
      expect(kindOf(tip).label).toBe("Keypair");
    });

    it(`withholds the body and carries the public half for ${alg}`, async () => {
      const [tip] = await artifactsOf(`genkey ${alg}`);
      // No body: materializing what the recipe never asked for would reverse
      // ACTION_REASONS.neverAskedFor, which §34b is built on.
      expect(tip.content).toBe("");
      expect(tip.sensitive).toBe(true);
      expect(tip.revealable).toBeFalsy();
      expect(tip.traits.alg).toBe(alg);
      const jwk = JSON.parse(tip.traits.publicJwk);
      expect(jwk.kty).toBeTruthy();
    });

    it(`puts no private key field anywhere on the ${alg} tip`, async () => {
      const [tip] = await artifactsOf(`genkey ${alg}`);
      // Asserted over the *serialized artifact*, not over the JWK alone: the
      // question is what could reach a tile at all, and the tile is handed the
      // whole object. A private field added to any future trait fails here.
      const jwk = JSON.parse(tip.traits.publicJwk);
      for (const field of PRIVATE_JWK_FIELDS) {
        expect(field in jwk, `public JWK carries private field "${field}"`).toBe(
          false
        );
      }
      // key_ops betray the half too — a private half would say sign/decrypt.
      for (const op of jwk.key_ops || []) {
        expect(["verify", "encrypt", "wrapKey"], `public JWK op ${op}`).toContain(op);
      }
    });
  }

  it("stops claiming a half in its own refined type", async () => {
    // `genkey` types its output `keypair/…/private`, which is a claim about a
    // value that has *both* halves. Nothing matched on `which`, so nothing was
    // visibly wrong — the silence `ssh-public` sat in before it bit.
    const [tip] = await artifactsOf("genkey ed25519");
    expect(tip.pipeType.base).toBe("keypair");
    expect(tip.pipeType.alg).toBe("ed25519");
    expect("which" in tip.pipeType).toBe(false);
  });

  it("leaves a symmetric key alone — it is not a keypair", async () => {
    // aes and hmac arrive as `keypair` values with `publicKey: null`. Calling
    // them keypairs would be the same class of mislabel this fixes, so they
    // keep the least-specific `key` role and get no public-half read-out.
    for (const alg of ["aes/256", "hmac/sha256"]) {
      const [tip] = await artifactsOf(`genkey ${alg}`);
      expect(tip.role, alg).toBe("key");
      expect(tip.traits.publicJwk, alg).toBeUndefined();
    }
  });
});

describe("the keypair tile does not render as a public key", () => {
  const kindById = (id) => ARTIFACT_KINDS.find((k) => k.id === id);

  it("captions itself with both halves, and names what is withheld", async () => {
    const [tip] = await artifactsOf("genkey ed25519");
    const kind = kindOf(tip);
    const el = kind.view({ artifact: tip, masked: false });
    expect(el.props.half).toBe("both");
    // Absence with a stated reason, never silent absence — and the reason
    // names the recipe edit, in ACTION_REASONS' register.
    expect(el.props.withheld).toMatch(/private half/i);
    expect(el.props.withheld).toMatch(/out @kp/);
    // Drawn from the public JWK on traits; there is no body to draw from.
    expect(el.props.content).toBe("");
    expect(el.props.jwk).toBe(tip.traits.publicJwk);
  });

  it("renders identically masked and unmasked, so no reveal can leak", async () => {
    // Structural rather than remembered: a tile with no body has nothing a
    // reveal could add, and making view === publicView means no future reveal
    // path can turn into an exposure here.
    const kind = kindById("keypair");
    expect(kind.view).toBe(kind.publicView);
  });

  it("no longer tells a masked private key it is a public half", async () => {
    // `publicOnly` was captioning the card as well as hiding the raw toggle,
    // so `publicView: keyCardFor(true)` — the masked *private* tile — said
    // "public half" about itself. Same defect, one layer up.
    const priv = kindById("keypair-private");
    const masked = priv.publicView({ artifact: { content: "{}", traits: {} }, masked: true });
    expect(masked.props.half).toBe("private");
    expect(masked.props.publicOnly).toBe(true);
    expect(priv.view({ artifact: { content: "{}", traits: {} }, masked: false }).props.half).toBe(
      "private"
    );
  });

  it("says nothing about the half on the kind that cannot know", async () => {
    // The least-specific `key` kind used to caption every lone key "keypair".
    // §33d's answer to "is this meaningful for this object" is omission.
    const key = kindById("key");
    expect(
      key.view({ artifact: { content: "{}", traits: {} }, masked: false }).props.half
    ).toBeUndefined();
  });

  it("is a different kind from the public half, on real artifacts", async () => {
    const [tip] = await artifactsOf("genkey ed25519");
    const halves = await artifactsOf("genkey ed25519 | out @kp");
    const pub = halves.find((a) => (a.tags || []).includes("public"));
    expect(kindOf(tip).id).toBe("keypair");
    expect(kindOf(pub).id).toBe("keypair-public");
    expect(kindOf(tip).label).not.toBe(kindOf(pub).label);
  });

  it("can still copy the fingerprint and the public line — both public facts", async () => {
    // The tile displays them, so a disabled button reading "carries no key to
    // fingerprint" would be a sentence about the artifact and a lie about the
    // key. §34b is about where a value lands, not how sensitive its neighbour
    // is: these derive from the public half only.
    const [tip] = await artifactsOf("genkey ed25519");
    const ctx = { artifact: tip, masked: true };
    expect(actionById("key.copyFingerprint").available(ctx)).toBe(true);
    expect(actionById("key.copyPublicLine").available(ctx)).toBe(true);

    const written = [];
    const services = { clipboard: { write: (t) => written.push(t) } };
    await actionById("key.copyFingerprint").run({ artifact: tip, services });
    await actionById("key.copyPublicLine").run({ artifact: tip, services });
    expect(written[0]).toMatch(/^SHA256:/);
    expect(written[1]).toMatch(/^ssh-ed25519 /);
    // Nothing derived from the private half can appear in what was copied.
    for (const line of written) expect(line).not.toMatch(/"d"/);
  });

  it("refuses Copy and Download in the sentences the table already owns", async () => {
    const [tip] = await artifactsOf("genkey ed25519");
    const ctx = { artifact: tip, masked: true };
    for (const id of ["copy", "download"]) {
      const verdict = actionById(id).available(ctx);
      expect(verdict, id).not.toBe(true);
      expect(verdict.disabled, id).toMatch(/was not asked for/);
      expect(verdict.disabled, id).toMatch(/out @label/);
    }
  });
});

describe("the two halves of `out` share no marker naming a half", () => {
  /**
   * Every word on an artifact that names a key half, from wherever it rides.
   *
   * Collected as a *set* rather than asserted as two literals, and gathered
   * from `tags` and every string in `pipeType` rather than from one named
   * field — so a half-word later added to both halves, in either place, fails
   * here. Two literal assertions would both still pass; one kind claiming both
   * halves is the whole failure mode (7d563cd).
   */
  const HALF_WORDS = ["public", "private", "secret"];
  const halfMarkers = (a) =>
    new Set(
      [
        ...(a.tags || []),
        ...Object.values(a.pipeType || {}).filter((v) => typeof v === "string"),
      ]
        .map(String)
        .filter((w) => HALF_WORDS.includes(w))
    );

  it("gives each half exactly its own word", async () => {
    const arts = await artifactsOf("genkey ed25519 | out @kp");
    const priv = arts.find((a) => (a.tags || []).includes("private"));
    const pub = arts.find((a) => (a.tags || []).includes("public"));
    expect(priv, "no private half emitted").toBeTruthy();
    expect(pub, "no public half emitted").toBeTruthy();
    expect([...halfMarkers(priv)]).toEqual(["private"]);
    expect([...halfMarkers(pub)]).toEqual(["public"]);
  });

  it("shares none of them, whatever else the two carry", async () => {
    const arts = await artifactsOf("genkey ec/p256 | out @kp");
    const priv = arts.find((a) => (a.tags || []).includes("private"));
    const pub = arts.find((a) => (a.tags || []).includes("public"));
    const shared = [...halfMarkers(priv)].filter((w) => halfMarkers(pub).has(w));
    expect(shared, `both halves carry: ${shared.join(", ")}`).toEqual([]);
    // Both must actually carry one — disjointness is trivially true of two
    // empty sets, which is how this assertion would rot into a tautology.
    expect(halfMarkers(priv).size).toBeGreaterThan(0);
    expect(halfMarkers(pub).size).toBeGreaterThan(0);
  });

  it("resolves the two to different kinds", async () => {
    const arts = await artifactsOf("genkey ed25519 | out @kp");
    const ids = arts.map((a) => kindOf(a).id).sort();
    expect(ids).toEqual(["keypair-private", "keypair-public"]);
  });
});

describe("no placeholder body survives on a key path", () => {
  it("emits no bracketed stub for any dangling key value", async () => {
    // `[keypair — use out or export before emitting]` and its siblings were
    // instructions rendered where a value goes. A body is a value or it is
    // absent; it is never a note to the reader about the recipe.
    for (const src of [
      "genkey ed25519",
      "genkey ec/p256",
      "genkey x25519",
      "genkey aes/256",
      "genkey ed25519 | out @kp",
    ]) {
      for (const a of await artifactsOf(src)) {
        expect(a.content, `${src} → ${a.label}`).not.toMatch(/^\[.*\]$/);
      }
    }
  });
});
