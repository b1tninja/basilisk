/**
 * The two SSH key kinds (§37, design_handoff_artifact_actions).
 *
 * `ssh-format.test.js` pinned the *tags* an hour before this landed: the two
 * `ssh.encode` formats share none, so one kind can never claim both halves.
 * This file is the other end of that — the kinds those tags made safe to
 * write, and the three things they were written for: a tile that names the key
 * instead of showing a base64 run, a masked private tile that still says which
 * key it is holding, and a Download that lands under `.pub` rather than
 * `pub.txt`.
 *
 * Everything below resolves *real engine artifacts*. A kind is matched on
 * `role` + `tags`, both of which are stamped during a run and re-stamped by
 * `attachPipeMeta`, so asserting against hand-built objects would pin the
 * table against a shape nothing emits — which is exactly how `jose-token`
 * shipped matching a role no artifact carried.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { ARTIFACT_ROLES, artifactMetaFromType, typeOf } from "../lib/toolkit/types.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { ARTIFACT_KINDS, FALLBACK_KIND } from "../toolkit/artifact-kinds/registry.tsx";
import { resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";
import {
  actionsFor,
  downloadNameFor,
  ARTIFACT_ACTIONS,
} from "../lib/toolkit/artifact-actions.js";
import { sshKeySummary } from "../lib/toolkit/artifact-readouts.js";
import { sshFingerprint } from "../lib/ssh/fingerprint.js";
import { parsePublicLine } from "../lib/ssh/wire.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url)), "utf8");

const kindById = (id) => ARTIFACT_KINDS.find((k) => k.id === id);

/** Run a recipe and hand back each artifact with the kind that claims it. */
const tilesOf = async (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.errors, `fixture should compile: ${src}`).toEqual([]);
  const arts = await runRecipe(ast, {});
  return arts.map((a) => ({
    artifact: a,
    kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND),
  }));
};

describe("the halves are two roles, not one role and a tag", () => {
  it("puts both words in the frozen vocabulary", () => {
    expect(ARTIFACT_ROLES).toContain("ssh-public");
    expect(ARTIFACT_ROLES).toContain("ssh-private");
  });

  it("projects each wire form to its own role", () => {
    expect(artifactMetaFromType(typeOf("text", { kind: "ssh-public" })).role).toBe(
      "ssh-public"
    );
    expect(artifactMetaFromType(typeOf("text", { kind: "ssh-private" })).role).toBe(
      "ssh-private"
    );
  });

  it("adds no tag the two halves would share", () => {
    // The disjointness contract from `ssh-format.test.js`, asserted against
    // the projection this time: a common "ssh" tag here would put it back on
    // both artifacts and make one kind able to claim both, which is the whole
    // defect 7d563cd removed.
    const pub = artifactMetaFromType(typeOf("text", { kind: "ssh-public" })).tags;
    const priv = artifactMetaFromType(typeOf("text", { kind: "ssh-private" })).tags;
    expect(pub.filter((t) => priv.includes(t))).toEqual([]);
  });
});

describe("both emit paths land on the same kind", () => {
  /**
   * The reason two roles were needed rather than tags on `text`/`secret`.
   * `out @priv` stamps `secret` from sensitivity and a dangling tip stamps
   * `text`, so before the type owned the role these two lines produced one
   * block wearing two identities — and `ArtifactMatch.role` is exact.
   */
  it("claims a public line whether or not the recipe wrote `out`", async () => {
    for (const src of ["genkey ed25519 | ssh.encode | out @pub", "genkey ed25519 | ssh.encode"]) {
      const [tile] = await tilesOf(src);
      expect(tile.artifact.role, src).toBe("ssh-public");
      expect(tile.kind.id, src).toBe("ssh-public");
      expect(tile.artifact.sensitive, src).toBe(false);
    }
  }, 60_000);

  it("claims a private block whether or not the recipe wrote `out`", async () => {
    for (const src of [
      "genkey ed25519 | ssh.encode format=private | out @priv",
      "genkey ed25519 | ssh.encode format=private",
    ]) {
      const [tile] = await tilesOf(src);
      expect(tile.artifact.role, src).toBe("ssh-private");
      expect(tile.kind.id, src).toBe("ssh-private");
      // Never quietly unmasked by acquiring an identity.
      expect(tile.artifact.sensitive, src).toBe(true);
    }
  }, 60_000);

  it("never lets the public kind claim the private block", async () => {
    // The failure this pair of kinds exists to make impossible: a kind that
    // matched an SSH public line and also claimed the openssh-key-v1 block
    // would label a private key "SSH public key".
    const [priv] = await tilesOf("genkey ed25519 | ssh.encode format=private | out @a");
    expect(kindById("ssh-public").label).toMatch(/public/i);
    expect(resolveArtifactKind(priv.artifact, [kindById("ssh-public")], FALLBACK_KIND).id).toBe(
      "fallback"
    );
  }, 60_000);
});

describe("what the tiles say", () => {
  it("reads a public line as type, comment and ssh-keygen's fingerprint", async () => {
    const line = fixture("id_ed25519.pub").trim();
    const summary = await sshKeySummary(line);
    expect(summary.form).toBe("public");
    expect(summary.keyType).toBe("ssh-ed25519");
    expect(summary.comment).toBe("fixture@basilisk");
    // Against `ssh-keygen -lf`'s own output, via the checked-in fixture.
    expect(summary.fingerprint).toBe(
      fixture("fingerprints.txt").trim().split("\n")[0].split(/\s+/)[1]
    );
  });

  it("reads the same three facts out of a private block", async () => {
    // All three come off the public blob the container carries, which is what
    // makes them drawable while the secret is masked (§34b).
    const summary = await sshKeySummary(fixture("id_ed25519"));
    expect(summary.form).toBe("private");
    expect(summary.keyType).toBe("ssh-ed25519");
    expect(summary.comment).toBe("fixture@basilisk");
    const { blob } = parsePublicLine(fixture("id_ed25519.pub"));
    expect(summary.fingerprint).toBe(await sshFingerprint(blob));
  });

  it("agrees with ssh.fingerprint about the key the recipe just made", async () => {
    // The op and the tile deriving the same key's identity differently would
    // be worse than the tile showing nothing.
    const tiles = await tilesOf(
      "genkey ed25519 | tee { - ssh.encode format=private | out @priv } | ssh.fingerprint | out @fp"
    );
    const priv = tiles.find((t) => t.artifact.label === "priv");
    const fp = tiles.find((t) => t.artifact.label === "fp");
    const summary = await sshKeySummary(priv.artifact.content);
    expect(summary.fingerprint).toBe(String(fp.artifact.content).trim());
  }, 60_000);

  it("returns null for a passphrase-protected block instead of throwing", async () => {
    // bcrypt-KDF material this build cannot open. The kind's `empty` sentence
    // stands in; a tile must not turn an unreadable body into an error.
    await expect(sshKeySummary(fixture("id_ed25519_enc"))).resolves.toBeNull();
    expect(kindById("ssh-private").empty).toMatch(/passphrase-protected/);
  });

  it("gives the private kind a publicView that is not its full view", () => {
    // §35d for the SSH block: a masked private key tile that shows nothing is
    // a key you cannot identify without revealing it.
    const priv = kindById("ssh-private");
    expect(typeof priv.publicView).toBe("function");
    expect(priv.publicView).not.toBe(priv.view);
    // …and the public half has none, because it is never masked.
    expect(kindById("ssh-public").publicView).toBeUndefined();
  });
});

describe("what the tiles can do", () => {
  it("offers Copy fingerprint on both halves, and honours it", async () => {
    for (const [src, id] of [
      ["genkey ed25519 | ssh.encode | out @pub", "ssh-public"],
      ["genkey ed25519 | ssh.encode format=private | out @priv", "ssh-private"],
    ]) {
      const [tile] = await tilesOf(src);
      expect(tile.kind.actions, id).toContain("key.copyFingerprint");
      const action = ARTIFACT_ACTIONS.find((a) => a.id === "key.copyFingerprint");
      // Enabled *while masked* — the fingerprint is a public fact, and the
      // private tile is masked by default, which is the case it exists for.
      expect(action.available({ artifact: tile.artifact, masked: true }), id).toBe(true);
      let copied = "";
      const result = await action.run({
        artifact: tile.artifact,
        services: { clipboard: { write: (t) => void (copied = t) } },
      });
      expect(copied, id).toMatch(/^SHA256:/);
      expect(result.detail, id).toBe(copied);
      const summary = await sshKeySummary(tile.artifact.content);
      expect(copied, id).toBe(summary.fingerprint);
    }
  }, 60_000);

  it("never offers Publish on either half", () => {
    // Publishing a private key is not a thing, and by §33d that is an
    // omission — no button, nothing to reason about at runtime. The public
    // line is omitted too: `key.publish` writes an OpenPGP key to this site's
    // directory, and `publishArtifact` refuses any role but `public-key`.
    for (const id of ["ssh-public", "ssh-private"]) {
      expect(kindById(id).actions, id).not.toContain("key.publish");
    }
  });

  it("offers Add to My Keys on the private half only", () => {
    // The vault decodes an openssh-key-v1 block through `ssh.decode`
    // (`keyring-service.js`), so the button has somewhere to put it. A
    // disabled one on the public tile would teach that public keys belong in
    // a vault.
    expect(kindById("ssh-private").actions).toContain("keyring.add");
    expect(kindById("ssh-public").actions).not.toContain("keyring.add");
  });

  it("declares no action the table does not define", () => {
    for (const id of ["ssh-public", "ssh-private"]) {
      expect(actionsFor(kindById(id)).length, id).toBe(kindById(id).actions.length);
    }
  });
});

describe("what Download writes", () => {
  it("gives a public line the extension every SSH tool expects", async () => {
    const [tile] = await tilesOf("genkey ed25519 | ssh.encode | out @pub");
    // Stem from the engine's namer, extension from the kind — one namer with
    // a declared correction, never two schemes.
    expect(tile.artifact.filename).toBe("pub.txt");
    expect(downloadNameFor(tile.artifact, tile.kind)).toBe("pub.pub");
  }, 60_000);

  it("keeps a private block out of a text editor", async () => {
    const [tile] = await tilesOf("genkey ed25519 | ssh.encode format=private | out @priv");
    expect(downloadNameFor(tile.artifact, tile.kind)).toBe("priv.key");
  }, 60_000);

  it("still takes the stem the recipe chose, not the kind's", async () => {
    const [tile] = await tilesOf("genkey ed25519 | ssh.encode | out @github");
    expect(downloadNameFor(tile.artifact, tile.kind)).toBe("github.pub");
  }, 60_000);
});
