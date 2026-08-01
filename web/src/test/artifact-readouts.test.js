/**
 * The §37 tile read-outs (design_handoff_artifact_actions).
 *
 * These functions turn an artifact's body into what its tile shows, and the
 * property that matters most is that they are **total**: a malformed body must
 * degrade to the raw text the tile would have shown anyway (§32d), never throw
 * and never blank a cell for a computation that in fact succeeded. So every
 * function gets a garbage case as well as a real one, and the real cases come
 * from `runRecipe` rather than from a hand-written fixture — the design's
 * description of what the engine emits has been wrong more than once.
 */
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import {
  packetSummary,
  qrDataUri,
  receiptSummary,
  recipientRows,
  shareIdentity,
  sshsigSummary,
} from "../lib/toolkit/artifact-readouts.js";

/** Run a recipe and hand back its artifacts. */
const run = async (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.ok, (validation.errors || []).map((e) => e.message).join(" · ")).toBe(
    true
  );
  return runRecipe(ast, {});
};

describe("packetSummary — the framing, never the contents", () => {
  it("maps a real OpenPGP envelope into its packets", async () => {
    const arts = await run(
      '"secret data" | utf8 | gpg.symencrypt mode=passphrase passphrase="hunter2"'
    );
    const env = arts.find((a) => a.role === "envelope");
    const summary = packetSummary(env.content);
    expect(summary.rows.length).toBeGreaterThan(0);
    // A passphrase envelope is protected by an SKESK, not a PKESK. That
    // distinction is the whole reason the tile draws packets: it is the
    // difference between "a key can open this" and "a passphrase can".
    expect(summary.rows.map((r) => r.name)).toContain("SKESK");
    expect(summary.bytes).toBeGreaterThan(0);
  }, 60_000);

  it("returns null for anything that is not armored, rather than throwing", () => {
    expect(packetSummary("")).toBeNull();
    expect(packetSummary("not a message")).toBeNull();
    expect(packetSummary("-----BEGIN PGP MESSAGE-----\n!!!!\n-----END PGP MESSAGE-----")).toBeNull();
  });
});

describe("recipientRows", () => {
  it("reads the five fields the engine serializes", () => {
    const rows = recipientRows(
      JSON.stringify([
        {
          fingerprint: "AABBCCDD",
          label: "Dana",
          email: "dana@example.com",
          approvalState: "approved",
          encryptCapable: false,
        },
      ])
    );
    expect(rows).toEqual([
      {
        fingerprint: "AABBCCDD",
        label: "Dana",
        email: "dana@example.com",
        approvalState: "approved",
        encryptCapable: false,
      },
    ]);
  });

  it("drops a row with no fingerprint", () => {
    // The fingerprint is the only field that identifies a recipient, so a row
    // without one must not be shown as one.
    expect(recipientRows(JSON.stringify([{ label: "nobody" }]))).toBeNull();
  });

  it("returns null for a body that is not a list", () => {
    expect(recipientRows("{}")).toBeNull();
    expect(recipientRows("not json")).toBeNull();
  });
});

describe("sshsigSummary", () => {
  it("reads the envelope off a signature this build produced", async () => {
    const arts = await run(
      'genkey ed25519 | out @id\n\n"msg" | utf8 | ssh.sign key=@id namespace=git | out @sig'
    );
    const sig = arts.find((a) => a.label === "sig");
    const summary = await sshsigSummary(sig.content);
    // Namespace leads because it is the field that silently decides whether a
    // signature verifies at all — a `git` signature never verifies as `file`.
    expect(summary.namespace).toBe("git");
    expect(summary.sigType).toBe("ssh-ed25519");
    expect(summary.keyType).toBe("ssh-ed25519");
    expect(summary.hashAlg).toBe("sha512");
    // §28a: the id in the shape `ssh-keygen -lf` prints, so it can be compared
    // against an allowed_signers line character for character.
    expect(summary.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  }, 60_000);

  it("returns null for armor that is not an sshsig envelope", async () => {
    expect(await sshsigSummary("")).toBeNull();
    expect(await sshsigSummary("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----")).toBeNull();
  });
});

describe("receiptSummary", () => {
  it("reduces a real receipt to the rows run.verify walks", async () => {
    const arts = await run('"plain" | utf8 | out @msg\n\nrun.receipt label="ceremony" | out @r');
    const receipt = arts.find((a) => a.role === "receipt");
    const summary = receiptSummary(receipt.content);
    expect(summary.label).toBe("ceremony");
    expect(summary.recipeDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(summary.cells.length).toBeGreaterThan(0);
    expect(summary.artifacts).toBe(
      summary.cells.reduce((n, c) => n + c.outputs.length, 0)
    );
  }, 60_000);

  it("returns null rather than throwing on a receipt it cannot read", () => {
    // A v1 receipt throws inside parseReceipt; the tile then shows the raw
    // JSON, and `run.verify` owns the sentence explaining the version (§38c).
    expect(receiptSummary(JSON.stringify({ kind: "basilisk.run-receipt", v: 1 }))).toBeNull();
    expect(receiptSummary("not json")).toBeNull();
    expect(receiptSummary("")).toBeNull();
  });
});

describe("qrDataUri", () => {
  it("encodes an SVG as an img source", async () => {
    const arts = await run('"hello" | qr');
    const qr = arts.find((a) => a.role === "qr");
    const uri = qrDataUri(qr.content);
    expect(uri.startsWith("data:image/svg+xml;base64,")).toBe(true);
    const decoded = Buffer.from(uri.split(",")[1], "base64").toString("utf8");
    expect(decoded).toBe(qr.content);
  }, 60_000);

  it("refuses anything that is not an SVG", () => {
    // The alternative to an `<img>` is dangerouslySetInnerHTML, which would be
    // a script-injection surface for a value that came out of the pipeline.
    expect(qrDataUri("<script>alert(1)</script>")).toBeNull();
    expect(qrDataUri("")).toBeNull();
  });

  it("survives an SVG carrying non-Latin-1 characters", () => {
    // `btoa` throws on these; the encoder goes through UTF-8 bytes.
    expect(qrDataUri('<svg><title>クローン</title></svg>')).toContain("base64,");
  });
});

describe("shareIdentity — what a masked share may still say", () => {
  it("reads index and threshold off a real split", async () => {
    const arts = await run("random 32 | sss.split threshold=2 shares=3 | out @s");
    const ids = arts.map(shareIdentity);
    expect(ids.map((i) => i.index)).toEqual([1, 2, 3]);
    expect(ids.every((i) => i.threshold === 2)).toBe(true);
    expect(ids[0].flavour).toBe("raw share");
  }, 60_000);

  it("calls an encrypted share encrypted, not a mnemonic", () => {
    // A GPG-encrypted share carries `blip39` too — it is armor *around* a
    // mnemonic. Calling it a mnemonic would tell a custodian to read words off
    // a tile that holds none.
    expect(
      shareIdentity({
        tags: ["encrypted", "openpgp", "blip39"],
        traits: { shareOf: 2, threshold: 3 },
      }).flavour
    ).toBe("encrypted share");
  });

  it("returns null when there is nothing public to say", () => {
    expect(shareIdentity({})).toBeNull();
    expect(shareIdentity(null)).toBeNull();
  });
});
