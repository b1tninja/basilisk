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
  expiryInstant,
  expiryNote,
  filterRecipientRows,
  openpgpKeyForm,
  openpgpKeySummary,
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
  it("maps a real OpenPGP symmetric ciphertext into its packets", async () => {
    const arts = await run(
      '"secret data" | utf8 | gpg.symencrypt mode=passphrase passphrase="hunter2"'
    );
    // `role: "ciphertext"`, which is what this artifact has always been: it
    // stamped `envelope` on both modes until the ceremony word was given back
    // to the master-key wrap alone. The read-out is the same either way —
    // `ciphertext` and `envelope` both draw `PacketMapCard` — so nothing about
    // this test's subject moved, only the word it looks the artifact up by.
    const env = arts.find((a) => a.role === "ciphertext");
    const summary = packetSummary(env.content);
    expect(summary.rows.length).toBeGreaterThan(0);
    // A passphrase-sealed body is protected by an SKESK, not a PKESK. That
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

describe("filterRecipientRows — which rows match, not how they are drawn", () => {
  const rows = [
    {
      fingerprint: "AABBCCDD11223344AABBCCDD11223344AABBCCDD",
      label: "Dana Okonkwo",
      email: "dana@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "99887766554433229988776655443322998877 66",
      label: "Sam Reyes",
      email: "sam@example.org",
      approvalState: "unverified",
      encryptCapable: false,
    },
  ];

  it("returns the rows untouched for an empty query", () => {
    // The same array, not a copy — the unfiltered case is every case until
    // someone types, and it should cost nothing.
    expect(filterRecipientRows(rows, "")).toBe(rows);
    expect(filterRecipientRows(rows, "   ")).toBe(rows);
  });

  it("matches label and email, case-insensitively", () => {
    expect(filterRecipientRows(rows, "DANA").map((r) => r.label)).toEqual([
      "Dana Okonkwo",
    ]);
    expect(filterRecipientRows(rows, "sam@example").map((r) => r.label)).toEqual([
      "Sam Reyes",
    ]);
  });

  /**
   * The reason this is a read-out and not a `String.includes` in the card.
   *
   * A fingerprint is *displayed* grouped and copied from wherever the user has
   * it — a `gpg --list-keys` line, an email, this tile — so the spaces are
   * arbitrary on both sides. The second fixture row carries one *inside* the
   * stored value, which is what a real hkp response looks like. A card
   * comparing the strings as typed matches nothing here and reads as "no such
   * recipient" for the one field people paste rather than type.
   */
  it("ignores grouping spaces on both sides of a fingerprint", () => {
    expect(filterRecipientRows(rows, "AABB CCDD").map((r) => r.label)).toEqual([
      "Dana Okonkwo",
    ]);
    expect(filterRecipientRows(rows, "998877665544").map((r) => r.label)).toEqual([
      "Sam Reyes",
    ]);
    expect(filterRecipientRows(rows, "3322 9988").map((r) => r.label)).toEqual([
      "Sam Reyes",
    ]);
  });

  it("never reorders, because the order is the one gpg.encrypt will walk", () => {
    expect(filterRecipientRows(rows, "example").map((r) => r.label)).toEqual([
      "Dana Okonkwo",
      "Sam Reyes",
    ]);
  });

  it("is total on rubbish", () => {
    expect(filterRecipientRows(null, "x")).toEqual([]);
    expect(filterRecipientRows([{}], "x")).toEqual([]);
  });
});

/**
 * The armor parse, which had no test at all while it lived inside
 * `OpenPgpKeyCard` — the suite is `environment: "node"`, so nothing in it could
 * reach a `useEffect`. That is the module header's stated reason for existing,
 * and this is the case that proves it: the caption defect below shipped, was
 * fixed, and was fixed *again*, without a single assertion ever running.
 */
describe("openpgpKeyForm — one source for which half the armor holds", () => {
  it("reads both halves off the header, synchronously", async () => {
    const arts = await run(
      'gpg.genkey name="Dana Okonkwo" email="dana@example.org" | out $k'
    );
    const pub = arts.find((a) => a.role === "public-key");
    const priv = arts.find((a) => (a.tags || []).includes("private"));
    expect(openpgpKeyForm(pub.content)).toBe("public");
    // The defect: `parsed?.isPrivate ? "private" : "public"` said **public**
    // here for the whole of the lazy import, and forever on armor that will
    // not parse. Nothing about this answer waits for anything.
    expect(openpgpKeyForm(priv.content)).toBe("private");
  });

  it("says nothing rather than guessing at armor that is neither", () => {
    expect(openpgpKeyForm("-----BEGIN PGP MESSAGE-----\n\nxxxx\n")).toBeNull();
    expect(openpgpKeyForm("ssh-ed25519 AAAA nobody@nowhere")).toBeNull();
    expect(openpgpKeyForm("")).toBeNull();
    expect(openpgpKeyForm(undefined)).toBeNull();
  });
});

describe("openpgpKeySummary", () => {
  it("reads uid, fingerprint and dates off a key this build produced", async () => {
    const arts = await run(
      'gpg.genkey name="Dana Okonkwo" email="dana@example.org" | out $k'
    );
    const pub = arts.find((a) => a.role === "public-key");
    const summary = await openpgpKeySummary(pub.content);
    expect(summary.uid).toBe("Dana Okonkwo <dana@example.org>");
    expect(summary.form).toBe("public");
    expect(summary.fingerprint).toMatch(/^[0-9A-F]{40}$/);
    expect(summary.created).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    // `gpg.genkey` sets no expiry, and `getExpirationTime` answers Infinity
    // for that — not a Date, so it is null here and the card says "does not
    // expire" in words rather than drawing a date nobody chose.
    expect(summary.expires).toBeNull();
    expect(summary.expiresAt).toBeNull();
  });

  it("reports the same half `openpgpKeyForm` does, because it calls it", async () => {
    const arts = await run(
      'gpg.genkey name="Dana Okonkwo" email="dana@example.org" | out $k'
    );
    for (const a of arts.filter((x) => String(x.content).includes("BEGIN PGP"))) {
      expect((await openpgpKeySummary(a.content)).form).toBe(openpgpKeyForm(a.content));
    }
  });

  /**
   * The whole D5 path for the OpenPGP card, from a key this build generated.
   *
   * `expiresAt` was added to the summary for exactly this and had no consumer
   * until now. Asserting it against `expiryNote` here rather than against a
   * hand-written armor fixture is what stops the card's verdict rotting: the
   * key is minted `expiry=` seconds from *this* run, so the arithmetic is
   * re-proved every time the suite runs instead of on the day it was written
   * (D3's lesson, applied to the other card).
   */
  it("hands the card an instant a verdict can be read off", async () => {
    const arts = await run(
      'gpg.genkey name="Dana Okonkwo" email="dana@example.org" expiry=777600 | out $k'
    );
    const pub = arts.find((a) => a.role === "public-key");
    const summary = await openpgpKeySummary(pub.content);
    // 9 days: the date is still drawn, and the verdict sits beside it.
    expect(summary.expires).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(summary.expiresAt).toBeGreaterThan(Date.now());
    expect(expiryNote(summary.expiresAt)).toEqual({
      text: "expires in 9 days",
      severity: "warn",
    });
    // And the card asks for no second parse: the instant is on the summary it
    // already has, which is why `expires` and the verdict cannot disagree.
    expect(new Date(summary.expiresAt).toISOString().slice(0, 10)).toBe(summary.expires);
  }, 60_000);

  it("says nothing about a key that does not expire", async () => {
    const arts = await run('gpg.genkey email="dana@example.org" | out $k');
    const pub = arts.find((a) => a.role === "public-key");
    const summary = await openpgpKeySummary(pub.content);
    // The card's "does not expire" stands alone — a verdict here would be a
    // warning about a deadline that does not exist.
    expect(expiryNote(summary.expiresAt)).toBeNull();
  }, 60_000);

  it("returns null for armor that will not parse, rather than throwing", async () => {
    expect(
      await openpgpKeySummary("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot base64\n")
    ).toBeNull();
    expect(await openpgpKeySummary("not armor at all")).toBeNull();
    expect(await openpgpKeySummary("")).toBeNull();
  });
});

/**
 * The verdict half of §48b/D5. The thresholds and the wording are asserted in
 * `gpg-key-binder.test.js`, unchanged by the move; what is new here is the
 * *instant*, because the three things that expire in this app state it three
 * different ways and only one of them is a number.
 */
describe("expiryInstant — one reading of 'when does this stop being valid'", () => {
  const AT = Date.UTC(2026, 7, 31, 12, 0, 0);

  it("takes the ISO string a DTLS certificate carries", async () => {
    // `rtc-ops.js` serializes `cert.expires` through `toISOString()`, so the
    // certificate panel's value is a string where the key card's is a number.
    // A panel that reached for `Date.parse` itself would be the second
    // derivation of one fact, which is the thing the boundary calls a bug.
    expect(expiryInstant(new Date(AT).toISOString())).toBe(AT);
    expect(expiryInstant(AT)).toBe(AT);
    expect(expiryInstant(new Date(AT))).toBe(AT);
  });

  it("calls an unreadable date no known expiry, never an expired one", () => {
    // The dangerous rounding: a date we cannot parse must not fall to 0 and
    // read as 1970. A certificate we cannot describe has not expired.
    expect(expiryInstant("soon")).toBeNull();
    expect(expiryInstant("")).toBeNull();
    expect(expiryInstant(null)).toBeNull();
    expect(expiryInstant(undefined)).toBeNull();
    expect(expiryInstant(NaN)).toBeNull();
    expect(expiryNote("soon", AT)).toBeNull();
  });

  it("gives a string and a number the same verdict", async () => {
    const in9 = AT + 9 * 86_400_000;
    expect(expiryNote(new Date(in9).toISOString(), AT)).toEqual(
      expiryNote(in9, AT)
    );
    expect(expiryNote(in9, AT)).toEqual({ text: "expires in 9 days", severity: "warn" });
  });

  it("stays tier 1 — a verdict that cannot differ one second later", () => {
    // §47b's test for which tier a live fact belongs in: if re-rendering a
    // second later cannot change the text, it needs no timer. This is what
    // licenses `OpenPgpKeyCard` and `CertificatePanel` to call it at render
    // and hold no interval.
    const in9 = AT + 9 * 86_400_000;
    expect(expiryNote(in9, AT)).toEqual(expiryNote(in9, AT + 1000));
  });
});

describe("sshsigSummary", () => {
  it("reads the envelope off a signature this build produced", async () => {
    const arts = await run(
      'genkey ed25519 | out $id\n\n"msg" | utf8 | ssh.sign key=$id namespace=git | out $sig'
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
    const arts = await run('"plain" | utf8 | out $msg\n\nrun.receipt label="ceremony" | out $r');
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
    const arts = await run("random 32 | sss.split threshold=2 shares=3 | out $s");
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
