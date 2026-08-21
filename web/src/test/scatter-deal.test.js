/**
 * `scatter` at run time — the pairing itself, over a live (stubbed-transport)
 * exchange: share i to member i in canonical audience order, derived on this
 * machine and chosen by nobody.
 *
 * The harness is `quorum-lifecycle.test.js`'s: `NotebookSession` is replaced
 * with a fake whose peers map and `sendChatTo` the test reads, so
 * `execQuorumOpen`, `scatterRoom`, `execQuorumSend` and the engine's scatter
 * loop all run their real bodies. The OpenPGP keys are real — `seal` really
 * encrypts, and the proof of its pairing is decryption: each member's own
 * private key opens exactly the envelope holding the share whose index is
 * that member's position in the canonical audience.
 *
 * This is the file that catches a reversed pairing. Mutating the engine's zip
 * to `members[members.length - 1 - i]` makes share 1 ride to the last member,
 * and the assertions here name the mismatch — which is the property nothing
 * else in the product would report.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { decrypt, generateKey, readMessage, readPrivateKey } from "openpgp";

/** A `NotebookSession` with the shape quorum-ops consumes (see quorum-lifecycle). */
const { FakeSession } = vi.hoisted(() => {
  class FakeSession {
    /** @type {FakeSession[]} */
    static instances = [];
    static onStart = null;
    constructor(opts) {
      this.opts = opts;
      this.peers = new Map();
      this.sent = [];
      FakeSession.instances.push(this);
    }
    async start() {
      await FakeSession.onStart?.(this);
    }
    stop() {}
    async sendChat(text) {
      this.sent.push({ to: "", text });
      return this.verified("").length;
    }
    async sendChatTo(to, text) {
      const wrote = this.verified(to).length;
      if (!wrote) throw new Error(`no verified peer matches ${to}`);
      this.sent.push({ to, text });
      return wrote;
    }
    verified(prefix) {
      const want = String(prefix || "").replace(/\s+/g, "").toUpperCase();
      return [...this.peers.entries()]
        .filter(
          ([f, p]) =>
            p.status === "connected" &&
            p.kcVerified &&
            (!want || String(f).toUpperCase().startsWith(want))
        )
        .map(([f]) => f);
    }
    connect(fpr) {
      this.peers.set(fpr, {
        fingerprint: fpr,
        status: "connected",
        pgpVerified: true,
        kcVerified: true,
        link: null,
        channel: null,
      });
      this.opts.onRoster?.(this.peers);
    }
  }
  return { FakeSession };
});

/** Armored public keys `seal`'s recipient loading resolves — see beforeAll. */
const { armorByFpr } = vi.hoisted(() => ({ armorByFpr: new Map() }));

vi.mock("../lib/notebook/session.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, NotebookSession: FakeSession };
});

// `seal` delegates to `gpg.encrypt to=<fingerprint>`, whose key loading goes
// through `loadRecipientKey` (pubkey cache → keyserver). The members' keys
// here were minted in this process, so the lookup answers from the map — the
// resolution *path* is the real one, only the keyserver behind it is local.
vi.mock("../lib/recipient-picker.js", () => ({
  loadRecipientKey: async (fpr) => {
    const armoredKey = armorByFpr.get(String(fpr).toUpperCase());
    return armoredKey
      ? { armoredKey }
      : { error: `no key for ${fpr} in this test's keyring` };
  },
}));

/**
 * The unlocked-key cache `gpg.decrypt` reads, standing in for a person having
 * pressed Unlock in My Keys — which is what `openQuorumSession` does for real
 * when a session starts (`execAgentUnlock` → `unlockVaultForUse` → `sessionPut`).
 * Only the *storage* is faked: the decrypt path, the key parsing and the
 * `zeroKeyMaterial` wipe are the shipped ones.
 */
const { sessionKeys } = vi.hoisted(() => ({ sessionKeys: new Map() }));

vi.mock("../lib/vault-session.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    sessionList: () => [...sessionKeys.keys()].map((fingerprint) => ({ fingerprint })),
    sessionGet: (fpr) => sessionKeys.get(String(fpr).toUpperCase()) || null,
  };
});

globalThis.window = /** @type {any} */ (new EventTarget());
globalThis.RTCPeerConnection = class {};

const q = await import("../lib/toolkit/quorum-ops.js");
const { runRecipe } = await import("../lib/toolkit/engine.js");
const { parseRecipe } = await import("../lib/toolkit/recipe.js");
const { readShareHeader } = await import("../lib/slip39/blip39.js");

/** @type {{ fpr: string, armoredPrivate: string }[]} member keys */
let keys = [];
/** The audience in canonical order — ascending whole fingerprint, deduped. */
let members = [];
/** This machine's key (an arbitrary member — the order must not care). */
let self;

beforeAll(async () => {
  const made = await Promise.all(
    ["a", "b", "c"].map((who) =>
      generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ email: `${who}@scatter.test` }],
        format: "armored",
      })
    )
  );
  keys = [];
  for (const k of made) {
    const priv = await readPrivateKey({ armoredKey: k.privateKey });
    const fpr = priv.getFingerprint().toUpperCase();
    keys.push({ fpr, armoredPrivate: k.privateKey });
    armorByFpr.set(fpr, k.publicKey);
  }
  members = keys.map((k) => k.fpr).sort();
  self = keys[0];
}, 60_000);

afterEach(() => {
  q.closeQuorumExchange("closed");
  FakeSession.instances = [];
  FakeSession.onStart = null;
  sessionKeys.clear();
});

/** Open the room as `self`, with the given other members connected+verified. */
async function openRoom(connectedFprs) {
  FakeSession.onStart = (s) => {
    for (const f of connectedFprs) s.connect(f);
  };
  await q.execQuorumOpen(
    { to: members.join(" ") },
    { getFingerprint: () => self.fpr.toLowerCase() },
    null,
    "creator"
  );
  return FakeSession.instances.at(-1);
}

/** Run one recipe source through the real engine. */
async function run(src, bindings = {}) {
  const { ast, errors } = parseRecipe(src);
  expect(errors, src).toEqual([]);
  return runRecipe(ast, bindings);
}

const others = () => members.filter((f) => f !== self.fpr);
const positionOf = (fpr) => members.indexOf(fpr) + 1;

describe("send to=each delivers share i to member i", () => {
  it("pairs by canonical audience order, and the dealer's own share never crosses a wire", async () => {
    const session = await openRoom(others());
    await run(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - send to=each"
    );

    // One wire send per *other* member — the pair whose member is this
    // machine stays here ("mine" is the one that never crossed a wire).
    expect(session.sent).toHaveLength(members.length - 1);
    expect(session.sent.map((s) => s.to).sort()).toEqual(others().sort());

    for (const { to, text } of session.sent) {
      const header = readShareHeader(text);
      expect(header, `sent to ${to} was not a share mnemonic`).toBeTruthy();
      // The security property: share i to member i, i = the member's
      // position in canonical audience order. A reversed pairing sends
      // share 1 to the last member, and this line is what names it.
      expect(
        header.index,
        `member ${to} (position ${positionOf(to)}) received share ${header.index}`
      ).toBe(positionOf(to));
    }
    // And the dealer's own share is the one absent from the wire.
    const wireIndexes = session.sent.map((s) => readShareHeader(s.text).index);
    expect(wireIndexes).not.toContain(positionOf(self.fpr));
  });
});

describe("seal to=each encrypts share i to member i's key", () => {
  it("each member's own private key opens exactly the envelope holding their share", async () => {
    await openRoom(others());
    const artifacts = await run(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - seal to=each | out $sealed"
    );

    const sealed = artifacts.filter((a) => a.role === "share");
    expect(sealed).toHaveLength(members.length);
    // The artifact record already names the addressee — whole, never a prefix.
    expect(sealed.map((a) => a.recipientFingerprint)).toEqual(members);
    // And again in `traits`, which is the copy that reaches a reader: the three
    // projections between here and a tile drop every field they do not name and
    // `recipientFingerprint` is named by none of them. The share tile shows this
    // one — see `sealed-share-recipient.test.js`, which owns the rendering half.
    expect(sealed.map((a) => a.traits?.sealedTo)).toEqual(
      members.map((m) => m.toUpperCase())
    );

    // The cryptographic proof, not just the record: decrypt each envelope
    // with its member's own key and read the share index off the mnemonic.
    for (const art of sealed) {
      const member = keys.find((k) => k.fpr === art.recipientFingerprint);
      const opened = await decrypt({
        message: await readMessage({ armoredMessage: art.content }),
        decryptionKeys: await readPrivateKey({
          armoredKey: member.armoredPrivate,
        }),
      });
      const header = readShareHeader(String(opened.data));
      expect(header).toBeTruthy();
      expect(
        header.index,
        `${member.fpr} (position ${positionOf(member.fpr)}) can open share ${header.index}`
      ).toBe(positionOf(member.fpr));
    }
  });
});

describe("seal to=each | send to=each — the deal the owner asked for", () => {
  /**
   * The whole requirement in one body: **each peer gets a share of the same
   * key, sealed to that peer, delivered to that peer and nobody else.**
   *
   * Before the pair survived `seal`, this line did not compile — `seal`'s
   * armored output named nobody, so `send` had no pair to read and refused
   * with a type error. The generated ceremony therefore dealt mnemonics in the
   * clear under the transport's own key, which is what `6388ad0` recorded as
   * deferred: a holder had no way to open a sealed share, so nothing sealed
   * them.
   *
   * Two independent proofs, because the record and the cryptography are two
   * claims: the wire carries armor addressed to the member whose share it is,
   * and that member's own private key — nobody else's — opens it onto the
   * share index that member's position in the canonical audience entitles them
   * to.
   */
  it("puts armor on the wire that only its own member can open", async () => {
    const session = await openRoom(others());
    await run(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - seal to=each | send to=each"
    );

    // One wire send per *other* member: the pair whose member is this machine
    // still never crosses a wire, sealed or not.
    expect(session.sent).toHaveLength(members.length - 1);
    expect(session.sent.map((s) => s.to).sort()).toEqual(others().sort());

    for (const { to, text } of session.sent) {
      expect(text, `what reached ${to} was not an OpenPGP message`).toContain(
        "-----BEGIN PGP MESSAGE-----"
      );
      // Not a mnemonic any more — the thing this whole change is about. A
      // readable share on the wire is what the unsealed deal put there.
      expect(readShareHeader(text)).toBeFalsy();

      const opened = await decrypt({
        message: await readMessage({ armoredMessage: text }),
        decryptionKeys: await readPrivateKey({
          armoredKey: keys.find((k) => k.fpr === to).armoredPrivate,
        }),
      });
      const header = readShareHeader(String(opened.data));
      expect(header, `${to} opened their message onto something else`).toBeTruthy();
      expect(
        header.index,
        `member ${to} (position ${positionOf(to)}) received share ${header.index}`
      ).toBe(positionOf(to));

      // And **only** that member: every other key in the room is refused by
      // the same message. Sealing to the room instead of to the person would
      // pass every assertion above and fail this one.
      for (const other of keys.filter((k) => k.fpr !== to)) {
        await expect(
          decrypt({
            message: await readMessage({ armoredMessage: text }),
            decryptionKeys: await readPrivateKey({ armoredKey: other.armoredPrivate }),
          }),
          `${other.fpr} could open the message sealed to ${to}`
        ).rejects.toThrow();
      }
    }
  });

  /**
   * What the self-pair costs, and why the generated deal ends with a decrypt.
   *
   * `seal to=each` has no exception for the pair whose member is this machine:
   * it seals every share to the key of the person it is for, and for one pair
   * that person is the dealer. Skipping it would be worse than pointless — the
   * shipped `- seal to=each | out $sealed | publish` would then publish the
   * dealer's own share in the clear — so the dealer's retained payload is an
   * OpenPGP message to themselves, and the honest way back to the mnemonic is
   * the one every holder uses: open it with your own key.
   */
  it("leaves the dealer holding their own share, opened with their own key", async () => {
    const { createSlotRegistry } = await import("../lib/toolkit/slot-registry.js");
    const slotRegistry = createSlotRegistry();
    sessionKeys.set(self.fpr, self.armoredPrivate);
    const session = await openRoom(others());
    const { ast, errors } = parseRecipe(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n" +
        "  - seal to=each | send to=each | gpg.decrypt | out $share"
    );
    expect(errors).toEqual([]);
    await runRecipe(ast, {}, { slotRegistry });

    // The decrypt ran on exactly one pair — the one that stayed. A delivered
    // pair's pipe ends at `send`, so nothing else reached it.
    expect(session.sent).toHaveLength(members.length - 1);

    const mine = slotRegistry.resolve("$share");
    expect(mine.type, `the slot holds ${mine.type}`).toBe("text");
    // A mnemonic, not the armor it was a moment ago: `$share` is the same
    // shape on the dealer as `$share-i` is on every holder, which is what the
    // recovery notebook reads back on whichever machine writes it.
    expect(String(mine.data)).not.toContain("BEGIN PGP MESSAGE");
    const header = readShareHeader(String(mine.data));
    expect(header, "the dealer's slot does not hold a share mnemonic").toBeTruthy();
    expect(header.index).toBe(positionOf(self.fpr));
  });

  /**
   * The holder's half, which is the half that did not exist. `gpg.decrypt` was
   * a source that read the Inputs panel and nothing else, so
   * `quorum.recv from=<dealer> | gpg.decrypt` discarded the message that
   * arrived and decrypted whatever had been pasted — a sealed share could be
   * sent and not opened.
   */
  it("opens a received share on the holder's side, with the holder's own key", async () => {
    const { createSlotRegistry } = await import("../lib/toolkit/slot-registry.js");
    const holder = keys.find((k) => k.fpr === others()[0]);
    const slotRegistry = createSlotRegistry();

    // Deal from this machine, and take the envelope that went to that holder
    // off the wire — nothing here reaches into the split.
    const session = await openRoom(others());
    await run(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - seal to=each | send to=each"
    );
    const envelope = session.sent.find((s) => s.to === holder.fpr).text;
    q.closeQuorumExchange("closed");

    // Now stand on the holder's machine: their key is unlocked, the dealer's
    // message arrives down the pipe, and the recipe names no panel at all.
    sessionKeys.set(holder.fpr, holder.armoredPrivate);
    const { ast, errors } = parseRecipe("input | gpg.decrypt | out $share-2");
    expect(errors).toEqual([]);
    await runRecipe(ast, { inputs: { text: { value: envelope } } }, { slotRegistry });

    const got = slotRegistry.resolve("$share-2");
    const header = readShareHeader(String(got.data));
    expect(header, "the holder's slot does not hold a share mnemonic").toBeTruthy();
    expect(header.index).toBe(positionOf(holder.fpr));
  });
});

describe("the deal refuses before it starts", () => {
  it("an unverified room member stops the deal, named whole", async () => {
    const absent = others()[1];
    await openRoom([others()[0]]); // one of the two others never verified
    await expect(
      run("random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - send to=each")
    ).rejects.toThrow(new RegExp(`${absent}.*not key-confirmed`, "s"));
  });

  it("a run-time count mismatch names both numbers", async () => {
    await openRoom(others());
    await expect(
      run("random 32 | sss.split 2/2 | blip39 | scatter to=room\n  - send to=each")
    ).rejects.toThrow(/2 shares against a room of 3 members/);
  });

  it("without a live exchange there is no room to derive", async () => {
    await expect(
      run("random 32 | sss.split 2/3 | blip39 | scatter to=room\n  - send to=each")
    ).rejects.toThrow(/no live exchange/);
  });
});

describe("the body's slots keep foreach's bundle rule", () => {
  it("a body out binds once, to a bundle of every pair's value, in indexed order", async () => {
    await openRoom(others());
    const artifacts = await run(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - :key | out $who"
    );
    // One tile per pair, and the tile order is the pairing order — the
    // members, ascending, exactly as `canonicalAudience` returns them.
    const tiles = artifacts.filter((a) => a.stepName === "out");
    expect(tiles.map((a) => a.content)).toEqual(members);
  });
});

describe("out after send to=each binds the dealer's own share, once", () => {
  it("the slot holds the value itself — the one pair whose member is this machine", async () => {
    // The carve-out from the bundle rule, decided by the body's syntax: a
    // delivered pair's pipe ends at `send`, so exactly one value — the share
    // that never crossed a wire — reaches the `out`, and the slot binds it
    // directly rather than as a bundle-of-one. This is what the generated
    // deal's `$share` is, and what the recovery's `$share | quorum.send`
    // reads back, so a bundle here would break the second notebook on the
    // dealer's machine while every unit assertion about the wire still
    // passed.
    const { createSlotRegistry } = await import("../lib/toolkit/slot-registry.js");
    const slotRegistry = createSlotRegistry();
    await openRoom(others());
    const { ast, errors } = parseRecipe(
      "random 32 | sss.split 2/3 | blip39.encode | scatter to=room\n  - send to=each | out $share"
    );
    expect(errors).toEqual([]);
    await runRecipe(ast, {}, { slotRegistry });

    const mine = slotRegistry.resolve("$share");
    expect(mine.type, `the slot holds ${mine.type}`).toBe("text");
    const header = readShareHeader(String(mine.data));
    expect(header, "the slot does not hold a share mnemonic").toBeTruthy();
    // And it is *this machine's* share: the index is this session's position
    // in the canonical audience — the pairing rule, read back off the one
    // value that stayed.
    expect(header.index).toBe(positionOf(self.fpr));
  });
});
