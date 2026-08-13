/**
 * The room where the creator pressed first.
 *
 * Reported as *"I can only get the connection to work if I stop the initiating
 * peer, and then rerun the notebook, then it connects."* That workaround is the
 * diagnosis: stopping and restarting the creator republishes the invite at a
 * moment the other side is already listening, which is the only thing that was
 * ever missing.
 *
 * Azure Web PubSub brokers to the connections in the group at the instant of the
 * send and keeps no backlog, so a creator that joins first broadcasts its invite
 * — and its `hello`, and its offer, and that offer's candidates — into a room
 * containing nobody. The joiner then waits for an introduction that will not
 * come again, and **says nothing while it waits**: a session that has verified no
 * invite has verified nobody, so before this change it put not one byte on the
 * wire. Two silent ends, no error on either, and a product whose copy told the
 * user to solve it by coordinating the order they pressed buttons in.
 *
 * The fix is that a joiner knocks. Everything a knock can carry is in
 * `crypto.js`: a signature over this room id and nothing else, because a joiner
 * that has verified no invite has nothing it may assert. The creator answers one
 * knock per audience member with the invite it already published — same
 * initiator, same ECDH, same nonce (`_publishInvite` argues that at length) —
 * and starts that peer's transport over, because the offer it made earlier went
 * to the same empty room the invite did.
 */
import { afterEach, describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import { sealSignalingEnvelope } from "../lib/notebook/crypto.js";
import { makeQuorumPair, until } from "./helpers/notebook-pair.js";

/** @type {any} */
let pair = null;

afterEach(async () => {
  await pair?.stop();
  pair = null;
});

/** @param {any} p */
const bothConfirmed = (p) =>
  [...p.creator.session.peers.values()].some((x) => x.kcVerified) &&
  [...p.joiner.session.peers.values()].some((x) => x.kcVerified);

describe("a joiner that arrives after the invite went out", () => {
  it("meshes anyway, without either side being restarted", async () => {
    pair = await makeQuorumPair();
    // The creator alone in the room, long enough that its invite, its `hello`
    // and its offer have all been broadcast to nobody. This is the ordering the
    // report is about.
    await pair.startCreatorFirst();

    expect(await until(() => bothConfirmed(pair))).toBe(true);
    // Nothing was reported to either end, because nothing went wrong.
    expect(pair.creator.errors).toEqual([]);
    expect(pair.joiner.errors).toEqual([]);
  });

  it("says so on the wire, and says it once", async () => {
    /** @type {string[]} */
    const wire = [];
    pair = await makeQuorumPair({
      tamper: (p, from) => {
        wire.push(`${p.type} ${from === pair?.creator?.fpr ? "creator" : "joiner"}`);
        return p;
      },
    });
    await pair.startCreatorFirst();
    await until(() => bothConfirmed(pair));
    await pair.settle();

    // One knock from the joiner — it is sent at `start`, not on a timer — and
    // exactly two invites from the creator: the broadcast nobody heard, and the
    // one answering the knock.
    expect(wire.filter((t) => t === "knock joiner")).toHaveLength(1);
    expect(wire.filter((t) => t === "invite creator")).toHaveLength(2);
    // The joiner never publishes an invite, before or after this change: it has
    // the nonce it verified and none of the material to mint one.
    expect(wire.filter((t) => t === "invite joiner")).toHaveLength(0);
  });

  it("is answered once per member, however often they knock", async () => {
    /** @type {number} */
    let invites = 0;
    pair = await makeQuorumPair({
      tamper: (p) => {
        if (p.type === "invite") invites += 1;
        return p;
      },
    });
    await pair.startCreatorFirst();
    await until(() => bothConfirmed(pair));
    await pair.settle();
    const served = invites;

    // A peer that announces itself again — a relay recycle, a reload, a bug —
    // gets silence. The bound is the set of fingerprints already served, so it
    // holds however long the session runs and whatever the interval.
    for (let i = 0; i < 5; i += 1) {
      await pair.joiner.session._broadcast({ type: "knock" });
    }
    await pair.settle();

    expect(invites).toBe(served);
    expect([...pair.creator.session._invited]).toEqual([pair.joiner.fpr]);
    // And the link that was already confirmed is still confirmed — a knock does
    // not reset a peer whose key both ends proved.
    expect(bothConfirmed(pair)).toBe(true);
  });

  it("republishes the nonce it minted, so the key transcript does not move", async () => {
    /** @type {string[]} */
    const nonces = [];
    pair = await makeQuorumPair({
      tamper: (p) => {
        if (p.type === "invite") nonces.push(String(p.nonce));
        return p;
      },
    });
    await pair.startCreatorFirst();
    await until(() => bothConfirmed(pair));
    await pair.settle();

    // `inviteNonce` is in the HKDF salt of every pairwise key, and
    // `_maybeDeriveSession` reads the live field for every peer at the moment it
    // derives. A republish that minted a fresh one would leave two honest peers
    // deriving over different transcripts.
    expect(nonces).toHaveLength(2);
    expect(nonces[1]).toBe(nonces[0]);
    expect(pair.creator.session.inviteNonce).toBe(nonces[0]);
    expect(pair.joiner.session.inviteNonce).toBe(nonces[0]);
  });

  it("does not read its own republished invite as a second session", async () => {
    // `_noteOwnKeyElsewhere` tells this creator apart from somebody else holding
    // its private key by one test: an invite signed by my key carrying a nonce
    // that is not the one I minted cannot have come from me. Reusing the nonce
    // is what keeps that airtight — a fresh one per republish would make every
    // echo of the *earlier* invite look like proof of a stranger, and that
    // signal stops a run.
    pair = await makeQuorumPair();
    await pair.startCreatorFirst();
    await until(() => bothConfirmed(pair));
    await pair.settle();

    expect(pair.creator.ownKeyElsewhere).toBe(0);
    expect(pair.creator.session.ownKeyElsewhere).toBe(false);
    expect(pair.joiner.ownKeyElsewhere).toBe(0);
  });

  it("leaves the joiner-first ordering meshing as it always did", async () => {
    // The ordering that always worked has to go on working, and this is also
    // where the duplicate below stops being hypothetical: started back to back,
    // the joiner's knock is still in the relay's queue when the creator joins
    // the group, so it *is* delivered — the joiner gets the broadcast invite and
    // the answer to its own knock. Two invites, one nonce, one meshed room.
    pair = await makeQuorumPair();
    await pair.start();

    expect(await until(() => bothConfirmed(pair))).toBe(true);
    expect(pair.creator.errors).toEqual([]);
    expect(pair.joiner.errors).toEqual([]);
  });
});

describe("an invite that arrives twice", () => {
  it("leaves the joiner exactly where one invite left it", async () => {
    // Established before anything causes duplicates, because near-simultaneous
    // starts now produce them for real: the creator's broadcast can reach a
    // joiner that has already knocked, and the answer to that knock arrives
    // behind it.
    pair = await makeQuorumPair();
    await pair.start();
    await until(() => bothConfirmed(pair));
    await pair.settle();

    const before = {
      nonce: pair.joiner.session.inviteNonce,
      initiator: pair.joiner.session.initiatorFpr,
      verified: pair.joiner.session.inviteVerified,
      confirmed: bothConfirmed(pair),
      errors: pair.joiner.errors.length,
    };

    await pair.creator.session._publishInvite(pair.joiner.fpr);
    await pair.settle();

    expect(pair.joiner.session.inviteNonce).toBe(before.nonce);
    expect(pair.joiner.session.initiatorFpr).toBe(before.initiator);
    expect(pair.joiner.session.inviteVerified).toBe(before.verified);
    expect(pair.joiner.errors).toHaveLength(before.errors);
    // The one that would have hurt: `_handleInvite` only calls `_beginMeshing`
    // when this session is not already meshing, so a second invite re-announces
    // nothing and re-offers nothing over a link that is carrying traffic.
    expect(bothConfirmed(pair)).toBe(true);
  });
});

describe("a knock from outside the audience", () => {
  it("is refused by name, and pulls no invite out of the room", async () => {
    let invites = 0;
    pair = await makeQuorumPair({
      tamper: (p) => {
        if (p.type === "invite") invites += 1;
        return p;
      },
    });
    await pair.startCreatorFirst();
    await until(() => bothConfirmed(pair));
    await pair.settle();
    const served = invites;

    const stranger = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ email: "nobody@quorum.test" }],
      format: "object",
    });
    const armored = await sealSignalingEnvelope({
      payload: /** @type {any} */ ({
        v: 1,
        type: "knock",
        from: stranger.publicKey.getFingerprint().toUpperCase(),
        to: null,
        roomId: pair.roomId,
        ts: Date.now(),
      }),
      signingKey: stranger.privateKey,
      audienceKeys: [...pair.creator.session.audienceKeys.values()],
    });
    // Straight at the receive path: a real stranger cannot reach even this far,
    // because the relay token is minted from room material derived from the
    // audience. This is the envelope that would arrive if one could.
    await pair.creator.session._onRelayEnvelope(armored);
    await pair.settle();

    // The refusal is `openSignalingEnvelope`'s and it names the state the reader
    // is in: this room admits exactly the fingerprints it was derived from, and
    // this signature is not one of them.
    expect(pair.creator.errors.map((e) => e.message).join("\n")).toMatch(
      /Signaling signer is not in the room audience — this room is derived from its audience's fingerprints and admits only those keys/
    );
    expect(invites).toBe(served);
    expect([...pair.creator.session._invited]).toEqual([pair.joiner.fpr]);
  });
});
