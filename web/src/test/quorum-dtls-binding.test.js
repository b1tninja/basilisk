/**
 * The DTLS binding — the property that makes moving the WebRTC driver a safe
 * refactor rather than a hopeful one.
 *
 * `derivePairwiseSessionKey` folds **both** DTLS certificate fingerprints into
 * the transcript, so a pairwise session key is bound to the transport that
 * carries it. `peer.localDtls` is read out of the local description the moment
 * `setLocalDescription()` resolves, inside the negotiation path — which means
 * *when* negotiation runs decides *when* that value exists, and any change to
 * the driver is a change to the binding.
 *
 * The failure mode is the reason this file exists: get it subtly wrong and key
 * confirmation **succeeds anyway**, over a transcript that no longer commits to
 * anything about the transport. Every suite stays green. So the demonstration
 * cannot be "the tests pass" — it has to be a test that *fails when tampered*,
 * run before and after.
 *
 * The tamper here is the strongest one the protocol permits. The mailbox opens
 * each envelope, rewrites the fingerprint, and re-seals it **with the original
 * signer's own private key**: right signer, right room, right audience, valid
 * signature, correct `from`. Nothing in the PGP layer can see it. Only the
 * transcript binding can — and if it ever stops seeing it, this test goes green
 * and says so.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/** Every `derivePairwiseSessionKey` call, with its inputs, in order. */
const { derived } = vi.hoisted(() => ({ derived: /** @type {any[]} */ ([]) }));

vi.mock("../lib/quorum/crypto.js", async (importOriginal) => {
  const actual = /** @type {any} */ (await importOriginal());
  return {
    ...actual,
    /** @param {any} opts */
    async derivePairwiseSessionKey(opts) {
      const out = await actual.derivePairwiseSessionKey(opts);
      derived.push({ ...opts, transcriptHash: out.transcriptHash });
      return out;
    },
  };
});

const { combineDtlsFingerprints, derivePairwiseSessionKey } = await import(
  "../lib/quorum/crypto.js"
);
const { makeQuorumPair, until } = await import("./helpers/quorum-pair.js");

/** A fingerprint no transport would ever mint. */
const LIE = `sha-256 ${new Array(32).fill("00").join(":")}`;

/** @type {{ stop: () => void }|null} */
let pair = null;

beforeEach(() => {
  derived.length = 0;
});

afterEach(() => {
  pair?.stop();
  pair = null;
});

/**
 * @param {any} p
 * @param {string} peerFpr
 */
const peerOf = (p, peerFpr) => p.session.peers.get(peerFpr);

/**
 * The transport itself, reached past the link on purpose.
 *
 * The session cannot do this — it holds a `PeerLink` and `lib/quorum/` may not
 * name a connection at all — and that is exactly why the test must. The
 * provenance assertion below compares `localDtls` against the fingerprint the
 * *connection* minted; asking the session for that number would compare it to
 * itself, and a driver reporting one constant fingerprint would sail through
 * every tamper case with both ends agreeing.
 *
 * @param {any} peer
 */
const transportOf = (peer) => peer.link.pc;

/* ───────────────────────── the transcript bytes ───────────────────────── */

describe("the pairwise transcript is pinned to its bytes", () => {
  // Fixed P-256 keys and fixed nonces, so the whole derivation is
  // deterministic. Any change to the field order, the separators, the salt
  // material or the info string moves both numbers below — and every session
  // key that has ever been derived moves with them. That is a protocol break,
  // not a refactor, so it must never happen by accident.
  const A_PRIVATE_JWK = {
    kty: "EC",
    crv: "P-256",
    x: "cjyTvWaY7sd1uyQ0kIQ4lUs_ObX9V3_7kFDFjLPdjIs",
    y: "hGLlCxKmJ9fHlyk5xbwGeUh2P_b0I58sxSiKasr-uBE",
    d: "m8ly6eYpxuPOXnss5ij6QFbEbX-qS7jQ3r0TLdD82Wo",
  };
  const A_PUBLIC_JWK = {
    kty: "EC",
    crv: "P-256",
    x: "cjyTvWaY7sd1uyQ0kIQ4lUs_ObX9V3_7kFDFjLPdjIs",
    y: "hGLlCxKmJ9fHlyk5xbwGeUh2P_b0I58sxSiKasr-uBE",
  };
  const B_PUBLIC_JWK = {
    kty: "EC",
    crv: "P-256",
    x: "5le5SNnWAKAghOvjm3Wzri3HmOpn6PUGwYKSbVptVY4",
    y: "p9wZjoHofSU8dxGrGU2nFCMxPNA68LRAe-vcwFNgoUs",
  };

  const VECTOR = {
    roomId: "ABCD2345EFGH6789",
    myFpr: "A".repeat(40),
    peerFpr: "B".repeat(40),
    audienceFprs: ["A".repeat(40), "B".repeat(40)],
    myEcdhJwk: A_PUBLIC_JWK,
    peerEcdhJwk: B_PUBLIC_JWK,
    inviteNonce: "ab".repeat(16),
    myHelloNonce: "11".repeat(16),
    peerHelloNonce: "22".repeat(16),
    dtlsFingerprint: "sha-256 AA:BB|sha-256 CC:DD",
  };

  async function deriveVector(overrides = {}) {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      A_PRIVATE_JWK,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const peerPublicKey = await crypto.subtle.importKey(
      "jwk",
      B_PUBLIC_JWK,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    return derivePairwiseSessionKey({
      privateKey,
      peerPublicKey,
      ...VECTOR,
      ...overrides,
    });
  }

  it("produces the same transcript hash and the same key bytes as it always has", async () => {
    const { aesKey, transcriptHash } = await deriveVector();
    expect(transcriptHash).toBe(
      "15425a93b4ca431fc3ba4f22d8e66069e52773f88de3711beb0e6c3e4a282535"
    );
    // The AES key is non-extractable by design, so it is pinned through what
    // it does: one fixed plaintext under one fixed IV.
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(12) },
      aesKey,
      new TextEncoder().encode("basilisk")
    );
    expect(
      [...new Uint8Array(ct)].map((b) => b.toString(16).padStart(2, "0")).join("")
    ).toBe("c0f4aa6691546492566388ecb004cf300a1bf34b17151085");
  });

  it("moves both numbers when only the DTLS fingerprint changes", async () => {
    // The pin above would be satisfied by a transcript that ignored the
    // fingerprint entirely. This is the half that says it does not.
    const { aesKey, transcriptHash } = await deriveVector({
      dtlsFingerprint: "sha-256 AA:BB|sha-256 CC:DE",
    });
    expect(transcriptHash).not.toBe(
      "15425a93b4ca431fc3ba4f22d8e66069e52773f88de3711beb0e6c3e4a282535"
    );
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(12) },
      aesKey,
      new TextEncoder().encode("basilisk")
    );
    expect(
      [...new Uint8Array(ct)].map((b) => b.toString(16).padStart(2, "0")).join("")
    ).not.toBe("c0f4aa6691546492566388ecb004cf300a1bf34b17151085");
  });
});

/* ──────────────────────── two peers, honest wire ──────────────────────── */

describe("two peers mesh, confirm keys, and pass data", () => {
  it("binds the transcript to the fingerprints both transports committed to", async () => {
    pair = await makeQuorumPair();
    const p = /** @type {any} */ (pair);
    await p.start();

    const [loFpr, hiFpr] = p.audience;
    const sideOf = (fpr) => (p.creator.fpr === fpr ? p.creator : p.joiner);
    const lo = sideOf(loFpr);
    const hi = sideOf(hiFpr);

    const ready = await until(
      () =>
        peerOf(lo, hiFpr)?.kcVerified === true &&
        peerOf(hi, loFpr)?.kcVerified === true
    );
    expect(ready, `errors: ${[...lo.errors, ...hi.errors].map((e) => e.message)}`)
      .toBe(true);

    const loPeer = peerOf(lo, hiFpr);
    const hiPeer = peerOf(hi, loFpr);

    // The transport really is up — otherwise the negative case below could
    // "pass" because nothing connected at all.
    expect(loPeer.link.isLive()).toBe(true);
    expect(hiPeer.link.isLive()).toBe(true);
    expect(loPeer.channel.readyState).toBe("open");
    expect(hiPeer.channel.readyState).toBe("open");
    expect(loPeer.status).toBe("connected");
    expect(hiPeer.status).toBe("connected");

    // Each side's `localDtls` is the fingerprint *its own* connection minted,
    // read out of its own local description. This is the assertion the driver
    // extraction has to keep true: move negotiation and this is the first
    // thing that can silently stop holding.
    expect(loPeer.localDtls).toBe(transportOf(loPeer).dtlsFingerprint());
    expect(hiPeer.localDtls).toBe(transportOf(hiPeer).dtlsFingerprint());
    expect(loPeer.remoteDtls).toBe(transportOf(hiPeer).dtlsFingerprint());
    expect(hiPeer.remoteDtls).toBe(transportOf(loPeer).dtlsFingerprint());

    // …and the two are different numbers, so "both ends agree" is a fact about
    // the exchange rather than about a driver that mints one constant.
    expect(transportOf(loPeer).dtlsFingerprint()).not.toBe(
      transportOf(hiPeer).dtlsFingerprint()
    );

    // …and that is exactly what reached the KDF, on both sides.
    const expectedDtls = combineDtlsFingerprints(
      transportOf(loPeer).dtlsFingerprint(),
      transportOf(hiPeer).dtlsFingerprint()
    );
    expect(derived.length).toBeGreaterThanOrEqual(2);
    for (const call of derived) {
      expect(call.dtlsFingerprint).toBe(expectedDtls);
    }

    // Both sides reached the same transcript, which is what key confirmation
    // compares.
    expect(loPeer.transcriptHash).toBe(hiPeer.transcriptHash);
    expect(loPeer.transcriptHash).toMatch(/^[0-9a-f]{64}$/);

    // And the channel carries application data under that key, both ways.
    expect(await lo.session.sendChatTo(hiFpr, "from lo")).toBe(1);
    expect(await hi.session.sendChatTo(loFpr, "from hi")).toBe(1);
    await until(() => lo.chats.length > 0 && hi.chats.length > 0);
    expect(hi.chats.map((c) => c.text)).toEqual(["from lo"]);
    expect(lo.chats.map((c) => c.text)).toEqual(["from hi"]);
  });
});

/* ─────────────────── two peers, one substituted fingerprint ─────────────────── */

describe("key confirmation rejects a substituted DTLS fingerprint", () => {
  /**
   * @param {"lo"|"hi"} victim which end lies about its own certificate
   */
  async function runTampered(victim) {
    /** @type {string} */
    let liarFpr = "";
    pair = await makeQuorumPair({
      tamper: (payload, fromFpr) => {
        if (payload.dtlsFingerprint && fromFpr === liarFpr) {
          payload.dtlsFingerprint = LIE;
        }
        return payload;
      },
    });
    const p = /** @type {any} */ (pair);
    const [loFpr, hiFpr] = p.audience;
    liarFpr = victim === "lo" ? loFpr : hiFpr;
    await p.start();
    const sideOf = (/** @type {string} */ fpr) =>
      p.creator.fpr === fpr ? p.creator : p.joiner;
    return { p, lo: sideOf(loFpr), hi: sideOf(hiFpr), loFpr, hiFpr };
  }

  for (const victim of /** @type {const} */ (["lo", "hi"])) {
    it(`refuses to confirm when the ${victim === "lo" ? "offerer" : "answerer"} claims a fingerprint its transport never used`, async () => {
      const { p, lo, hi, loFpr, hiFpr } = await runTampered(victim);

      // Give it every chance to succeed — a negative test that only passes
      // because it gave up early proves nothing.
      const confirmed = await until(
        () =>
          peerOf(lo, hiFpr)?.kcVerified === true &&
          peerOf(hi, loFpr)?.kcVerified === true,
        3000
      );
      await p.settle();

      const loPeer = peerOf(lo, hiFpr);
      const hiPeer = peerOf(hi, loFpr);

      // The transport came up. The handshake is not failing for want of a
      // connection — it is failing because the transcripts disagree.
      expect(loPeer.link.isLive()).toBe(true);
      expect(hiPeer.link.isLive()).toBe(true);
      expect(loPeer.channel.readyState).toBe("open");
      expect(hiPeer.channel.readyState).toBe("open");

      expect(confirmed).toBe(false);
      expect(loPeer.kcVerified).toBe(false);
      expect(hiPeer.kcVerified).toBe(false);

      // Both derived a key; the two keys are not the same key.
      expect(loPeer.transcriptHash).toBeTruthy();
      expect(hiPeer.transcriptHash).toBeTruthy();
      expect(loPeer.transcriptHash).not.toBe(hiPeer.transcriptHash);

      // One side saw the lie in the transcript it built.
      const lied = derived.filter((d) => d.dtlsFingerprint.includes("00:00:00"));
      expect(lied.length).toBeGreaterThan(0);

      // Somebody complained: the confirmation frame does not open under the
      // other side's key.
      expect([...lo.errors, ...hi.errors].length).toBeGreaterThan(0);

      // And nothing is deliverable over the unconfirmed link.
      await expect(lo.session.sendChatTo(hiFpr, "nope")).rejects.toThrow(
        /no verified peer/
      );
      await expect(hi.session.sendChatTo(loFpr, "nope")).rejects.toThrow(
        /no verified peer/
      );
      expect(await lo.session.sendChat("broadcast")).toBe(0);
    });
  }
});
