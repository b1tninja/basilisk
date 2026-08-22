/**
 * Awaiting the key confirmation has to mean the frame is on the wire.
 *
 * `announceNotebookHeld` awaits `_maybeSendKeyConfirm` before it says anything,
 * and the comment there explains exactly why: the channel is ordered, so
 * putting our own key confirmation out first means everything after it is read
 * by a peer who has already confirmed us. A `notebook-held` frame that
 * overtakes it is dropped as unauthenticated at the far end, and the
 * once-per-member bound remembers it as said — the newcomer is then told
 * nothing, forever, which is the state that method exists to end.
 *
 * The guard fired on *intent* rather than on completion. `kcSent` was set
 * before the `await` that encrypts the frame, so a second caller arriving
 * during that window saw a confirmation that had been decided on and not yet
 * written, returned immediately, and sent its announcement first. The
 * fire-and-forget call in `_wireChannel`'s `onopen` is exactly such a first
 * caller, and a roster render is exactly such a second one.
 *
 * These drive `_maybeSendKeyConfirm` directly rather than through the pair
 * harness, because the failure is a two-caller interleaving inside one `await`
 * and the harness cannot hold a send open at that point.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

/** Lets a test hold the encryption open and decide when it finishes. */
let gate = null;

vi.mock("../lib/notebook/crypto.js", async (importOriginal) => {
  const actual = /** @type {any} */ (await importOriginal());
  return {
    ...actual,
    encryptSessionPayload: async (key, plaintext) => {
      if (gate) await gate.promise;
      return `blob:${JSON.parse(plaintext).kind}`;
    },
  };
});

const { NotebookSession } = await import("../lib/notebook/session.js");
const { deriveRoomId } = await import("../lib/notebook/room.js");

const FPR_ME = "A".repeat(40);
const FPR_PEER = "B".repeat(40);

function deferred() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** A session with one peer already key-agreed, and a channel that records. */
async function oneAgreedPeer() {
  const audience = [FPR_ME, FPR_PEER].sort();
  const session = new NotebookSession({
    roomId: await deriveRoomId(audience),
    myFingerprint: FPR_ME,
    audienceFprs: audience,
    privateKey: /** @type {any} */ ({}),
    role: "creator",
  });
  /** @type {string[]} */
  const sent = [];
  const peer = {
    ...session.peers.get(FPR_PEER),
    sessionKey: /** @type {any} */ ({}),
    transcriptHash: "th",
    kcSent: false,
    channel: { readyState: "open", send: (s) => sent.push(s) },
  };
  session.peers.set(FPR_PEER, /** @type {any} */ (peer));
  return { session, peer, sent };
}

// A test that fails while holding the gate open would hang every test after
// it on a promise nobody resolves, reporting three failures for one defect.
afterEach(() => {
  gate?.resolve();
  gate = null;
});

describe("a key confirmation is sent before it is reported as sent", () => {
  it("makes a second caller wait for the frame the first one is writing", async () => {
    const { session, sent } = await oneAgreedPeer();
    gate = deferred();

    // `_wireChannel`'s `onopen` does exactly this — fire and forget.
    const first = session._maybeSendKeyConfirm(FPR_PEER);
    // The frame is decided on but not written: nothing has reached the channel.
    expect(sent).toEqual([]);

    // A roster render arrives and awaits the confirmation, as
    // `announceNotebookHeld` does. This must not resolve before the write.
    let secondResolved = false;
    const second = session._maybeSendKeyConfirm(FPR_PEER).then(() => {
      secondResolved = true;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(
      secondResolved,
      "the second caller resolved while the frame was still unwritten, so anything it sends next overtakes the confirmation"
    ).toBe(false);

    gate.resolve();
    await Promise.all([first, second]);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toContain("kc");
  });

  it("does not report a confirmation the channel never accepted", async () => {
    const { session, peer } = await oneAgreedPeer();
    peer.channel.send = () => {
      throw new Error("channel went away mid-write");
    };
    await expect(session._maybeSendKeyConfirm(FPR_PEER)).rejects.toThrow(/channel went away/);
    expect(
      peer.kcSent,
      "a failed write left the peer marked as confirmed, so nothing will retry"
    ).toBe(false);
  });

  it("does not confirm a link that was torn down while the frame was in flight", async () => {
    const { session, peer } = await oneAgreedPeer();
    gate = deferred();
    const inflight = session._maybeSendKeyConfirm(FPR_PEER);

    // `_resetPeer` and the epoch rotation both do exactly this, and either can
    // land while the encrypt above is still open. The write that follows
    // belongs to the link that is now gone.
    peer.kcSent = false;
    peer.kcSending = null;

    gate.resolve();
    await inflight;
    expect(
      peer.kcSent,
      "a write from the torn-down link marked the fresh peer state as confirmed, so the new link never sends its own"
    ).toBe(false);
  });

  it("retries after a write the channel refused", async () => {
    const { session, peer, sent } = await oneAgreedPeer();
    peer.channel.send = () => {
      throw new Error("channel went away mid-write");
    };
    await expect(session._maybeSendKeyConfirm(FPR_PEER)).rejects.toThrow();

    // The link recovers. Nothing else re-arms this -- if the failed attempt is
    // still remembered as in flight, every later caller joins a promise that
    // has already rejected and the peer is never confirmed at all.
    peer.channel.send = (frame) => sent.push(frame);
    await session._maybeSendKeyConfirm(FPR_PEER);
    expect(sent).toHaveLength(1);
    expect(peer.kcSent).toBe(true);
  });

  it("still sends exactly once when it succeeds", async () => {
    const { session, sent, peer } = await oneAgreedPeer();
    await session._maybeSendKeyConfirm(FPR_PEER);
    await session._maybeSendKeyConfirm(FPR_PEER);
    expect(sent).toHaveLength(1);
    expect(peer.kcSent).toBe(true);
  });
});
