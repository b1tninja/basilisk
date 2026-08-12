/**
 * The DKG round driver, run for real.
 *
 * Every participant runs concurrently against the actual Feldman arithmetic
 * over a loopback transport that delivers asynchronously — so ordering is not
 * assumed, only convergence. This is the test a "two browsers, by hand"
 * protocol never gets, and it is the reason the driver takes its transport as
 * a parameter.
 */
import { describe, expect, it, vi } from "vitest";
import { createLoopbackTransports, runDkg } from "../lib/quorum/dkg-run.js";
import { publicKeyForSecret, reconstruct } from "../lib/quorum/dkg.js";
import { normalizeIds, scalarToHex } from "../lib/quorum/vss.js";

/** @param {number} n */
const ids = (n) => Array.from({ length: n }, (_, i) => scalarToHex(BigInt(i + 1)));

/**
 * Run a complete DKG among `n` participants, all at once.
 * @param {number} n @param {number} threshold
 */
function runAll(n, threshold, opts = {}) {
  const parties = ids(n);
  const transports = createLoopbackTransports(parties);
  return Promise.all(
    parties.map((me) =>
      runDkg({
        transport: /** @type {any} */ (transports.get(me)),
        myId: me,
        ids: parties,
        threshold,
        timeoutMs: 5000,
        ...opts,
      })
    )
  );
}

describe("a complete run over the transport", () => {
  it("converges: every participant ends with the same joint public key", async () => {
    const results = await runAll(3, 2);
    const keys = new Set(results.map((r) => r.publicKey));
    expect(keys.size, "participants disagree on the joint key").toBe(1);
  });

  it("the shares it produces really are shares of that key", async () => {
    // The assertion that makes the rest meaningful. Reconstruct from a
    // threshold subset of what the *driver* handed each participant, and check
    // the secret's public key is the one they all published.
    const parties = ids(5);
    const results = await runAll(5, 3);
    const secret = reconstruct(
      results.slice(0, 3).map((r, i) => ({ id: parties[i], share: r.share }))
    );
    expect(publicKeyForSecret(secret)).toBe(results[0].publicKey);
  });

  it("works at 5-of-7", async () => {
    const parties = ids(7);
    const results = await runAll(7, 5);
    const secret = reconstruct(
      results.slice(0, 5).map((r, i) => ({ id: parties[i], share: r.share }))
    );
    expect(publicKeyForSecret(secret)).toBe(results[0].publicKey);
  }, 20_000);

  it("counts every participant as a dealer, including itself", async () => {
    const results = await runAll(3, 2);
    for (const r of results) expect(r.dealers).toHaveLength(3);
  });

  it("reports progress as contributions arrive, naming who they came from", async () => {
    /** @type {any[]} */
    const seen = [];
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    // Watched from one seat. `runAll` would hand the same hook to all three and
    // interleave three participants' rosters into one array, which is exactly
    // the merge this progress type exists to avoid.
    await Promise.all(
      parties.map((me, i) =>
        runDkg({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          threshold: 2,
          timeoutMs: 5000,
          onProgress: i === 0 ? (p) => seen.push(p) : undefined,
        })
      )
    );
    expect(seen.length).toBeGreaterThan(0);
    const last = seen[seen.length - 1];

    // `expected` was a count and is now the roster. Tightened rather than
    // adapted: three numbers can draw "2 of 5 commitments" and cannot draw
    // *which* participant is still silent, so a surface that wanted to say so
    // had to invent it. `.length` still gives the number.
    expect(last.expected).toHaveLength(2);
    expect([...last.expected].sort()).toEqual(parties.slice(1).sort());

    // Both halves stay separate: commitments are broadcast, shares are
    // pairwise, and they do not arrive together.
    expect([...last.commitments].sort()).toEqual(parties.slice(1).sort());
    expect([...last.shares].sort()).toEqual(parties.slice(1).sort());

    // Never ourselves. A participant reading its own contribution back would
    // see the round as further along than it is.
    for (const p of seen) {
      expect(p.commitments).not.toContain(parties[0]);
      expect(p.shares).not.toContain(parties[0]);
      expect(p.expected).not.toContain(parties[0]);
    }
  });

  it("counts a participant who contributes twice once", async () => {
    // The case identity introduces and counting never had: a dealer who
    // broadcasts a second set of commitments is trying to split the group's
    // view of their polynomial. First-writing-wins already handles the
    // arithmetic; what must not happen is the roster reading as one more
    // participant than the room holds.
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const loud = parties[1];
    const real = /** @type {any} */ (transports.get(loud));
    // Same message twice, which is what a duplicated broadcast looks like on
    // the wire — not a second, different set, which is a different attack.
    transports.set(loud, {
      ...real,
      broadcast: (msg) => {
        real.broadcast(msg);
        real.broadcast(msg);
      },
    });

    /** @type {any[]} */
    const seen = [];
    await Promise.all(
      parties.map((me) =>
        runDkg({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          threshold: 2,
          timeoutMs: 5000,
          onProgress: me === parties[0] ? (p) => seen.push(p) : undefined,
        })
      )
    );

    const last = seen[seen.length - 1];
    expect(last.commitments).toHaveLength(2);
    expect(new Set(last.commitments).size).toBe(2);
    expect(last.commitments.filter((x) => x === loud)).toHaveLength(1);
  });

  it("hands back the caller's ids, not the scalars it runs the arithmetic on", async () => {
    // A shell matching progress against a room roster should not have to know
    // that this layer reduces ids to field elements. Fingerprints are valid
    // hex and are *not* their own scalar form — `normalizeIds` pads them to 64
    // characters — so this is a real difference and not an identity check.
    const fprs = [
      "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388",
      "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43",
      "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029",
    ];
    const parties = fprs.map((f) => scalarToHex(normalizeIds([f])[0]));
    expect(parties[0]).not.toBe(fprs[0]);
    const transports = createLoopbackTransports(parties);
    /** @type {any[]} */
    const seen = [];
    await Promise.all(
      parties.map((me, i) =>
        runDkg({
          transport: /** @type {any} */ (transports.get(me)),
          myId: fprs[i],
          ids: fprs,
          threshold: 2,
          timeoutMs: 5000,
          onProgress: i === 0 ? (p) => seen.push(p) : undefined,
        })
      )
    );
    const last = seen[seen.length - 1];
    expect([...last.expected].sort()).toEqual(fprs.slice(1).sort());
    expect([...last.commitments].sort()).toEqual(fprs.slice(1).sort());
  });
});

describe("what the driver refuses", () => {
  it("refuses when my own id is not among the participants", async () => {
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    await expect(
      runDkg({
        transport: /** @type {any} */ (transports.get(parties[0])),
        myId: scalarToHex(99n),
        ids: parties,
        threshold: 2,
      })
    ).rejects.toThrow(/my own id is not in the participant list/i);
  });

  it("refuses a one-participant 'distributed' generation", async () => {
    const parties = ids(1);
    const transports = createLoopbackTransports(parties);
    await expect(
      runDkg({
        transport: /** @type {any} */ (transports.get(parties[0])),
        myId: parties[0],
        ids: parties,
        threshold: 1,
      })
    ).rejects.toThrow(/at least two participants/i);
  });

  it("times out naming who it is still waiting on", async () => {
    // A participant who never runs is the ordinary failure — someone closed a
    // tab. The message has to say who, or the group cannot act on it.
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const first = runDkg({
      transport: /** @type {any} */ (transports.get(parties[0])),
      myId: parties[0],
      ids: parties,
      threshold: 2,
      timeoutMs: 300,
    });
    await expect(first).rejects.toThrow(/timed out.*waiting on 2 of 2/is);
  });
});

describe("a dishonest dealer", () => {
  it("is caught and named, and does not corrupt the key silently", async () => {
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const honest = parties.slice(0, 2);

    // Participant 3 deals correctly to everyone except participant 1, who
    // receives a share off by one — the pairwise inconsistency Feldman
    // commitments exist to catch.
    const liar = /** @type {any} */ (transports.get(parties[2]));
    const tampering = {
      ...liar,
      sendTo(id, msg) {
        if (id === parties[0] && msg.t === "dkg-share") {
          const bumped = (BigInt(`0x${msg.share}`) + 1n).toString(16).padStart(64, "0");
          return liar.sendTo(id, { ...msg, share: bumped });
        }
        return liar.sendTo(id, msg);
      },
    };

    const runs = [
      runDkg({ transport: /** @type {any} */ (transports.get(honest[0])), myId: honest[0], ids: parties, threshold: 2, timeoutMs: 4000 }),
      runDkg({ transport: /** @type {any} */ (transports.get(honest[1])), myId: honest[1], ids: parties, threshold: 2, timeoutMs: 4000 }),
      runDkg({ transport: tampering, myId: parties[2], ids: parties, threshold: 2, timeoutMs: 4000 }),
    ];
    const settled = await Promise.allSettled(runs);

    // The victim refuses, naming the dealer.
    expect(settled[0].status).toBe("rejected");
    expect(String(settled[0].reason?.message)).toMatch(/does not match their commitments/i);
    expect(String(settled[0].reason?.message)).toContain(parties[2].slice(-8));

    // And the others complete — which is exactly why the refusal cannot be
    // adjudicated mechanically: from their seat nothing was wrong, so "3 dealt
    // badly" is indistinguishable from "1 is lying about 3".
    expect(settled[1].status).toBe("fulfilled");
    expect(settled[2].status).toBe("fulfilled");
  }, 15_000);
});

describe("hostile or noisy traffic", () => {
  it("ignores messages from outside the participant set", async () => {
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const t = /** @type {any} */ (transports.get(parties[0]));
    const run = runDkg({
      transport: t,
      myId: parties[0],
      ids: parties,
      threshold: 2,
      timeoutMs: 4000,
    });
    // An uninvited party injecting a well-formed contribution must not be
    // counted — otherwise it could complete the round in place of a real
    // participant and put its own share into the joint key.
    t.subscribe(() => {});
    transports.get(parties[1]).sendTo(parties[0], {
      t: "dkg-share",
      v: 1,
      from: scalarToHex(4242n),
      to: parties[0],
      share: scalarToHex(7n),
    });
    const others = parties.slice(1).map((me) =>
      runDkg({ transport: /** @type {any} */ (transports.get(me)), myId: me, ids: parties, threshold: 2, timeoutMs: 4000 })
    );
    const [mine] = await Promise.all([run, ...others]);
    expect(mine.dealers).toHaveLength(3);
    expect(mine.dealers).not.toContain(scalarToHex(4242n));
  }, 15_000);

  it("takes a dealer's first commitments and ignores a second, conflicting set", async () => {
    // Broadcasting twice is an attempt to split the group's view of one
    // polynomial. First-writing-wins means everyone who heard it agrees.
    const parties = ids(2);
    const transports = createLoopbackTransports(parties);
    const a = /** @type {any} */ (transports.get(parties[0]));
    const doubled = {
      ...a,
      async broadcast(msg) {
        await a.broadcast(msg);
        if (msg.t === "dkg-commit") {
          await a.broadcast({ ...msg, commitments: msg.commitments.slice().reverse() });
        }
      },
    };
    const [r0, r1] = await Promise.all([
      runDkg({ transport: doubled, myId: parties[0], ids: parties, threshold: 2, timeoutMs: 4000 }),
      runDkg({ transport: /** @type {any} */ (transports.get(parties[1])), myId: parties[1], ids: parties, threshold: 2, timeoutMs: 4000 }),
    ]);
    expect(r1.publicKey).toBe(r0.publicKey);
  }, 15_000);
});
