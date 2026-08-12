/**
 * The entropy-pool rounds, run for real.
 *
 * Every participant runs concurrently against the actual digests over a
 * loopback transport that delivers asynchronously, so ordering is not assumed —
 * only convergence. The same shape `dkg-run.test.js` uses, and the reason the
 * driver takes its transport as a parameter: a ceremony that can only be tested
 * with two browsers is a ceremony nobody tests.
 *
 * The property that matters most is not "it agrees". It is **when a participant
 * reveals**: not one message before every commitment is in. A driver that
 * revealed early would still converge, still agree, and still pass a test that
 * only checked the digest — while handing the last mover exactly the choice
 * committing was meant to take away.
 */
import { describe, expect, it } from "vitest";
import {
  POOL_COMMIT,
  POOL_REVEAL,
  createLoopbackTransports,
  runEntropyPool,
} from "../lib/quorum/pool-run.js";
import { entropyPoolDigest, randomNonce } from "../lib/toolkit/entropy-pool.js";

const ids = (n) => Array.from({ length: n }, (_, i) => `@p${i + 1}`);

/** Run a complete pool among `n` participants, all at once. */
function runAll(n, opts = {}) {
  const parties = ids(n);
  const transports = createLoopbackTransports(parties);
  return Promise.all(
    parties.map((me) =>
      runEntropyPool({
        transport: /** @type {any} */ (transports.get(me)),
        myId: me,
        ids: parties,
        timeoutMs: 5000,
        ...(typeof opts.per === "function" ? opts.per(me) : opts),
      })
    )
  );
}

describe("a complete pool over the transport", () => {
  it("converges: every participant computes the same value", async () => {
    const results = await runAll(4);
    const first = results[0].digest;
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    for (const r of results) expect(r.digest).toBe(first);
  });

  it("is the digest over everyone's reveals, and nobody else's", async () => {
    // Recomputed from the outside, from the nonces the participants ended up
    // holding — so the driver agreeing with itself is not what is being tested.
    const parties = ids(3);
    const results = await runAll(3);
    expect(await entropyPoolDigest(parties.map((id, i) => ({ id, nonce: results[i].nonce })))).toBe(
      results[0].digest
    );
    for (const r of results) expect(r.contributors).toEqual([...parties].sort());
  });

  it("draws a different value every time", async () => {
    // Nonces are minted per run. A pool that repeated would mean somebody's
    // contribution was not random, which is the whole point of the exercise.
    const a = await runAll(3);
    const b = await runAll(3);
    expect(a[0].digest).not.toBe(b[0].digest);
  });

  it("lets a participant supply its own contribution", async () => {
    // The seam a test needs, and a caller rehearsing a ceremony with a fixed
    // transcript. Same reveals in, same pool out.
    const parties = ids(3);
    const nonces = { "@p1": "aa".repeat(32), "@p2": "bb".repeat(32), "@p3": "cc".repeat(32) };
    const transports = createLoopbackTransports(parties);
    const results = await Promise.all(
      parties.map((me) =>
        runEntropyPool({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          nonce: nonces[me],
          timeoutMs: 5000,
        })
      )
    );
    expect(results[0].digest).toBe(
      await entropyPoolDigest(parties.map((id) => ({ id, nonce: nonces[id] })))
    );
  });
});

describe("nobody reveals before every commitment is in", () => {
  it("holds its nonce until the last participant has committed", async () => {
    // The ordering rule, observed rather than asserted about the source. One
    // participant's commitment is held back; every other participant must be
    // silent on `pool-reveal` for as long as it is.
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const slow = parties[2];

    /** @type {string[]} */
    const wire = [];
    /** @type {(() => void)|null} */
    let releaseCommit = null;
    const held = new Promise((r) => (releaseCommit = () => r(undefined)));

    for (const id of parties) {
      const real = /** @type {any} */ (transports.get(id));
      transports.set(id, {
        ...real,
        broadcast: async (msg) => {
          wire.push(`${id}:${msg.t}`);
          // `@p3` sits on its commitment until the test lets it go.
          if (id === slow && msg.t === POOL_COMMIT) await held;
          return real.broadcast(msg);
        },
      });
    }

    const run = Promise.all(
      parties.map((me) =>
        runEntropyPool({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          timeoutMs: 5000,
        })
      )
    );

    // Long enough for the two prompt participants to have revealed if they
    // were going to. They must not have.
    await new Promise((r) => setTimeout(r, 250));
    expect(
      wire.filter((e) => e.endsWith(POOL_REVEAL)),
      `revealed while ${slow}'s commitment was outstanding: ${wire.join(" ")}`
    ).toEqual([]);

    releaseCommit?.();
    const results = await run;
    expect(new Set(results.map((r) => r.digest)).size).toBe(1);
    // And every commitment really did precede every reveal on the wire.
    expect(wire.lastIndexOf(`${slow}:${POOL_COMMIT}`)).toBeLessThan(
      wire.findIndex((e) => e.endsWith(POOL_REVEAL))
    );
  });

  it("times out naming who never committed, and pools nothing", async () => {
    // The correct failure. A participant who withholds a commitment stalls the
    // round; they do not get to choose the value by being last.
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const silent = parties[2];
    const real = /** @type {any} */ (transports.get(silent));
    transports.set(silent, { ...real, broadcast: () => {} });

    await expect(
      runEntropyPool({
        transport: /** @type {any} */ (transports.get(parties[0])),
        myId: parties[0],
        ids: parties,
        timeoutMs: 300,
      })
    ).rejects.toThrow(/timed out .* waiting for commitments/);
  });

  it("refuses a reveal that does not open its commitment", async () => {
    // A participant who commits honestly and then reveals something else is
    // choosing after the fact. The round is refused by name — not recomputed
    // without them, which would be the same value the rest of us chose.
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const liar = parties[1];
    const real = /** @type {any} */ (transports.get(liar));
    transports.set(liar, {
      ...real,
      broadcast: (msg) =>
        real.broadcast(
          msg.t === POOL_REVEAL ? { ...msg, nonce: randomNonce() } : msg
        ),
    });

    const results = await Promise.allSettled(
      parties.map((me) =>
        runEntropyPool({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          timeoutMs: 5000,
        })
      )
    );
    // Everyone who was lied to refuses; the liar's own run is not the subject.
    const refused = results.filter(
      (r) => r.status === "rejected" && /does not open their commitment/.test(String(r.reason?.message))
    );
    expect(refused.length).toBeGreaterThanOrEqual(2);
    for (const r of refused) expect(String(r.reason.message)).toContain(liar);
  });
});

describe("progress names participants", () => {
  it("reports who has committed and who has revealed, from one seat", async () => {
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    /** @type {any[]} */
    const seen = [];
    await Promise.all(
      parties.map((me, i) =>
        runEntropyPool({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          timeoutMs: 5000,
          onProgress: i === 0 ? (p) => seen.push(p) : undefined,
        })
      )
    );
    expect(seen.length).toBeGreaterThan(0);
    const last = seen[seen.length - 1];
    expect([...last.expected].sort()).toEqual(parties.slice(1).sort());
    expect([...last.commitments].sort()).toEqual(parties.slice(1).sort());
    expect([...last.reveals].sort()).toEqual(parties.slice(1).sort());
    // Never ourselves: a seat reading its own contribution back would see the
    // round as further along than it is.
    for (const p of seen) {
      expect(p.commitments).not.toContain(parties[0]);
      expect(p.reveals).not.toContain(parties[0]);
    }
    // And the round is named, so a surface can say which half is outstanding.
    expect(seen.map((p) => p.round)).toContain("committing");
    expect(seen.map((p) => p.round)).toContain("revealing");
  });

  it("counts a participant who broadcasts twice once", async () => {
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    const loud = parties[1];
    const real = /** @type {any} */ (transports.get(loud));
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
      parties.map((me, i) =>
        runEntropyPool({
          transport: /** @type {any} */ (transports.get(me)),
          myId: me,
          ids: parties,
          timeoutMs: 5000,
          onProgress: i === 0 ? (p) => seen.push(p) : undefined,
        })
      )
    );
    const last = seen[seen.length - 1];
    expect(last.commitments.filter((x) => x === loud)).toHaveLength(1);
    expect(last.reveals.filter((x) => x === loud)).toHaveLength(1);
  });
});

describe("what the driver refuses before it starts", () => {
  it("refuses when my own id is not among the participants", async () => {
    const parties = ids(3);
    const transports = createLoopbackTransports(parties);
    await expect(
      runEntropyPool({
        transport: /** @type {any} */ (transports.get(parties[0])),
        myId: "@nobody",
        ids: parties,
      })
    ).rejects.toThrow(/my own id is not in the participant list/);
  });

  it("refuses a pool of one", async () => {
    const transports = createLoopbackTransports(["@solo"]);
    await expect(
      runEntropyPool({
        transport: /** @type {any} */ (transports.get("@solo")),
        myId: "@solo",
        ids: ["@solo"],
      })
    ).rejects.toThrow(/at least two participants/);
  });
});
