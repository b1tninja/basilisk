/**
 * The pooled value, and the four things that have to be true about it.
 *
 * `manifest.js` has carried `entropy: { mode: "pool", digest }` and the refusal
 * that declared it — `entropy: { mode: "pool", digest }` — while saying plainly
 * in its own header that nothing produced one. This is the value.
 *
 * What keeps a pooled value away from key material is the compiler's
 * pooled-value rule (`pooled-value-rule.test.js`), which checks it by value
 * flow rather than by the company an op keeps.
 *
 * Pure: no transport, no session, no clock. A pool is a digest over reveals, so
 * it can be tested as one, which is why it comes before the op that will collect
 * them over a live exchange.
 */
import { describe, expect, it } from "vitest";
import {
  ENTROPY_COMMIT_DOMAIN,
  ENTROPY_POOL_DOMAIN,
  entropyCommitment,
  entropyPoolDigest,
  openEntropyPool,
} from "../lib/toolkit/entropy-pool.js";
import { canonicalJson, digestText } from "../lib/toolkit/receipt.js";

const REVEALS = [
  { id: "@mara", nonce: "a1b2c3d4" },
  { id: "@okafor", nonce: "ffeeddcc" },
  { id: "@lin", nonce: "0011223344556677" },
];

/** The commitments those reveals open. */
const commitmentsFor = async (reveals) =>
  Object.fromEntries(
    await Promise.all(reveals.map(async (r) => [r.id, await entropyCommitment(r)]))
  );

describe("the same reveals in any order give the same pool", () => {
  it("does not depend on who spoke first", async () => {
    // The property sorting exists for. Two participants whose messages crossed
    // must compute the same value or the pool is a function of the network.
    const forward = await entropyPoolDigest(REVEALS);
    const backward = await entropyPoolDigest([...REVEALS].reverse());
    const shuffled = await entropyPoolDigest([REVEALS[1], REVEALS[2], REVEALS[0]]);
    expect(backward).toBe(forward);
    expect(shuffled).toBe(forward);
    expect(forward).toMatch(/^[0-9a-f]{64}$/);
  });

  it("gives the same answer through the checked path", async () => {
    // `openEntropyPool` verifies first and then pools; an auditor holding only
    // the reveals must reach the same digest, or a manifest could not be
    // checked once the commitments are gone.
    const { digest, contributors } = await openEntropyPool({
      commitments: await commitmentsFor(REVEALS),
      reveals: REVEALS,
    });
    expect(digest).toBe(await entropyPoolDigest(REVEALS));
    // Sorted, and the whole room: the contributors are part of what the value
    // means, not a by-product of iterating a map.
    expect(contributors).toEqual(["@lin", "@mara", "@okafor"]);
  });
});

describe("the domain is part of the digest", () => {
  it("is not the digest the same bytes would get under another domain", async () => {
    // A pool must never be mistakable for some other digest of the same
    // preimage — the reason `PEERS_DOMAIN` and `AUDIENCE_DOMAIN` exist, applied
    // here. Computed by hand so the test would notice the prefix being dropped
    // rather than agreeing with whatever the module happens to do.
    const sorted = [
      { id: "@lin", nonce: "0011223344556677" },
      { id: "@mara", nonce: "a1b2c3d4" },
      { id: "@okafor", nonce: "ffeeddcc" },
    ];
    expect(await entropyPoolDigest(REVEALS)).toBe(
      await digestText(ENTROPY_POOL_DOMAIN + canonicalJson(sorted))
    );
    const undomained = await digestText(canonicalJson(sorted));
    const otherDomain = await digestText("basilisk.run-manifest/peers/v1\n" + canonicalJson(sorted));
    expect(await entropyPoolDigest(REVEALS)).not.toBe(undomained);
    expect(await entropyPoolDigest(REVEALS)).not.toBe(otherDomain);
  });

  it("pins the domain strings themselves", () => {
    // Written out rather than referenced, because every assertion above builds
    // its expectation *from* these constants and would follow them anywhere —
    // emptying `ENTROPY_POOL_DOMAIN` moved both sides of the comparison
    // together and only the un-prefixed check noticed. A domain separator is a
    // value, not an implementation detail: changing it silently changes every
    // digest ever computed under it, so a change should have to be typed twice.
    expect(ENTROPY_POOL_DOMAIN).toBe("basilisk.run-manifest/entropy-pool/v1\n");
    expect(ENTROPY_COMMIT_DOMAIN).toBe("basilisk.run-manifest/entropy-commit/v1\n");
    // The trailing newline is the family's, and it is what stops a domain being
    // a prefix of a longer one.
    for (const d of [ENTROPY_POOL_DOMAIN, ENTROPY_COMMIT_DOMAIN]) {
      expect(d.endsWith("\n")).toBe(true);
    }
  });

  it("keeps a commitment out of the pool's namespace", async () => {
    // A one-participant pool and that participant's commitment are digests over
    // the same id and nonce. Different domains are the only thing that stops
    // one being replayed as the other.
    const one = [{ id: "@mara", nonce: "a1b2c3d4" }];
    expect(await entropyCommitment(one[0])).not.toBe(await entropyPoolDigest(one));
    expect(ENTROPY_COMMIT_DOMAIN).not.toBe(ENTROPY_POOL_DOMAIN);
  });

  it("binds a commitment to its participant", async () => {
    // Without the id in the preimage, a commitment is a bare digest of a nonce
    // and anyone who has seen it can publish it as their own — two
    // participants contributing one choice.
    const mine = await entropyCommitment({ id: "@mara", nonce: "a1b2c3d4" });
    const theirs = await entropyCommitment({ id: "@okafor", nonce: "a1b2c3d4" });
    expect(theirs).not.toBe(mine);
  });
});

describe("every contribution changes the value", () => {
  it("moves when one participant's nonce moves", async () => {
    const before = await entropyPoolDigest(REVEALS);
    const after = await entropyPoolDigest([
      REVEALS[0],
      { ...REVEALS[1], nonce: "ffeeddcd" },
      REVEALS[2],
    ]);
    expect(after).not.toBe(before);
  });

  it("moves when the room does", async () => {
    // A pool over two people is not the same value as a pool over three, even
    // when the two contributed identically. Who it is made of is part of it.
    expect(await entropyPoolDigest(REVEALS.slice(0, 2))).not.toBe(
      await entropyPoolDigest(REVEALS)
    );
  });
});

describe("a broken round is refused, not shrunk", () => {
  it("refuses a reveal that does not open its commitment", async () => {
    // The attack the whole ceremony exists to stop: waiting to see everyone
    // else, then choosing. Refused **by name** — and refused rather than
    // dropped, because a pool computed without them is a pool the rest of the
    // room chose, which is the same outcome reached by accident.
    const commitments = await commitmentsFor(REVEALS);
    const late = [REVEALS[0], REVEALS[1], { id: "@lin", nonce: "deadbeefdeadbeef" }];
    await expect(openEntropyPool({ commitments, reveals: late })).rejects.toThrow(
      /@lin revealed a nonce that does not open their commitment/
    );
    await expect(openEntropyPool({ commitments, reveals: late })).rejects.toThrow(
      /refused rather than pooled without them/
    );
  });

  it("refuses a commitment nobody opened, and says it is a different event", async () => {
    // Someone offline is not someone cheating, and the room has to be able to
    // tell them apart — but pooling without either hands the value to whoever
    // decided to stop waiting.
    await expect(
      openEntropyPool({
        commitments: await commitmentsFor(REVEALS),
        reveals: REVEALS.slice(0, 2),
      })
    ).rejects.toThrow(/@lin committed and did not reveal/);
  });

  it("refuses a reveal nobody was bound to", async () => {
    const commitments = await commitmentsFor(REVEALS.slice(0, 2));
    await expect(
      openEntropyPool({ commitments, reveals: REVEALS })
    ).rejects.toThrow(/@lin revealed without committing/);
  });

  it("refuses one participant revealing twice", async () => {
    // Two reveals under one id means the room disagrees about who contributed
    // what, and picking either one picks a pool.
    await expect(
      entropyPoolDigest([REVEALS[0], { id: "@mara", nonce: "0000" }])
    ).rejects.toThrow(/@mara revealed twice/);
  });

  it("refuses an empty round rather than digesting nothing", async () => {
    // `H(domain + "[]")` is a perfectly good digest and a completely bogus
    // pool: a value nobody contributed to that every party can compute.
    await expect(entropyPoolDigest([])).rejects.toThrow(/nobody contributed to/);
    await expect(
      openEntropyPool({ commitments: {}, reveals: REVEALS })
    ).rejects.toThrow(/no commitments/);
  });

  it("refuses a nonce that is not unambiguous bytes", async () => {
    // Hex, even-length, because a pool is a digest over bytes and two spellings
    // of one value would be two different pools.
    await expect(entropyPoolDigest([{ id: "@mara", nonce: "zz" }])).rejects.toThrow(/not hex/);
    await expect(entropyPoolDigest([{ id: "@mara", nonce: "abc" }])).rejects.toThrow(
      /odd number of hex digits/
    );
    await expect(entropyPoolDigest([{ id: "@mara", nonce: "" }])).rejects.toThrow(
      /revealed no nonce/
    );
    await expect(entropyPoolDigest([{ id: "", nonce: "aabb" }])).rejects.toThrow(
      /no participant id/
    );
  });

  it("reads a nonce's case as one value", async () => {
    // Normalized rather than refused: an uppercase nonce is the same bytes, and
    // two participants who spell it differently must not compute two pools.
    expect(await entropyPoolDigest([{ id: "@mara", nonce: "A1B2C3D4" }])).toBe(
      await entropyPoolDigest([{ id: "@mara", nonce: "a1b2c3d4" }])
    );
  });
});
