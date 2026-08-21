/**
 * A knock claims "I am here now", so it has to be able to say *now*.
 *
 * `knock` was the one signalling payload with no nonce and no clock. Nobody
 * outside the audience can mint one — the envelope is signed — but a captured
 * frame replays byte for byte, and `_knocked`/`_invited` are fresh in a new
 * session, so the per-session bounds never saw the second arrival. What that
 * bought was a presence lie: a roster line saying an audience member is here
 * when they are not.
 *
 * These drive `_knockIsFresh` directly. The predicate is the whole fix and it
 * is pure, which is the layer a test can hold still — the frames around it are
 * covered by the session suites.
 */
import { describe, expect, it, vi, afterEach } from "vitest";
import { NotebookSession } from "../lib/notebook/session.js";
import { KNOCK_MAX_AGE_MS } from "../lib/notebook/crypto.js";

/** A session shell — the predicate reads only its own seen-set. */
function judge() {
  const s = Object.create(NotebookSession.prototype);
  s._knockNonces = new Set();
  return (payload) => s._knockIsFresh(payload);
}

const nonce = (n) => String(n).padStart(32, "0");

afterEach(() => vi.useRealTimers());

describe("a knock has to say now, and say it once", () => {
  it("accepts a fresh, unseen knock", () => {
    expect(judge()({ nonce: nonce(1), ts: Date.now() })).toBe(true);
  });

  it("refuses the same frame a second time", () => {
    const fresh = judge();
    const frame = { nonce: nonce(2), ts: Date.now() };
    expect(fresh(frame)).toBe(true);
    // The replay this exists to stop: identical bytes, still in the window.
    expect(fresh(frame)).toBe(false);
  });

  /**
   * The clock is frozen for the two boundary cases, and only for them.
   *
   * The judge reads its own `Date.now()` *after* the test has built `ts` from
   * an earlier one, so a margin of one millisecond is spent by whatever
   * happens in between. That is invisible for the past case — elapsed time
   * carries a stale frame further past the bound — and intermittently fatal
   * for the future one, where the same elapsed time carries the frame back
   * *inside* the window and the refusal correctly stops firing. It failed
   * that way once in a full suite run and passed alone, which is the shape of
   * a test that races rather than one that is wrong.
   *
   * Freezing rather than widening the margin: a margin big enough to outrun
   * scheduling jitter would stop pinning the boundary at all, and the
   * boundary is the rule. With both samples reading one instant, `MAX` and
   * `MAX + 1` can be asserted as themselves — so these now pin that the
   * comparison is strictly `>`, which the racy version could never have
   * claimed.
   */
  it("accepts a frame at exactly the window, in both directions", () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);
    const at = judge();
    expect(at({ nonce: nonce(30), ts: Date.now() - KNOCK_MAX_AGE_MS })).toBe(true);
    expect(at({ nonce: nonce(31), ts: Date.now() + KNOCK_MAX_AGE_MS })).toBe(true);
  });

  it("refuses a frame one millisecond past the window, in both directions", () => {
    // `Math.abs`, as `assertInvite` does it: a clock ahead is as wrong as one
    // behind, and a future timestamp would otherwise buy an attacker a frame
    // that stays valid for as long as they chose.
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);
    const past = judge();
    expect(past({ nonce: nonce(3), ts: Date.now() - KNOCK_MAX_AGE_MS - 1 })).toBe(false);
    expect(past({ nonce: nonce(4), ts: Date.now() + KNOCK_MAX_AGE_MS + 1 })).toBe(false);
  });

  it("does not spend a nonce on a knock it refused for its clock", () => {
    // Otherwise replaying a member's knock early, against a skewed clock,
    // would burn the nonce and make their real knock unusable.
    const fresh = judge();
    const n = nonce(5);
    expect(fresh({ nonce: n, ts: Date.now() - KNOCK_MAX_AGE_MS - 1 })).toBe(false);
    expect(fresh({ nonce: n, ts: Date.now() })).toBe(true);
  });

  it("refuses a knock carrying no nonce at all", () => {
    // The shape the payload had before this existed.
    expect(judge()({ ts: Date.now() })).toBe(false);
    expect(judge()({})).toBe(false);
  });

  it("bounds what a stranger can make this browser remember", () => {
    const fresh = judge();
    for (let i = 0; i < 600; i++) {
      expect(fresh({ nonce: nonce(1000 + i), ts: Date.now() })).toBe(true);
    }
    // The most recent is still remembered...
    expect(fresh({ nonce: nonce(1599), ts: Date.now() })).toBe(false);
    // ...and the earliest has been evicted, which is what proves there is a
    // bound at all. Asserting only the first half passes just as well with no
    // bound, which is how this assertion was wrong the first time.
    expect(fresh({ nonce: nonce(1000), ts: Date.now() })).toBe(true);
  });
});
