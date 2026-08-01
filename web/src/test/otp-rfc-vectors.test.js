/**
 * HOTP / TOTP against the published RFC test vectors.
 *
 * Every number below is copied from RFC 4226 Appendix D and RFC 6238
 * Appendix B — an authority outside this repository, produced by an
 * implementation that has never seen ours. `ssh-format.test.js` holds the
 * same line for SSH: interop is asserted against fixtures another
 * implementation produced, not by round-tripping through our own code, which
 * would happily agree with its own bugs.
 *
 * Two footguns the vectors themselves contain:
 *
 *  1. RFC 4226's table publishes the *intermediate* values too — the full
 *     HMAC-SHA-1 and the dynamically truncated integer. Asserting those as
 *     well as the six digits means a bug in truncation cannot hide behind a
 *     modulo that happens to land right.
 *  2. RFC 6238's SHA-256 and SHA-512 rows do **not** use the same 20-byte
 *     seed as the SHA-1 rows. The reference implementation in Appendix A
 *     defines `seed32` and `seed64` as the ASCII digits repeated out to 32 and
 *     64 bytes. An implementation fed the 20-byte seed "fails" vectors that
 *     are perfectly correct.
 */
import { describe, expect, it } from "vitest";
import {
  counterBytes,
  hotp,
  normalizeCode,
  secondsRemaining,
  timeCounter,
  totp,
  truncate,
  verifyHotp,
  verifyTotp,
} from "../lib/otp/hotp.js";
import { bytesToHex, hexToBytes } from "../lib/toolkit/encode.js";

const ascii = (s) => new TextEncoder().encode(s);

/** RFC 4226 Appendix D: "the ASCII string 12345678901234567890". */
const SEED_SHA1 = ascii("12345678901234567890");
/** RFC 6238 Appendix A, `seed32` — the same digits out to 32 bytes. */
const SEED_SHA256 = ascii("12345678901234567890123456789012");
/** RFC 6238 Appendix A, `seed64` — out to 64 bytes. */
const SEED_SHA512 = ascii(
  "1234567890123456789012345678901234567890123456789012345678901234"
);

describe("RFC 4226 Appendix D — HOTP test values", () => {
  it("pins the seed as the RFC states it, in hex", () => {
    expect(bytesToHex(SEED_SHA1)).toBe("3132333435363738393031323334353637383930");
    expect(SEED_SHA1).toHaveLength(20);
    expect(SEED_SHA256).toHaveLength(32);
    expect(SEED_SHA512).toHaveLength(64);
  });

  /** count, HMAC-SHA-1 (hex), truncated (decimal), HOTP */
  const VECTORS = [
    [0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 1284755224, "755224"],
    [1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab", 1094287082, "287082"],
    [2, "0bacb7fa082fef30782211938bc1c5e70416ff44", 137359152, "359152"],
    [3, "66c28227d03a2d5529262ff016a1e6ef76557ece", 1726969429, "969429"],
    [4, "a904c900a64b35909874b33e61c5938a8e15ed1c", 1640338314, "338314"],
    [5, "a37e783d7b7233c083d4f62926c7a25f238d0316", 868254676, "254676"],
    [6, "bc9cd28561042c83f219324d3c607256c03272ae", 1918287922, "287922"],
    [7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 82162583, "162583"],
    [8, "1b3c89f65e6c9e883012052823443f048b4332db", 673399871, "399871"],
    [9, "1637409809a679dc698207310c8c7fc07290d9e5", 645520489, "520489"],
  ];

  it.each(VECTORS)("count %i produces %s → %i → %s", async (count, mac, truncated, code) => {
    expect(await hotp(SEED_SHA1, count, { algorithm: "SHA1", digits: 6 })).toBe(code);
    // The intermediates, so a right answer for the wrong reason is caught:
    // the RFC's truncated integer is the 31-bit number before the modulo,
    // and `truncate` reaches it at 10 digits (2^31 is ten digits wide).
    expect(Number(truncate(hexToBytes(mac), 10))).toBe(truncated);
    expect(truncate(hexToBytes(mac), 6)).toBe(code);
  });

  it("hashes the counter as eight big-endian bytes, per §5.1", () => {
    expect(bytesToHex(counterBytes(0))).toBe("0000000000000000");
    expect(bytesToHex(counterBytes(1))).toBe("0000000000000001");
    // The value the four-byte shortcut gets wrong.
    expect(bytesToHex(counterBytes(0x1_0000_0000n))).toBe("0000000100000000");
  });
});

describe("RFC 6238 Appendix B — TOTP test vectors", () => {
  const SEED = { SHA1: SEED_SHA1, SHA256: SEED_SHA256, SHA512: SEED_SHA512 };

  /** time (sec), T (hex), TOTP, mode — all eight digits, X = 30, T0 = 0 */
  const VECTORS = [
    [59, "0000000000000001", "94287082", "SHA1"],
    [59, "0000000000000001", "46119246", "SHA256"],
    [59, "0000000000000001", "90693936", "SHA512"],
    [1111111109, "00000000023523EC", "07081804", "SHA1"],
    [1111111109, "00000000023523EC", "68084774", "SHA256"],
    [1111111109, "00000000023523EC", "25091201", "SHA512"],
    [1111111111, "00000000023523ED", "14050471", "SHA1"],
    [1111111111, "00000000023523ED", "67062674", "SHA256"],
    [1111111111, "00000000023523ED", "99943326", "SHA512"],
    [1234567890, "000000000273EF07", "89005924", "SHA1"],
    [1234567890, "000000000273EF07", "91819424", "SHA256"],
    [1234567890, "000000000273EF07", "93441116", "SHA512"],
    [2000000000, "0000000003F940AA", "69279037", "SHA1"],
    [2000000000, "0000000003F940AA", "90698825", "SHA256"],
    [2000000000, "0000000003F940AA", "38618901", "SHA512"],
    [20000000000, "0000000027BC86AA", "65353130", "SHA1"],
    [20000000000, "0000000027BC86AA", "77737706", "SHA256"],
    [20000000000, "0000000027BC86AA", "47863826", "SHA512"],
  ];

  it.each(VECTORS)("t=%i (%s) %s under %s", async (seconds, tHex, code, mode) => {
    expect(
      await totp(SEED[mode], { algorithm: mode, digits: 8, period: 30, seconds })
    ).toBe(code);
  });

  it("computes the same T the RFC prints beside each row", () => {
    for (const [seconds, tHex] of VECTORS) {
      expect(bytesToHex(counterBytes(timeCounter(seconds, 30, 0))).toUpperCase(), String(seconds)).toBe(
        tHex
      );
    }
  });

  it("fails the SHA-256 rows if fed the 20-byte seed — the footgun, pinned", async () => {
    // Not a hypothetical: implementations "fail" Appendix B this way. If this
    // ever passes, someone has quietly made the seeds equal.
    const wrong = await totp(SEED_SHA1, {
      algorithm: "SHA256",
      digits: 8,
      period: 30,
      seconds: 59,
    });
    expect(wrong).not.toBe("46119246");
  });

  it("moves to the next code exactly on the step boundary", async () => {
    const at = (seconds) => totp(SEED_SHA1, { digits: 8, period: 30, seconds });
    expect(await at(59)).toBe("94287082");
    expect(await at(30)).toBe("94287082"); // same step: floor(30/30) === 1
    expect(await at(29)).not.toBe("94287082"); // step 0
    expect(await at(60)).not.toBe("94287082"); // step 2
  });
});

describe("verification accepts drift, and only the drift it was asked to", () => {
  const opts = { algorithm: "SHA1", digits: 8, period: 30, seconds: 1111111111 };

  it("accepts the current step at window 0", async () => {
    const v = await verifyTotp("14050471", SEED_SHA1, { ...opts, window: 0 });
    expect(v).toEqual({ ok: true, delta: 0, counter: 0x23523edn });
  });

  it("refuses the neighbouring step at window 0", async () => {
    // 07081804 is the code for t=1111111109, one step earlier.
    const v = await verifyTotp("07081804", SEED_SHA1, { ...opts, window: 0 });
    expect(v.ok).toBe(false);
  });

  it("accepts it at window 1, and reports which way the clock is off", async () => {
    const v = await verifyTotp("07081804", SEED_SHA1, { ...opts, window: 1 });
    expect(v.ok).toBe(true);
    expect(v.delta).toBe(-1);
  });

  it("accepts a future step too — drift has two directions", async () => {
    // The code for t = 1111111111 + 30.
    const ahead = await totp(SEED_SHA1, { ...opts, seconds: 1111111141 });
    const v = await verifyTotp(ahead, SEED_SHA1, { ...opts, window: 1 });
    expect(v).toMatchObject({ ok: true, delta: 1 });
  });

  it("still refuses two steps out at window 1", async () => {
    const far = await totp(SEED_SHA1, { ...opts, seconds: 1111111171 });
    expect((await verifyTotp(far, SEED_SHA1, { ...opts, window: 1 })).ok).toBe(false);
    expect((await verifyTotp(far, SEED_SHA1, { ...opts, window: 2 })).ok).toBe(true);
  });

  it("takes the code as the user sees it, spaces and all", async () => {
    expect(normalizeCode("140 50471")).toBe("14050471");
    expect((await verifyTotp("140 50471", SEED_SHA1, opts)).ok).toBe(true);
    expect(() => normalizeCode("14o50471")).toThrow(/not a code/);
  });

  it("refuses a code of the wrong length rather than comparing a prefix", async () => {
    expect((await verifyTotp("1405047", SEED_SHA1, opts)).ok).toBe(false);
  });
});

describe("HOTP verification looks ahead, never behind", () => {
  it("resynchronises up to the look-ahead window", async () => {
    // The server thinks the counter is 3; the client has run on to 5.
    const v = await verifyHotp("254676", SEED_SHA1, 3, { window: 3 });
    expect(v).toMatchObject({ ok: true, delta: 2, counter: 5n });
  });

  it("never accepts a counter the server has already passed", async () => {
    // 969429 is counter 3. A server at 5 must not take it again — that is a
    // replay, and a ±window would wave it through.
    const v = await verifyHotp("969429", SEED_SHA1, 5, { window: 3 });
    expect(v.ok).toBe(false);
  });

  it("defaults to a window at all, so a one-off skip is survivable", async () => {
    expect((await verifyHotp("287082", SEED_SHA1, 0)).ok).toBe(true); // counter 1
  });
});

describe("the shapes the parameters are allowed to take", () => {
  it("refuses digits outside 6–8", async () => {
    await expect(hotp(SEED_SHA1, 0, { digits: 5 })).rejects.toThrow(/6, 7 or 8/);
    await expect(hotp(SEED_SHA1, 0, { digits: 9 })).rejects.toThrow(/6, 7 or 8/);
  });

  it("refuses an unknown algorithm by name", async () => {
    await expect(hotp(SEED_SHA1, 0, { algorithm: "MD5" })).rejects.toThrow(/unknown algorithm/);
  });

  it("accepts the spellings a URI and a user each use", async () => {
    const canon = await hotp(SEED_SHA1, 0, { algorithm: "SHA1" });
    for (const spelling of ["sha1", "SHA-1", "sha_1", " Sha1 "]) {
      expect(await hotp(SEED_SHA1, 0, { algorithm: spelling }), spelling).toBe(canon);
    }
  });

  it("refuses an empty secret rather than keying an HMAC with nothing", async () => {
    await expect(hotp(new Uint8Array(0), 0)).rejects.toThrow(/empty/);
  });

  it("counts down the seconds left in the step", () => {
    expect(secondsRemaining({ period: 30, seconds: 1111111111 })).toBe(29);
    expect(secondsRemaining({ period: 30, seconds: 1111111109 })).toBe(1);
    expect(secondsRemaining({ period: 30, seconds: 1111111110 })).toBe(30);
  });
});
