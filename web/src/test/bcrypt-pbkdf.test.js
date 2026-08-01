/**
 * Blowfish and `bcrypt_pbkdf` against published vectors (§29f).
 *
 * Same rule as ssh-format.test.js: every expected value here was produced by
 * an implementation that is not ours. The Blowfish tables are checked against
 * pi — recomputed here with Machin's formula, not copied from anywhere — so a
 * transcription slip in 1042 hex constants fails a test instead of quietly
 * deriving the wrong key. The KDF is checked against OpenBSD's own regress
 * vectors and Go's `x/crypto/ssh/internal/bcrypt_pbkdf` golden values, which
 * were generated independently of each other.
 *
 * The one thing vectors cannot prove is that we write files `ssh-keygen`
 * accepts; that is asserted in ssh-format.test.js against a real fixture.
 */
import { describe, expect, it } from "vitest";
import { bcryptPbkdf } from "../lib/ssh/bcrypt-pbkdf.js";
import { blfEnc, blfKey, expand0State, initState } from "../lib/ssh/blowfish.js";

const H = (s) => Uint8Array.from(s.replace(/\s/g, "").match(/../g).map((x) => parseInt(x, 16)));
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const enc = (s) => new TextEncoder().encode(s);
/** n bytes of a C string literal — several vectors rely on the trailing NUL. */
const cstr = (s, n) => {
  const b = new Uint8Array(n);
  b.set(enc(s).subarray(0, n));
  return b;
};
const words = (hi, lo) => Int32Array.from([hi | 0, lo | 0]);
const wordsHex = (w) => [...w].map((v) => (v >>> 0).toString(16).padStart(8, "0")).join("");

describe("Blowfish tables are the digits of pi", () => {
  /**
   * Schneier specified the P-array and S-boxes as pi's fractional hex
   * expansion, so they are checkable rather than magic. Machin's formula in
   * BigInt gets there in well under a second — cheaper than trusting that
   * 1042 pasted constants survived the trip.
   */
  function piHexWords(count) {
    // 8 hex digits per word, ~1.205 decimal digits per hex digit, plus slack.
    // Running short does not fail loudly — it silently produces garbage from
    // the first exhausted digit on, which is how the first draft of this test
    // "found" a table mismatch at word 145.
    const SCALE = 10n ** BigInt(count * 10 + 100);
    const atanInv = (x) => {
      const x2 = BigInt(x) * BigInt(x);
      let term = SCALE / BigInt(x);
      let sum = term;
      let n = 1n;
      while (term !== 0n) {
        term = term / x2;
        const t = term / (2n * n + 1n);
        sum += n % 2n === 1n ? -t : t;
        n += 1n;
      }
      return sum;
    };
    let frac = 16n * atanInv(5) - 4n * atanInv(239) - 3n * SCALE;
    const out = [];
    for (let w = 0; w < count; w++) {
      let word = 0;
      for (let d = 0; d < 8; d++) {
        frac *= 16n;
        const digit = frac / SCALE;
        frac -= digit * SCALE;
        word = (word * 16 + Number(digit)) >>> 0;
      }
      out.push(word >>> 0);
    }
    return out;
  }

  it("initState() is pi: 18 P-array words then 1024 S-box words", () => {
    const pi = piHexWords(18 + 1024);
    const state = initState();
    expect([...state.P]).toEqual(pi.slice(0, 18));
    expect([...state.S]).toEqual(pi.slice(18));
  });
});

describe("Blowfish against published vectors", () => {
  it("matches the vector in OpenBSD blowfish.c's own test harness", () => {
    // blf_key("abcdefghijklmnopqrstuvwxyz"); blf_enc({0x424c4f57, 0x46495348})
    const d = words(0x424c4f57, 0x46495348);
    blfEnc(blfKey(enc("abcdefghijklmnopqrstuvwxyz")), d);
    expect(wordsHex(d)).toBe("324ed0fef413a203");
  });

  // Eric Young's ECB set, as republished by Schneier — the DES validation
  // plaintexts run through Blowfish.
  const ECB = [
    ["0000000000000000", "0000000000000000", "4ef997456198dd78"],
    ["ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"],
    ["3000000000000000", "1000000000000001", "7d856f9a613063f2"],
    ["1111111111111111", "1111111111111111", "2466dd878b963c9d"],
    ["0123456789abcdef", "1111111111111111", "61f9c3802281b096"],
    ["1111111111111111", "0123456789abcdef", "7d0cc630afda1ec7"],
    ["fedcba9876543210", "0123456789abcdef", "0aceab0fc6a0a28d"],
    ["7ca110454a1a6e57", "01a1d6d039776742", "59c68245eb05282b"],
    ["0131d9619dc1376e", "5cd54ca83def57da", "b1b8cc0b250f09a0"],
    ["07a1133e4a0b2686", "0248d43806f67172", "1730e5778bea1da4"],
    ["3849674c2602319e", "51454b582ddf440a", "a25e7856cf2651eb"],
    ["04b915ba43feb5b6", "42fd443059577fa2", "353882b109ce8f1a"],
    ["0113b970fd34f2ce", "059b5e0851cf143a", "48f4d0884c379918"],
    ["0170f175468fb5e6", "0756d8e0774761d2", "432193b78951fc98"],
    ["43297fad38e373fe", "762514b829bf486a", "13f04154d69d1ae5"],
    ["07a7137045da2a16", "3bdd119049372802", "2eedda93ffd39c79"],
    ["04689104c2fd3b2f", "26955f6835af609a", "d887e0393c2da6e3"],
    ["37d06bb516cb7546", "164d5e404f275232", "5f99d04f5b163969"],
    ["1f08260d1ac2465e", "6b056e18759f5cca", "4a057a3b24d3977b"],
    ["584023641aba6176", "004bd6ef09176062", "452031c1e4fada8e"],
    ["025816164629b007", "480d39006ee762f2", "7555ae39f59b87bd"],
    ["49793ebc79b3258f", "437540c8698f3cfa", "53c55f9cb49fc019"],
    ["4fb05e1515ab73a7", "072d43a077075292", "7a8e7bfa937e89a3"],
    ["49e95d6d4ca229bf", "02fe55778117f12a", "cf9c5d7a4986adb5"],
    ["018310dc409b26d6", "1d9d5c5018f728c2", "d1abb290658bc778"],
    ["1c587f1c13924fef", "305532286d6f295a", "55cb3774d13ef201"],
    ["0101010101010101", "0123456789abcdef", "fa34ec4847b268b2"],
    ["1f1f1f1f0e0e0e0e", "0123456789abcdef", "a790795108ea3cae"],
    ["e0fee0fef1fef1fe", "0123456789abcdef", "c39e072d9fac631d"],
  ];

  it.each(ECB)("ECB key=%s plain=%s", (key, plain, cipher) => {
    const d = words(parseInt(plain.slice(0, 8), 16), parseInt(plain.slice(8), 16));
    blfEnc(blfKey(H(key)), d);
    expect(wordsHex(d)).toBe(cipher);
  });

  it("expand0State is the same transform blfKey applies", () => {
    // blf_key is documented as initstate + expand0state; if the two ever
    // disagreed, bcrypt_hash's 64-round loop would be schedule-ing something
    // other than what the standard cipher does.
    const state = initState();
    expand0State(state, enc("abcdefghijklmnopqrstuvwxyz"));
    const d = words(0x424c4f57, 0x46495348);
    blfEnc(state, d);
    expect(wordsHex(d)).toBe("324ed0fef413a203");
  });
});

describe("bcrypt_pbkdf against published vectors", () => {
  /**
   * OpenBSD `regress/lib/libutil/bcrypt_pbkdf/bcrypt_pbkdf_test.c`.
   * The 256-byte case is the maximum the function accepts and the one that
   * exercises the output interleave hardest (stride 8).
   */
  const OPENBSD = [
    ["basic", 4, enc("password"), enc("salt"),
      "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9"],
    ["salt is one NUL byte", 4, enc("password"), cstr("", 1),
      "c12b566235eee04c212598970a579a67"],
    ["password is one NUL byte", 4, cstr("", 1), enc("salt"),
      "6051be18c2f4f82cbf0efee5471b4bb9"],
    ["trailing NUL counted in", 4, cstr("password", 9), cstr("salt", 5),
      "7410e44cf4fa07bfaac8a928b1727fac001375e7bf7384370f48efd121743050"],
    ["embedded NUL", 4, cstr("pass\0word", 8), cstr("sa\0lt", 4),
      "c2bffd9db38f6569efef4372f4de83c0"],
    ["embedded NUL, full length", 4, cstr("pass\0word", 9), cstr("sa\0lt", 5),
      "4ba4ac3925c0e8d7f0cdb6bb1684a56f"],
    ["64-byte key", 8, enc("password"), enc("salt"),
      `e1367ec5151a33faac4cc1c144cd23fa15d5548493ecc99b9b5d9c0d3b27bec7
       6227ea66088b849b20ab7aa478010246e74bba51723fefa9f9474d6508845e8d`],
    ["42 rounds", 42, enc("password"), enc("salt"),
      "833cf0dcf56db65608e8f0dc0ce882bd"],
    ["binary password and salt", 8, H("0db3ac94b3ee53284f4a22893b3c24ae"),
      H("3a62f0f0dbcef823cfcc854856ea1028"),
      "204438175eee7ce136c91b49a67923ff"],
    ["256-byte key (the maximum)", 8, H("0db3ac94b3ee53284f4a22893b3c24ae"),
      H("3a62f0f0dbcef823cfcc854856ea1028"),
      `2054b9fff34e3721440334746828e9ed38de4b72e0a69adc170a13b5e8d646385ea4034ae6d26600
       ee2332c5ed40ad557c86e3403fbb30e4e1dc1ae06b99a071368f518d2c426651c9e7e437fd6c915b
       1bbfc3a4cea71491490ea7afb7dd0290a678a4f441128db1792eab2776b21eb4238e0715add4127d
       ff44e4b3e4cc4c4f9970083f3f74bd698873fdf648844f75c9bf7f9e0c4d9e5d89a7783997492966
       616707611cb901de31a19726b6e08c3a8001661f2d5c9dcc33b4aa072f90dd0b3f548d5eeba42113
       97e2fb062e526e1d68f46a4ce256185b4badc2685fbe78e1c7657b59f83ab9ab80cf9318d6add1f5
       933f12d6f36182c8e8115f68030a1244`],
  ];

  it.each(OPENBSD)("OpenBSD regress: %s", async (_name, rounds, pass, salt, want) => {
    const expected = H(want);
    expect(hex(await bcryptPbkdf(pass, salt, expected.length, rounds))).toBe(hex(expected));
  });

  // golang.org/x/crypto/ssh/internal/bcrypt_pbkdf — a separate implementation
  // with separately generated goldens.
  const GO = [
    ["ascii", 12, enc("password"), enc("salt"),
      "1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a"],
    ["NUL-separated", 3, enc("passwordy\0PASSWORD\0"), enc("salty\0SALT\0"),
      "7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad"],
    ["non-ASCII, 88-byte key", 8, enc("секретное слово"), enc("посолить немножко"),
      `8df43fc6fe131fc47f0c9e39224bd94c70b6fcc8ee8135faddf61156e6cb2733ea765f315a3e1e4a
       fc35bf8687d189254c1e05a6fe80c0617f9183d67260d6a115c6c94e3603e2303fbb43a76a64523f
       fda686b1d4518543`],
  ];

  it.each(GO)("Go x/crypto golden: %s", async (_name, rounds, pass, salt, want) => {
    const expected = H(want);
    expect(hex(await bcryptPbkdf(pass, salt, expected.length, rounds))).toBe(hex(expected));
  });

  it("scatters output rather than concatenating blocks", () => {
    /*
     * The interleave is the deviation most likely to be "fixed" by someone
     * reading this as ordinary PBKDF2, and a wrong version still returns
     * plausible-looking bytes. Pin the property directly: with keylen 64 the
     * stride is 2, so the first PRF block lands on the even indices and the
     * second on the odd ones. Concatenation would make the first 32 bytes a
     * 32-byte derivation instead — this asserts they are not.
     */
    return Promise.all([
      bcryptPbkdf(enc("password"), enc("salt"), 64, 8),
      bcryptPbkdf(enc("password"), enc("salt"), 32, 8),
    ]).then(([sixtyFour, thirtyTwo]) => {
      expect(hex(sixtyFour.slice(0, 32))).not.toBe(hex(thirtyTwo));
      // …and the 32-byte answer is the even-indexed half of the 64-byte one,
      // because both are block `count = 1` of the same derivation.
      expect(hex(sixtyFour.filter((_, i) => i % 2 === 0))).toBe(hex(thirtyTwo));
    });
  });

  it("refuses inputs the original refuses", async () => {
    await expect(bcryptPbkdf(enc("p"), enc("s"), 32, 0)).rejects.toThrow(/rounds/);
    await expect(bcryptPbkdf(new Uint8Array(0), enc("s"), 32, 4)).rejects.toThrow(/passphrase/);
    await expect(bcryptPbkdf(enc("p"), new Uint8Array(0), 32, 4)).rejects.toThrow(/salt/);
    await expect(bcryptPbkdf(enc("p"), enc("s"), 0, 4)).rejects.toThrow(/keylen/);
    await expect(bcryptPbkdf(enc("p"), enc("s"), 1025, 4)).rejects.toThrow(/keylen/);
  });
});
