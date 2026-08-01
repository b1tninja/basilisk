/**
 * The `otpauth://` Key URI Format — building it, and the harder half, reading
 * one somebody else wrote.
 *
 * The build side is checked against strings real authenticators emit rather
 * than against our own parser, for the reason `ssh-format.test.js` gives:
 * round-tripping through our own code would happily agree with its own bugs.
 * The parse side is checked against the shapes that turn up in the wild —
 * `%3A` separators, lowercase secrets, missing `algorithm=`, a stray space
 * after the colon — plus the ambiguous ones it has to refuse.
 */
import { describe, expect, it } from "vitest";
import {
  buildOtpauthUri,
  isOtpauthUri,
  normalizeSecret,
  normalizeType,
  parseOtpauthUri,
} from "../lib/otp/uri.js";
import { totp } from "../lib/otp/hotp.js";
import { base32ToBytes } from "../lib/toolkit/encode.js";

describe("building", () => {
  it("writes the string Google Authenticator's own documentation shows", () => {
    expect(
      buildOtpauthUri({
        type: "totp",
        secret: "JBSWY3DPEHPK3PXP",
        issuer: "Example",
        account: "alice@google.com",
      })
    ).toBe(
      "otpauth://totp/Example:alice%40google.com" +
        "?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
    );
  });

  it("percent-encodes a space rather than form-encoding it as +", () => {
    // `URLSearchParams.toString()` writes "+", which is form encoding. A
    // reader that percent-decodes the query then shows the issuer as
    // "Big+Corp". Every authenticator writes %20.
    const uri = buildOtpauthUri({
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Big Corp",
      account: "a@b.com",
    });
    expect(uri).toContain("issuer=Big%20Corp");
    expect(uri).not.toContain("+");
    expect(parseOtpauthUri(uri).issuer).toBe("Big Corp");
  });

  it("states algorithm, digits and period even at their defaults", () => {
    // Optional in the format, but the defaults readers assume are not uniform
    // in the wild. A URI that states them cannot be read two ways.
    const uri = buildOtpauthUri({ secret: "JBSWY3DPEHPK3PXP", account: "a@b.com" });
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  it("writes counter= for hotp and period= for totp, never both", () => {
    const h = buildOtpauthUri({ type: "hotp", secret: "JBSWY3DPEHPK3PXP", account: "a", counter: 7 });
    expect(h).toContain("counter=7");
    expect(h).not.toContain("period=");
    const t = buildOtpauthUri({ type: "totp", secret: "JBSWY3DPEHPK3PXP", account: "a" });
    expect(t).toContain("period=30");
    expect(t).not.toContain("counter=");
  });

  it("refuses a URI with no account name in the label", () => {
    expect(() => buildOtpauthUri({ secret: "JBSWY3DPEHPK3PXP" })).toThrow(/account=/);
  });

  it("refuses an issuer containing the label separator", () => {
    expect(() =>
      buildOtpauthUri({ secret: "JBSWY3DPEHPK3PXP", issuer: "a:b", account: "c" })
    ).toThrow(/label separator/);
  });

  it("refuses a secret that is not Base32 before anyone scans it", () => {
    expect(() => buildOtpauthUri({ secret: "not base32!", account: "a" })).toThrow(/Base32/);
    expect(() => buildOtpauthUri({ secret: "", account: "a" })).toThrow(/required/);
    // 0, 1, 8 and 9 are not in the RFC 4648 alphabet.
    expect(() => normalizeSecret("JBSW01389")).toThrow(/Base32/);
  });

  it("normalizes a pasted secret to the uppercase unpadded form", () => {
    expect(normalizeSecret("jbswy3dpehpk3pxp")).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeSecret("JBSW Y3DP EHPK 3PXP")).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeSecret("MFRGGZDF====")).toBe("MFRGGZDF");
  });
});

describe("parsing what other people wrote", () => {
  it("reads the canonical form", () => {
    const rec = parseOtpauthUri(
      "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    );
    expect(rec).toEqual({
      type: "totp",
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Example",
      account: "alice@google.com",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      counter: 0,
    });
  });

  it("splits the label on an encoded separator, not just a literal colon", () => {
    const rec = parseOtpauthUri("otpauth://totp/ACME%20Co%3Ajohn%40example.com?secret=MFRGGZDF");
    expect(rec.issuer).toBe("ACME Co");
    expect(rec.account).toBe("john@example.com");
  });

  it("splits on the *encoded* text, so a decoded colon cannot invent an issuer", () => {
    // The account name really contains a colon; it arrives as %3A with no
    // separator before it. Decoding first and then splitting would hand back
    // an issuer of "weird" and lose half the account.
    const rec = parseOtpauthUri("otpauth://totp/weird%3Aname?secret=MFRGGZDF");
    expect(rec.issuer).toBe("weird");
    expect(rec.account).toBe("name");
    // …and with no separator at all, the whole label is the account.
    expect(parseOtpauthUri("otpauth://totp/plain?secret=MFRGGZDF").account).toBe("plain");
    expect(parseOtpauthUri("otpauth://totp/plain?secret=MFRGGZDF").issuer).toBe("");
  });

  it("tolerates the space some issuers put after the colon", () => {
    const rec = parseOtpauthUri("otpauth://totp/ACME:%20john?secret=MFRGGZDF&issuer=ACME");
    expect(rec.account).toBe("john");
  });

  it("is case-insensitive about the scheme and the type", () => {
    // `otpauth:` is a non-special scheme, so URL leaves the host's case alone
    // — the lowercasing has to be ours.
    const rec = parseOtpauthUri("OTPAUTH://TOTP/a@b.com?secret=MFRGGZDF");
    expect(rec.type).toBe("totp");
  });

  it("fills the format's defaults when the URI omits them", () => {
    const rec = parseOtpauthUri("otpauth://totp/a@b.com?secret=MFRGGZDF");
    expect(rec).toMatchObject({ algorithm: "SHA1", digits: 6, period: 30 });
  });

  it("carries a non-default algorithm, digits and period through", () => {
    const rec = parseOtpauthUri(
      "otpauth://totp/a@b.com?secret=MFRGGZDF&algorithm=SHA512&digits=8&period=60"
    );
    expect(rec).toMatchObject({ algorithm: "SHA512", digits: 8, period: 60 });
  });

  it("refuses a URI whose two issuers disagree", () => {
    // The Key URI Format says a reader should treat this as invalid rather
    // than picking one — two issuers is two accounts.
    expect(() =>
      parseOtpauthUri("otpauth://totp/Acme:a@b.com?secret=MFRGGZDF&issuer=Evil")
    ).toThrow(/ambiguous/);
    // Agreeing is fine, which is the ordinary case.
    expect(
      parseOtpauthUri("otpauth://totp/Acme:a@b.com?secret=MFRGGZDF&issuer=Acme").issuer
    ).toBe("Acme");
  });

  it("refuses a hotp URI with no counter", () => {
    // Defaulting to zero would hand back a confidently wrong code.
    expect(() => parseOtpauthUri("otpauth://hotp/a@b.com?secret=MFRGGZDF")).toThrow(
      /counter=/
    );
    expect(parseOtpauthUri("otpauth://hotp/a@b.com?secret=MFRGGZDF&counter=0").counter).toBe(0);
    expect(parseOtpauthUri("otpauth://hotp/a@b.com?secret=MFRGGZDF&counter=42").counter).toBe(42);
  });

  it("refuses the rest of the malformed family by name", () => {
    expect(() => parseOtpauthUri("https://example.com/totp")).toThrow(/Key URI/);
    expect(() => parseOtpauthUri("otpauth://steam/a?secret=MFRGGZDF")).toThrow(/unknown type/);
    expect(() => parseOtpauthUri("otpauth://totp/a@b.com")).toThrow(/secret= is required/);
    expect(() => parseOtpauthUri("otpauth://totp/?secret=MFRGGZDF")).toThrow(/no account name/);
    expect(() => parseOtpauthUri("otpauth://totp/a?secret=MFRGGZDF&digits=10")).toThrow(
      /6, 7 or 8/
    );
    expect(() => parseOtpauthUri("otpauth://totp/a?secret=MFRGGZDF&period=0")).toThrow(
      /above zero/
    );
    expect(() => parseOtpauthUri("otpauth://totp/a?secret=MFRGGZDF&algorithm=MD5")).toThrow(
      /unknown algorithm/
    );
  });

  it("recognises a Key URI without committing to parsing it", () => {
    expect(isOtpauthUri("  otpauth://totp/a?secret=MFRGGZDF")).toBe(true);
    expect(isOtpauthUri("MFRGGZDF")).toBe(false);
  });
});

describe("build and parse are inverses over the parts that survive", () => {
  it("round-trips a fully specified totp URI", () => {
    const rec = {
      type: "totp",
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Big Corp",
      account: "alice@example.com",
      algorithm: "SHA512",
      digits: 8,
      period: 60,
      counter: 0,
    };
    expect(parseOtpauthUri(buildOtpauthUri(rec))).toEqual(rec);
  });

  it("round-trips a hotp URI, counter and all", () => {
    const rec = {
      type: "hotp",
      secret: "MFRGGZDFMZTWQ2LK",
      issuer: "ACME",
      account: "bob",
      algorithm: "SHA256",
      digits: 7,
      period: 30,
      counter: 9,
    };
    expect(parseOtpauthUri(buildOtpauthUri(rec))).toEqual(rec);
  });

  it("normalizes the type through both directions", () => {
    expect(normalizeType("TOTP")).toBe("totp");
    expect(normalizeType(undefined)).toBe("totp");
    expect(() => normalizeType("steam")).toThrow(/unknown type/);
  });
});

describe("a URI carries enough to compute a code with", () => {
  it("produces the RFC 6238 SHA-1 vector from a URI built round its seed", async () => {
    // The whole enrolment arc, end to end: seed → Base32 → URI → parse →
    // code, landing on a number the RFC published.
    const uri = buildOtpauthUri({
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // ASCII "12345678901234567890"
      issuer: "RFC 6238",
      account: "appendix-b",
      digits: 8,
    });
    const rec = parseOtpauthUri(uri);
    const code = await totp(base32ToBytes(rec.secret), {
      algorithm: rec.algorithm,
      digits: rec.digits,
      period: rec.period,
      seconds: 1111111111,
    });
    expect(code).toBe("14050471");
  });
});
