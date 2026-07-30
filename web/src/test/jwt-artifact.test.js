/**
 * JwtArtifact — the escalation rules, and the one appearance invariant.
 *
 * The rendering is exercised in the catalog (`/toolkit-widgets` §jwtartifact),
 * which is where a widget's real states get reviewed. What is worth pinning
 * in a test is the decision underneath: when a token's remaining life crosses
 * into warn and into error, and that an *unverified* body can never be styled
 * like a verified one — the failure mode a token inspector exists to avoid.
 */
import { describe, expect, it } from "vitest";
import {
  EXPIRY_URGENT_SECONDS,
  EXPIRY_WARN_SECONDS,
  expiryTone,
  hasJoseRenderer,
  relativeSeconds,
} from "../toolkit/widgets/JwtArtifact";

describe("expiry escalation", () => {
  it("stays calm while there is real time left", () => {
    expect(expiryTone(EXPIRY_WARN_SECONDS + 1)).toBe("ok");
    expect(expiryTone(86_400)).toBe("ok");
  });

  it("warns from five minutes out", () => {
    expect(expiryTone(EXPIRY_WARN_SECONDS)).toBe("warn");
    expect(expiryTone(EXPIRY_URGENT_SECONDS + 1)).toBe("warn");
  });

  it("goes red in the last minute, before the token is actually dead", () => {
    // The point of escalating early: a token with 40 seconds left will be
    // expired by the time you have finished pasting it somewhere.
    expect(expiryTone(EXPIRY_URGENT_SECONDS)).toBe("error");
    expect(expiryTone(1)).toBe("error");
  });

  it("treats the exact moment of expiry, and everything after, as expired", () => {
    expect(expiryTone(0)).toBe("error");
    expect(expiryTone(-1)).toBe("error");
    expect(expiryTone(-86_400)).toBe("error");
  });

  it("has no verdict for a token with no exp, rather than a reassuring one", () => {
    // A token that never expires is not a *fresh* token; green would say
    // something the claims do not.
    expect(expiryTone(null)).toBe("muted");
  });
});

describe("relative time", () => {
  it("reports seconds while seconds matter and coarsens after", () => {
    expect(relativeSeconds(45)).toBe("in 45s");
    expect(relativeSeconds(90)).toBe("in 1m 30s");
    expect(relativeSeconds(3700)).toBe("in 1h 1m");
    expect(relativeSeconds(200_000)).toBe("in 2d");
  });

  it("reads the other way round for the past", () => {
    expect(relativeSeconds(-45)).toBe("45s ago");
    expect(relativeSeconds(-200_000)).toBe("2d ago");
  });
});

describe("hasJoseRenderer", () => {
  it("accepts either compact serialization", () => {
    expect(hasJoseRenderer({ kind: "jws", verified: true, header: {}, claims: null })).toBe(
      true
    );
    expect(hasJoseRenderer({ kind: "jwe", verified: true, header: {}, claims: null })).toBe(
      true
    );
  });

  it("declines anything that is not a JOSE body, so other rows keep their preview", () => {
    for (const v of [null, undefined, {}, "jws", { kind: "sdp" }, 7]) {
      expect(hasJoseRenderer(v), String(v)).toBe(false);
    }
  });
});
