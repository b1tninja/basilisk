/**
 * Which half of the exchange an SDP blob is (§30d).
 *
 * The rule lives in `sdpRole` rather than inline in `execCreateAnswer` for the
 * reason `offerCollisionAction` does: an `RTCPeerConnection` does not exist
 * under `environment: "node"`, and a rule that can only be checked in a browser
 * gets checked once. The browser half — that Chromium really does accept an
 * answer's SDP as an offer, which is what made the guard necessary — is in
 * `e2e/rtc-transport.e2e.js`.
 */

import { describe, expect, it } from "vitest";
import { ANSWER_NOT_AN_OFFER, sdpRole } from "../lib/toolkit/rtc-ops.js";

/** A real Chromium data-channel offer, trimmed to the lines that matter. */
const OFFER = [
  "v=0",
  "o=- 7671233154645700613 2 IN IP4 127.0.0.1",
  "s=-",
  "t=0 0",
  "m=application 65412 UDP/DTLS/SCTP webrtc-datachannel",
  "a=ice-ufrag:2XBm",
  "a=fingerprint:sha-256 2A:E6:21:9D:B7:59:4C:3E",
  "a=setup:actpass",
  "a=sctp-port:5000",
].join("\r\n");

const ANSWER = OFFER.replace("a=setup:actpass", "a=setup:active");

describe("sdpRole", () => {
  it("reads an offer by its uncommitted DTLS role", () => {
    // RFC 8842 §5.1: an offerer does not yet know which side is the DTLS
    // client, so it must advertise both.
    expect(sdpRole(OFFER)).toBe("offer");
  });

  it("reads an answer by its committed DTLS role", () => {
    expect(sdpRole(ANSWER)).toBe("answer");
    expect(sdpRole(OFFER.replace("a=setup:actpass", "a=setup:passive"))).toBe("answer");
    expect(sdpRole(OFFER.replace("a=setup:actpass", "a=setup:holdconn"))).toBe("answer");
  });

  it("declines to guess when the blob says nothing about its role", () => {
    // The refusal is deliberately one-sided: a stack that omits `a=setup:`
    // still has an answerable offer, and refusing it would trade a real defect
    // for a worse one.
    expect(sdpRole(OFFER.replace("a=setup:actpass\r\n", ""))).toBe("unknown");
    expect(sdpRole("")).toBe("unknown");
    expect(sdpRole("v=0\r\ns=-")).toBe("unknown");
  });

  it("declines to guess on a bundle whose sections disagree", () => {
    // Mixed roles across m-sections are not a shape this op should adjudicate;
    // "unknown" lets the browser reject it with its own, better, message.
    const mixed = `${OFFER}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=setup:active`;
    expect(sdpRole(mixed)).toBe("unknown");
  });

  it("matches only at the start of a line", () => {
    // `a=setup:` inside another attribute's value must not be read as the role.
    expect(sdpRole("v=0\r\na=label:not a=setup:active really")).toBe("unknown");
  });

  it("names the mistake and the fix in its refusal", () => {
    // The message is the whole value of the guard: the pipeline it fires in
    // has an offer sitting one step upstream, and saying so is the difference
    // between a fix and a puzzle.
    expect(ANSWER_NOT_AN_OFFER).toMatch(/already an answer/);
    expect(ANSWER_NOT_AN_OFFER).toMatch(/a=setup:active/);
    expect(ANSWER_NOT_AN_OFFER).toMatch(/Pipe the offer from the other side/);
  });
});
