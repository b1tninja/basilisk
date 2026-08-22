/**
 * "Copy invite" has to copy the thing the paste box accepts.
 *
 * Four controls say "Copy invite". Three of them copied
 * `quorumState.invite` — a status line, `quorum <room> · 3 keys · <host>` —
 * and a fifth read `inviteUrl || quorumState.invite`, degrading to that
 * string exactly when the link was missing. There was nothing wrong with the
 * paste box: this app's own reader is the judge, and it says the status line
 * is worth nothing while the link carries the room.
 *
 * The first two tests are the behavioural claim and need no DOM; the source
 * assertions below stop the wiring regressing, which is where the defect
 * actually lived.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { parseInviteAudience, pasteReadout } from "../lib/toolkit/session-flow.js";
import { hashForJoin, toolkitShareUrl } from "../lib/toolkit/fragment.js";

const SHELL = readFileSync(new URL("../toolkit/ToolkitShell.tsx", import.meta.url), "utf8");

const A = "83421F2C412BEE93DB4B5B57F08AE70E2B46B650";
const B = "A2DDD8BD53ACF97E4B9925D1C30E7F2A0F21B4A9";
/** Exactly what `quorum-ops.js` builds for `quorumState.invite`. */
const STATUS_LINE = "quorum 26TKM6KG52GCQDN3 · 2 keys · wss://basilisk.example";

describe("the invitation is the link, and the reader agrees", () => {
  it("finds nothing in the status line", () => {
    // Not an opinion about the string — the room's own extractor returns no
    // fingerprint, so pasting it can only ever report finding nobody.
    expect(parseInviteAudience(STATUS_LINE)).toEqual([]);
    expect(pasteReadout(STATUS_LINE, []).kind).toBe("nothing");
  });

  it("finds the room in the link", () => {
    const hash = hashForJoin([A, B]);
    expect(hash.ok).toBe(true);
    const url = toolkitShareUrl(hash.hash, { origin: "https://keys.example" });
    expect(parseInviteAudience(url)).toEqual([A, B]);
    const read = pasteReadout(url, []);
    // The marker is what makes it an *invitation* rather than a list of
    // people: it settles that the sender is the one starting the session.
    expect(read.kind).toBe("invite");
    expect(read.role).toBe("join");
  });
});

describe("every Copy invite control is wired to the link", () => {
  it("no control copies the status line", () => {
    // Written as an absence because no spelling of it would be right.
    expect(SHELL).not.toMatch(/writeText\(\s*nb\.quorumState\.invite\s*\)/);
    expect(SHELL).not.toMatch(/copyText\(\s*inviteUrl\s*\|\|\s*nb\.quorumState\.invite\s*\)/);
  });

  it("routes every control through one handler", () => {
    // Five call sites, one function: four controls cannot disagree about what
    // an invitation is if there is only one answer.
    const wired = SHELL.match(/onCopyInvite(?:=\{|: )copyInvite\b/g) || [];
    expect(wired.length).toBeGreaterThanOrEqual(5);
    expect(SHELL).toMatch(/const copyInvite = useCallback\(/);
  });

  it("refuses instead of copying something else when there is no link", () => {
    // The fallback is the defect: it fails as a paste that finds nothing
    // rather than as a sentence saying why.
    expect(SHELL).toMatch(/if \(!inviteUrl\) \{\s*\r?\n\s*nb\.refuse\(NO_LINK_YET\);/);
    expect(SHELL).toMatch(/import \{ NO_LINK_YET \} from "\.\/widgets\/InviteCard"/);
  });

  it("still shows the status line where it is a description, not an invitation", () => {
    // It is a fine sentence about the room; it was only ever wrong on a
    // clipboard. Deleting it would be the opposite over-correction.
    expect(SHELL).toMatch(/sessionInvite=\{nb\.quorumState\.invite\}/);
  });
});
