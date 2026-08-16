/**
 * A fingerprint has one presentation, and the abbreviation carries no key bits.
 *
 * The product used to contradict itself out loud. `pages/index.tsx` told the
 * reader "Short (8-character) key IDs are collision-prone. Confirm the full
 * fingerprint out of band before trusting a key" — while six surfaces printed
 * `AABBCCDD…EEFF`, twelve hex characters, and `documents.js` printed eight,
 * which is the exact length the sentence warns about. A reader comparing what
 * the UI showed them was doing precisely what the UI told them not to.
 *
 * The elided form had already cost a feature: `projectRosterPeers` used it as a
 * peer *identity*, `CellAssign` wrote `@83421F2C…B650` into the recipe, the
 * parser refused it, and `ToolkitShell` caught the failure into `return null`,
 * killing `runPlan` for every session with a peer. It is not merely unsafe to
 * compare; it was never a legal name.
 *
 * These assertions render the component with `react-dom/server`, which is what
 * this suite can do in `environment: "node"` — enough to see what reaches the
 * page and what the copy control carries, which is the whole question.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  ALREADY_IN_ROOM,
  Fingerprint,
  fingerprintActions,
} from "../components/ui/fingerprint.tsx";
import { CONTENTLESS_REASONS } from "../components/ui/refusal.tsx";
import { findFingerprints } from "../lib/pgp/verify-fpr.js";
import { formatFingerprint } from "../lib/utils.js";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");

/** v4 and v6, which are the only two lengths a fingerprint has here. */
const V4 = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const V6 = "1AE7F1E4B2C6D0938A5F47B3C1D9E2064F8A3B5C7D1E9F02A4B6C8D0E2F41537";
/** An `SHA256:` id from the SSH cards — a fingerprint of a different shape. */
const SSH = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

const render = (props) => renderToStaticMarkup(createElement(Fingerprint, props));

/** The whole value the copy control carries, as the markup publishes it. */
function copyPayload(markup) {
  const m = /class="fingerprint-value"[^>]*title="([^"]*)"/.exec(markup);
  if (!m) throw new Error(`no fingerprint value control in:\n${markup}`);
  return m[1];
}

/** Everything a reader can actually see, tags stripped. */
function visibleText(markup) {
  return markup.replace(/<[^>]*>/g, " ");
}

describe("the printed spelling round-trips, as a property of the component", () => {
  /**
   * The anti-drift guard `findFingerprints` was built with, moved to where the
   * printing now happens.
   *
   * It used to be a property of two functions that happened to agree —
   * `formatFingerprint` printed and `findFingerprints` recovered, and nothing
   * tied either to what the screen showed. Six widgets printing their own
   * abbreviation is exactly what that gap allows. The guard is worth something
   * only if it holds for the thing a reader can copy off the page.
   */
  it("recovers every fingerprint the component copies", () => {
    for (const fpr of [V4, V6]) {
      const copied = copyPayload(render({ fpr }));
      expect(findFingerprints(copied), fpr).toEqual([fpr]);
    }
  });

  it("copies the same spelling from the compact form as from the full one", () => {
    // The point of the exercise: what leaves on the clipboard does not depend
    // on how much room the row had.
    expect(copyPayload(render({ fpr: V4, variant: "compact", label: "peer2" }))).toBe(
      copyPayload(render({ fpr: V4 }))
    );
    expect(copyPayload(render({ fpr: V4 }))).toBe(formatFingerprint(V4));
  });

  it("carries an SSH id through unaltered", () => {
    // `ssh-keygen -lf` prints this and an `allowed_signers` line is compared
    // against it character for character, so grouping it would be a different
    // value wearing the same name.
    expect(copyPayload(render({ fpr: SSH }))).toBe(SSH);
  });
});

describe("what reaches the screen", () => {
  it("shows the whole fingerprint in the full variant", () => {
    const seen = visibleText(render({ fpr: V4 }));
    expect(seen).toContain(formatFingerprint(V4));
  });

  /**
   * The decision this component exists to make.
   *
   * `AABBCCDD…EEFF` is 48 bits — 65 536× the 32 that were forged wholesale in
   * 2016, and still a number nobody should stake a key exchange on. Worse, the
   * reader cannot tell: it shows the two ends, which are the characters people
   * compare aloud, and says nothing about the 112 bits behind the ellipsis. So
   * the compact form publishes no number of bits at all — it shows the name the
   * row already has, and the whole value is one press away.
   */
  it("publishes no part of the key in the compact variant", () => {
    const seen = visibleText(render({ fpr: V4, variant: "compact", label: "peer2" }));
    expect(seen).toContain("peer2");
    // Not "no long run of hex" — no run of four, which is one printed group.
    for (let i = 0; i + 4 <= V4.length; i++) {
      expect(seen, `leaked ${V4.slice(i, i + 4)}`).not.toContain(V4.slice(i, i + 4));
    }
  });

  it("says how much it is about to copy, in the control's own name", () => {
    // A control that copies must say what it copied, and the label has to hold
    // before the press as well as the status line after it.
    expect(render({ fpr: V4 })).toContain("all 40 characters");
    expect(render({ fpr: V6 })).toContain("all 64 characters");
  });
});

/**
 * The menu lives in a portal, so `renderToStaticMarkup` never sees a row of it.
 * `fingerprintActions` is where the rows and their refusals are decided, and it
 * is what the component renders — asserting it here is asserting the menu.
 */
describe("the refusals name the state the reader is in", () => {
  const by = (rows, id) => rows.find((r) => r.id === id);

  it("refuses to add a key that is already in the room, and says which", () => {
    const rows = fingerprintActions({ fpr: V4, canAdd: true, inAudience: true });
    expect(by(rows, "audience").refusal).toBe(ALREADY_IN_ROOM);
    expect(ALREADY_IN_ROOM).toMatch(/already in the room/);
    expect(
      by(fingerprintActions({ fpr: V4, canAdd: true }), "audience").refusal
    ).toBeUndefined();
  });

  it("offers no add at all where there is no room to add to", () => {
    // Absent, not refused: a surface with no session has not declined anything.
    expect(by(fingerprintActions({ fpr: V4 }), "audience")).toBeUndefined();
  });

  it("refuses the keyserver, the trust map and the room for an SSH id", () => {
    const rows = fingerprintActions({ fpr: SSH, canAdd: true });
    for (const id of ["keyserver", "trusted", "never", "audience"]) {
      expect(by(rows, id).refusal, id).toMatch(/SSH key fingerprint/);
    }
    // …and no link, because `/key?fpr=` is hex and there is no hex here.
    expect(by(rows, "keyserver").href).toBeUndefined();
    // Copy is the one thing that still works, which is the point: an SSH id is
    // a fingerprint, and copying the whole of one matters exactly as much.
    expect(by(rows, "copy").refusal).toBeUndefined();
  });

  it("does not call a malformed value an SSH key", () => {
    // Two states, two sentences. A 20-character hex string is not a fingerprint
    // of anything, and telling that reader they are looking at an SSH key would
    // be a confident lie in the one place the product is being trusted to say
    // what it knows. `KeyCard` renders exactly this on a key whose kind carries
    // no fingerprint of a length OpenPGP uses.
    const rows = fingerprintActions({ fpr: "AABBCCDDEEFF00112233", canAdd: true });
    for (const id of ["keyserver", "trusted", "never", "audience"]) {
      expect(by(rows, id).refusal, id).toMatch(/not a whole OpenPGP fingerprint/);
      expect(by(rows, id).refusal, id).not.toMatch(/SSH/);
    }
    expect(by(rows, "copy").refusal).toBeUndefined();
  });

  it("refuses a second identical trust mark, naming the mark already there", () => {
    const rows = fingerprintActions({ fpr: V4, trust: "trusted" });
    expect(by(rows, "trusted").refusal).toMatch(/already marked trusted/);
    expect(by(rows, "never").refusal).toBeUndefined();
    expect(by(rows, "clear").refusal).toBeUndefined();
    // And with no mark at all, clearing is what has nothing to do.
    expect(by(fingerprintActions({ fpr: V4 }), "clear").refusal).toMatch(
      /no trust mark on this key/
    );
  });

  it("links an OpenPGP key to its keyserver page by the whole fingerprint", () => {
    expect(by(fingerprintActions({ fpr: V4 }), "keyserver").href).toBe(
      `/key?fpr=${V4}`
    );
  });

  it("gives every refusal a sentence with something in it", () => {
    // The list `refusal.tsx` refuses wholesale: "Unavailable" restates
    // aria-disabled and leaves the reader where they were.
    const rows = [
      ...fingerprintActions({ fpr: SSH, canAdd: true }),
      ...fingerprintActions({ fpr: V4, canAdd: true, inAudience: true, trust: "never" }),
    ];
    for (const { id, refusal } of rows) {
      if (!refusal) continue;
      expect(refusal.length, id).toBeGreaterThan(24);
      expect(CONTENTLESS_REASONS, id).not.toContain(refusal.trim().toLowerCase());
    }
  });
});

/* ───────────────────────── the sweep ───────────────────────── */

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "node_modules" || name === "test") continue;
      walk(path, out);
    } else if (/\.(js|ts|tsx)$/.test(path)) {
      out.push(path);
    }
  }
  return out;
}

const rel = (path) => relative(WEB_ROOT, path).replace(/\\/g, "/");

describe("nothing prints part of a fingerprint any more", () => {
  /**
   * Comments stripped, the reverse of the reason `disabled-needs-reason.test.js`
   * strips them: here the prose is the *history*. Several of these files explain
   * at length what `shortFpr` was and why it went, and a naive grep would read
   * the explanation as the thing it explains.
   */
  const strip = (t) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const SOURCES = walk(SRC_ROOT).map((path) => ({
    file: rel(path),
    text: strip(readFileSync(path, "utf8")),
  }));

  it("has no `shortFpr` left anywhere in the app", () => {
    // Six private copies of one function, five of them in widgets. The name is
    // gone rather than centralised: a shared `shortFpr` would be the same
    // defect with one import.
    const left = SOURCES.filter((s) => /\bshortFpr\b/.test(s.text)).map((s) => s.file);
    expect(left, left.join(", ")).toEqual([]);
  });

  /** `${x.slice(0, 8)}…${x.slice(-4)}` — the elided form, in any spelling. */
  const BOTH_ENDS =
    /slice\(\s*0\s*,\s*\d+\s*\)[^\n]{0,40}…[^\n]{0,40}slice\(\s*-\s*\d+\s*\)/;
  /** `${x.slice(0, 8)}…` — the same defect with one end instead of two. */
  const ONE_END = /slice\(\s*0\s*,\s*\d+\s*\)[^\n]{0,40}…/;
  /** `x.slice(-8)` — the short key id, with no ellipsis to give it away. */
  const SHORT_KEY_ID = /slice\(\s*-\s*8\s*\)/;

  /**
   * The 32-bit form, swept over everything rather than a list — and only it.
   *
   * The two rules above look for an ellipsis, which is what made them readable
   * and what let this one hide: `fpr.slice(-8)` has no `…` and no `shortFpr` in
   * its name, so it read as ordinary string handling in seven modules at once —
   * a download filename, a ciphertext tile, a keyserver chip, a verify card, a
   * DKG timeout. Every one of them was a short key id under a different noun.
   *
   * Eight hex characters is 32 bits, which is the length forged wholesale in
   * 2016 and the length `pages/index.tsx` warns about by name. **Sixteen is
   * not on this list and must not be.** The OpenPGP key ID *is* the low 64 bits
   * of the fingerprint, and `vault.js`, `pubkey-cache.js`, `upstream-hkp.js` and
   * `recipient-picker.js` derive one to match a PKESK packet or index an HKP
   * record — protocol, not presentation, and rewriting those would break
   * lookup. The distinction is the whole point: a 16-hex value on the wire is
   * load-bearing, an 8-hex value in front of a person is the defect.
   *
   * So the sweep is the whole app, because there is no module where a 32-bit
   * key id is the right answer — not even a log line, where it is worse.
   */
  it("derives no 32-bit key id anywhere in the app", () => {
    const offenders = [];
    for (const { file, text } of SOURCES) {
      text.split(/\r?\n/).forEach((line, i) => {
        if (!SHORT_KEY_ID.test(line)) return;
        offenders.push(`${file}:${i + 1} ${line.trim()}`);
      });
    }
    expect(
      offenders,
      `A short key id is being derived here:\n${offenders.join("\n")}\nThe ` +
        `whole value goes on screen through <Fingerprint>, and into a filename, ` +
        `a label or a refusal as itself. If this is a key id for a lookup rather ` +
        `than for a reader, it is the low 64 bits — slice(-16) — and it still ` +
        `does not belong in front of anybody.`
    ).toEqual([]);
  });

  /**
   * The two-ended form has one legitimate subject left, and it is not a key.
   *
   * `deriveRoomMaterial` computes a room from the hostname and the sorted
   * audience, so admission is being in that list and holding the key it names —
   * decided before a byte moves, never by anybody reading a code aloud. Two
   * people comparing a room id on a call are checking that they typed the same
   * list; a match proves nothing about a key and no trust hangs on it.
   */
  it("shortens nothing at both ends but a room id", () => {
    const offenders = [];
    for (const { file, text } of SOURCES) {
      text.split(/\r?\n/).forEach((line, i) => {
        if (!BOTH_ENDS.test(line) || /\broom\b/i.test(line)) return;
        offenders.push(`${file}:${i + 1} ${line.trim()}`);
      });
    }
    expect(
      offenders,
      `The elided form is back:\n${offenders.join("\n")}\nRender it with ` +
        `<Fingerprint>, which shows the whole value or a name — never some of ` +
        `the characters of one.`
    ).toEqual([]);
  });

  /**
   * The modules that hold a fingerprint may not shorten one, at either end.
   *
   * Scoped by file rather than swept over all of `src`, because the same
   * `slice(0, n)…` is fine on things that are not identities — a recipe digest
   * on a receipt, a base32 preview in a parse error, an RSA modulus in the
   * inspector. Nobody trusts a key because two digests began alike. The list is
   * every module that renders or reports one, and it is short enough to read.
   */
  const HOLDS_A_FINGERPRINT = [
    "src/lib/notebook/roster.js",
    "src/lib/notebook/documents.js",
    "src/lib/notebook/crypto.js",
    "src/lib/notebook/session.js",
    "src/lib/toolkit/approval-gate.js",
    "src/toolkit/ToolkitShell.tsx",
    "src/toolkit/widgets/ConnectionsPanel.tsx",
    "src/toolkit/widgets/CeremonySheet.tsx",
    "src/toolkit/widgets/GpgKeyBinder.tsx",
    "src/toolkit/widgets/HandoffQueue.tsx",
    "src/toolkit/widgets/InviteCard.tsx",
    "src/toolkit/widgets/NetworkArtifact.tsx",
    "src/toolkit/widgets/SessionLive.tsx",
    "src/toolkit/widgets/SessionStart.tsx",
  ];

  it("keeps the fingerprint-bearing modules free of any elision", () => {
    const offenders = [];
    for (const file of HOLDS_A_FINGERPRINT) {
      const source = SOURCES.find((s) => s.file === file);
      expect(source, `${file} is on the list and not in the tree`).toBeTruthy();
      source.text.split(/\r?\n/).forEach((line, i) => {
        if (!ONE_END.test(line)) return;
        // A room id, for the reason above; and a payload digest, which is the
        // thing being signed rather than the key signing it — `approval-gate`
        // prints eight characters of one beside the whole fingerprint, and
        // nobody has ever trusted a key because two payloads began alike.
        if (/\broom\b/i.test(line) || /sha256/i.test(line)) return;
        offenders.push(`${file}:${i + 1} ${line.trim()}`);
      });
    }
    expect(
      offenders,
      `A fingerprint is shortened here:\n${offenders.join("\n")}\nOn screen ` +
        `use <Fingerprint>. In a log line or an error message use ` +
        `formatFingerprint and print the whole thing — nothing about a log ` +
        `needs to be short, and there is no press to reveal the rest of one.`
    ).toEqual([]);
  });
});

/**
 * Log lines and error messages carry the whole fingerprint.
 *
 * `roster.js`, `documents.js`, `crypto.js`, `session.js` and `approval-gate.js`
 * make strings, not elements, and a log line cannot be a widget. That is an
 * argument for a different *rendering*, not for a different *value*: nothing
 * about a log needs to be short, and a truncated fingerprint in a message is
 * the same checkable-looking part with no press to reveal the rest — strictly
 * worse than on screen, because there is no way to recover it. So they print
 * `formatFingerprint`'s spelling, which is the one this component prints, which
 * is the one `findFingerprints` recovers: an error message pasted into the
 * invite box names the key it was about.
 */
describe("what a log line carries", () => {
  it("keeps a whole fingerprint recoverable out of an error message", async () => {
    // `shortKeyId` is `keyIdText` now, because a name saying "short" on top of
    // a function that prints the whole value is a comment asserting something
    // untrue. An approval denial naming 12 characters of the key it refused for
    // was this defect in the one line a reader is most likely to paste into a
    // bug report — and a paste box that takes a fingerprint is right there.
    const { keyIdText } = await import("../lib/toolkit/approval-gate.js");
    expect(findFingerprints(keyIdText(V4))).toEqual([V4]);
    expect(keyIdText(SSH)).toBe(SSH);
    expect(keyIdText("")).toBe("");
  });
});
