/**
 * The one-time code tile (§37, design_handoff_artifact_actions).
 *
 * TOTP shipped with four ops and no kind, so a code rendered as a line of
 * text: six digits with nothing saying whose account they were for or how much
 * of their step was left — the two things `execOtpCode` computes and the string
 * cannot carry.
 *
 * Three claims are worth pinning, and each of them is a mistake this codebase
 * has already made once:
 *
 *  1. **The role is `text`, and that is a finding, not a default.** The SSH
 *     halves needed roles of their own because the text emit sites stamp `role`
 *     from *sensitivity*, so one artifact arrived under two spellings. A code
 *     is never sensitive, so both spellings collapse to one — asserted below
 *     against real `runRecipe` output, both with `out` and without, because the
 *     design's prose about emitted metadata has been wrong before.
 *
 *  2. **The facts reach the tile.** `otpExpiresIn` and friends were emitted an
 *     hour before this landed and consumed by nothing; a field the shell's
 *     `OutputArtifact` mapping does not list is dropped silently on the way in,
 *     which has made a shipped feature inert twice. They ride `traits`, and the
 *     test checks both that the engine writes them and that the mapping carries
 *     them.
 *
 *  3. **Nothing recomputes the code.** §37a: a button may move an artifact,
 *     never compute a new one. The countdown is a clock ticking against an
 *     absolute expiry the run already fixed — never a fresh code — and the
 *     widget is checked for the imports that would make it otherwise.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { ARTIFACT_ROLES } from "../lib/toolkit/types.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { digestArtifact, RECEIPT_VERSION } from "../lib/toolkit/receipt.js";
import { ARTIFACT_KINDS, FALLBACK_KIND } from "../toolkit/artifact-kinds/registry.tsx";
import { resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";
import { actionsFor } from "../lib/toolkit/artifact-actions.js";
import {
  groupOtpCode,
  otpCodeReadout,
  otpTimeLeft,
} from "../lib/toolkit/artifact-readouts.js";
import { otpTone, OTP_URGENT_SECONDS } from "../toolkit/widgets/OtpCodeCard.tsx";

/**
 * Read source with line endings normalised to `\n`.
 *
 * `.gitattributes` does not pin these files, so a Windows checkout with
 * `core.autocrlf` has CRLF in the working copy while the index holds LF —
 * `git diff` is empty and the content is identical, but a multi-line literal
 * asserted against the raw text cannot match. Without this the suite fails on
 * Windows and passes in CI, which is the worst direction for a test to be
 * wrong in: the machine that would catch a real regression is the one that
 * stays green.
 */
const read = (rel) =>
  readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8").replace(/\r\n/g, "\n");
/** Comments removed, for assertions about what the code *does* — never says. */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

const CARD_SRC = read("../toolkit/widgets/OtpCodeCard.tsx");
const SHELL_SRC = read("../toolkit/ToolkitShell.tsx");
const CATALOG_SRC = read("../pages/toolkit-widgets.tsx");

const kindById = (id) => ARTIFACT_KINDS.find((k) => k.id === id);

/** Run a recipe and hand back each artifact with the kind that claims it. */
const tilesOf = async (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.errors, `fixture should compile: ${src}`).toEqual([]);
  const arts = await runRecipe(ast, {});
  return arts.map((a) => ({
    artifact: a,
    kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND),
  }));
};

/** An instant 9s into a 30-second step, so the arithmetic is not aligned. */
const AT = 1234567899;
const STEP_END = 1234567920;

describe("the role is text, and a tag is what makes the code its own kind", () => {
  it("stamps role text on both emit paths, with the tag on each", async () => {
    // The SSH failure mode, checked for and absent: `out $code` and a bare
    // pipeline tip must agree, or a kind matching one silently disowns the
    // other (`ArtifactMatch.role` is exact).
    for (const src of [
      `random 20 | base32 | otp.code at=${AT} | out $code`,
      `random 20 | base32 | otp.code at=${AT}`,
    ]) {
      const [tile] = await tilesOf(src);
      expect(tile.artifact.role, src).toBe("text");
      expect(tile.artifact.tags, src).toContain("otp-code");
      // Not masked — `otp-ops.js` decided that deliberately, and the whole
      // reason one role suffices here is that the decision never flips.
      expect(tile.artifact.sensitive, src).toBe(false);
      expect(tile.kind.id, src).toBe("otp-code");
    }
  });

  it("adds no word to the frozen vocabulary", () => {
    // A role exists to distinguish what may be *done* with an artifact. A code
    // has one spelling and no dispositions of its own, so the tag carries it
    // and ARTIFACT_ROLES is untouched.
    expect(ARTIFACT_ROLES).not.toContain("otp-code");
    expect(kindById("otp-code").match.role).toBe("text");
    expect(kindById("otp-code").match.tags).toEqual(["otp-code"]);
  });

  it("wins over the plain text kind on specificity, and only for a code", () => {
    expect(
      resolveArtifactKind({ role: "text", tags: ["otp-code"] }, ARTIFACT_KINDS, FALLBACK_KIND).id
    ).toBe("otp-code");
    // Every other text artifact is untouched — one tag, one kind.
    expect(
      resolveArtifactKind({ role: "text", tags: ["opaque"] }, ARTIFACT_KINDS, FALLBACK_KIND).id
    ).toBe("text");
    expect(resolveArtifactKind({ role: "text" }, ARTIFACT_KINDS, FALLBACK_KIND).id).toBe("text");
  });

  it("leaves the enrolment template's other tiles exactly as they were", async () => {
    // The masking decision this kind must not disturb: the secret and the URI
    // are credentials and stay masked; only the code is readable.
    const tiles = await tilesOf(`random 20 | tee
  - base32 | out $secret
| otp.uri issuer="Basilisk" account=you@example.com | tee
  - qr
| out $uri

in $secret | otp.code | out $code`);
    const by = (label) => tiles.find((t) => t.artifact.label === label);
    expect(by("secret").artifact.sensitive).toBe(true);
    expect(by("secret").kind.id).toBe("secret");
    expect(by("uri").artifact.sensitive).toBe(true);
    expect(by("uri").kind.id).toBe("secret");
    expect(by("code").artifact.sensitive).toBe(false);
    expect(by("code").kind.id).toBe("otp-code");
  });
});

describe("the facts the op computed reach the tile", () => {
  it("stamps the run's OTP facts onto traits", async () => {
    const [tile] = await tilesOf(`random 20 | base32 | otp.code at=${AT} | out $code`);
    const t = tile.artifact.traits;
    expect(t.otpMode).toBe("totp");
    expect(t.otpDigits).toBe(6);
    expect(t.otpPeriod).toBe(30);
    expect(String(t.otpStep)).toMatch(/^[0-9]+$/);
    expect(t.otpExpiresIn).toBe(STEP_END - AT);
  });

  it("carries the account label when the code came from a URI", async () => {
    // The one fact a bare secret cannot supply, and the reason the tile can
    // say whose code this is at all.
    const tiles = await tilesOf(
      `random 20 | otp.uri issuer="Basilisk" account=you@example.com | out $uri\n\n` +
        `in $uri | otp.code at=${AT} | out $code`
    );
    const code = tiles.find((t) => t.artifact.label === "code");
    expect(code.artifact.traits.otpLabel).toBe("Basilisk: you@example.com");
    expect(otpCodeReadout(code.artifact.content, code.artifact.traits).label).toBe(
      "Basilisk: you@example.com"
    );
  });

  it("carries them through the shell's mappings, not only out of the engine", () => {
    // The trap this file exists to close: `OutputList` resolves kinds against a
    // *mapped* `OutputArtifact`, and a field the mapping omits is dropped
    // silently while an engine-backed test stays green. `traits` was chosen
    // over a field of its own precisely because both mappings already list it.
    const code = stripComments(SHELL_SRC);
    const carried = code.match(/traits:\s*a\.traits/g) || [];
    expect(carried.length, "both OutputList mappings must carry traits").toBeGreaterThanOrEqual(2);
  });

  it("adds no trait an op did not emit", async () => {
    // Copied key by key, so widening what reaches a tile is a deliberate edit
    // to the list rather than a side effect of adding a meta field.
    const [tile] = await tilesOf('"plain" | utf8 | out $msg');
    expect(tile.artifact.traits).toBeUndefined();
  });
});

describe("the countdown is honest about a stale artifact", () => {
  it("turns the run's step into an absolute expiry that agrees with the snapshot", async () => {
    // `otpExpiresIn` is a snapshot at run time; `(step + 1) × period` is the
    // same instant expressed so it survives the artifact being read minutes
    // later. At run time the two must agree exactly — the moment they do not,
    // one of them is wrong.
    const [tile] = await tilesOf(`random 20 | base32 | otp.code at=${AT} | out $code`);
    const readout = otpCodeReadout(tile.artifact.content, tile.artifact.traits);
    expect(readout.expiresAt).toBe(STEP_END);
    expect(readout.expiresAt - AT).toBe(readout.snapshotSeconds);
  });

  it("keeps ticking down and then sits at expired", () => {
    const readout = otpCodeReadout("228746", {
      otpMode: "totp",
      otpDigits: 6,
      otpPeriod: 30,
      otpStep: "41152263",
      otpExpiresIn: 21,
    });
    expect(otpTimeLeft(readout, STEP_END - 21).seconds).toBe(21);
    expect(otpTimeLeft(readout, STEP_END - 1).seconds).toBe(1);
    expect(otpTimeLeft(readout, STEP_END).expired).toBe(true);
    // Minutes later it is still expired — never negative-looking progress, and
    // never a fresh code.
    const stale = otpTimeLeft(readout, STEP_END + 3600);
    expect(stale.expired).toBe(true);
    expect(stale.fraction).toBe(0);
    expect(readout.code).toBe("228746");
  });

  it("escalates tone at the boundaries, without waiting out a real step", () => {
    expect(otpTone(30)).toBe("ok");
    expect(otpTone(OTP_URGENT_SECONDS + 1)).toBe("ok");
    expect(otpTone(OTP_URGENT_SECONDS)).toBe("warn");
    expect(otpTone(0)).toBe("error");
    expect(otpTone(-600)).toBe("error");
    expect(otpTone(null)).toBe("muted");
  });

  it("gives HOTP no clock at all, because it has none", async () => {
    // §33d: "is this meaningful for this object" is answered by omission. A
    // counter code does not expire, it gets spent — so there is no countdown,
    // not a disabled or a zeroed one.
    const [tile] = await tilesOf("random 20 | base32 | otp.code mode=hotp counter=2 | out $first");
    const readout = otpCodeReadout(tile.artifact.content, tile.artifact.traits);
    expect(readout.mode).toBe("hotp");
    expect(readout.counter).toBe(2);
    expect(readout.expiresAt).toBeNull();
    expect(otpTimeLeft(readout, Date.now() / 1000)).toBeNull();
  });
});

describe("a code the recipe pinned is not measured against now", () => {
  // The defect this block exists to close: `otp.code at=<past>` rendered
  // "expired — run the cell again for the current one", and re-running produced
  // the identical code forever, because `at=` is what pins it. The two cases
  // were indistinguishable — byte-identical trait shapes — so the card was
  // doing the only thing it could with what it had.

  it("records that the recipe named the instant, and stays silent when it did not", async () => {
    const [pinned] = await tilesOf(`random 20 | base32 | otp.code at=${AT} | out $code`);
    expect(pinned.artifact.traits.otpPinnedAt).toBe(AT);

    const [live] = await tilesOf("random 20 | base32 | otp.code | out $code");
    // Absent, not `null` or `0`. Absent already meant "the recipe meant now"
    // for every artifact ever produced, which is why this needs no migration.
    expect("otpPinnedAt" in live.artifact.traits).toBe(false);
    expect(live.artifact.traits.otpMode).toBe("totp");
  });

  it("says nothing about pinning on a HOTP code, which has no clock to pin", async () => {
    // `at=` is a claim about a wall clock. `hotp()` never sees one — it answers
    // to `counter=` — so recording an instant here would be recording a
    // parameter that did not participate in the value.
    const [tile] = await tilesOf(
      `random 20 | base32 | otp.code mode=hotp counter=2 at=${AT} | out $code`
    );
    expect(tile.artifact.traits.otpMode).toBe("hotp");
    expect("otpPinnedAt" in tile.artifact.traits).toBe(false);
    expect(otpCodeReadout(tile.artifact.content, tile.artifact.traits).pinnedAt).toBeNull();
  });

  it("re-running a pinned cell produces the same digits, which is why the old advice was false", async () => {
    const src = `"JBSWY3DPEHPK3PXP" | otp.code at=1700000000 | out $code`;
    const [a] = await tilesOf(src);
    const [b] = await tilesOf(src);
    expect(a.artifact.content).toBe(b.artifact.content);
    expect(a.artifact.traits.otpStep).toBe(b.artifact.traits.otpStep);
  });

  it("refuses the countdown arithmetic outright, rather than branching in the widget", () => {
    // The rule lives in `lib/`: *a card may tick only against an instant the
    // recipe did not choose*. Because `otpTimeLeft` returns null, every branch
    // downstream of it — the seconds, the draining bar, the word "expired" and
    // the sentence telling you to re-run — is unreachable for a pinned code,
    // and a second reader of these traits cannot reintroduce the claim.
    const traits = {
      otpMode: "totp",
      otpDigits: 6,
      otpPeriod: 30,
      otpStep: "41152263",
      otpExpiresIn: 21,
      otpPinnedAt: 1234567899,
    };
    const readout = otpCodeReadout("228746", traits);
    expect(readout.pinnedAt).toBe(1234567899);
    // The absolute expiry is still computed — it is a true fact about the step
    // — but nothing counts against it.
    expect(readout.expiresAt).toBe(STEP_END);
    expect(otpTimeLeft(readout, STEP_END - 21)).toBeNull();
    expect(otpTimeLeft(readout, STEP_END + 3600)).toBeNull();
    // And the digits are untouched: the value never varies with the sentence.
    expect(readout.code).toBe("228746");

    // The same traits without the intent are the live case, unchanged.
    const { otpPinnedAt: _drop, ...liveTraits } = traits;
    expect(otpTimeLeft(otpCodeReadout("228746", liveTraits), STEP_END - 21).seconds).toBe(21);
  });

  it("moves no receipt digest, which is why the intent is a trait at all", async () => {
    // The property the whole design rests on: `digestArtifact` reads label,
    // filename, role, stepName, sensitive, length and a digest of content —
    // never `traits`. A role carrying the same distinction would have moved
    // every row and cost a RECEIPT_VERSION bump, as v1 → v2 did.
    const [tile] = await tilesOf(`random 20 | base32 | otp.code at=${AT} | out $code`);
    const withIntent = await digestArtifact(tile.artifact);
    const { otpPinnedAt: _drop, ...rest } = tile.artifact.traits;
    const withoutIntent = await digestArtifact({ ...tile.artifact, traits: rest });
    expect(withIntent).toEqual(withoutIntent);
    expect(Object.keys(withIntent)).not.toContain("traits");
    expect(RECEIPT_VERSION).toBe(2);
  });

  it("keeps the clock branches under otpTimeLeft, including the interval", () => {
    const code = stripComments(CARD_SRC);
    // The timer asks the same function the sentence does, so a pinned code
    // cannot tick however the render below is later edited.
    expect(code).toMatch(/const ticks = otpTimeLeft\(readout, 0\) != null;/);
    expect(code).toMatch(/if \(!ticks\) return undefined;/);
    expect(code).toMatch(/const left = otpTimeLeft\(readout, tick \/ 1000\);/);

    // Neither false claim appears anywhere in what a pinned code renders.
    const branches = code
      .split(/pinnedAt != null \? \(/)
      .slice(1)
      .map((s) => s.split(/\) : /)[0]);
    expect(branches.length, "the chip and the sentence").toBe(2);
    for (const branch of branches) {
      expect(branch).not.toMatch(/expired/);
      expect(branch).not.toMatch(/run the cell again/);
    }
    expect(branches[0]).toMatch(/pinned/);
    expect(branches[1]).toMatch(/Pinned by/);
  });
});

describe("the catalog shows both states on purpose", () => {
  it("derives the live row's step from the clock instead of freezing one", () => {
    // `otpStep: "59520075"` was the step current the afternoon it was written,
    // so the one row whose job is to demonstrate a draining countdown could
    // only ever render its end state.
    const code = stripComments(CATALOG_SRC);
    expect(code).toMatch(/const liveStep = Math\.floor\(nowSeconds \/ 30\)/);
    expect(code).toMatch(/otpStep: String\(liveStep\)/);
    expect(code).not.toMatch(/otpStep: "59520075"/);
  });

  it("pins the pinned row to what a real run actually stamps", async () => {
    // A hand-written fixture is a claim about the engine. This one is checked.
    const [tile] = await tilesOf(`"JBSWY3DPEHPK3PXP" | otp.code at=1700000000 | out $code`);
    const t = tile.artifact.traits;
    const code = stripComments(CATALOG_SRC);
    expect(code).toContain(`otpStep: "${t.otpStep}"`);
    expect(code).toContain(`otpExpiresIn: ${t.otpExpiresIn},\n        otpPinnedAt: ${t.otpPinnedAt},`);
    expect(code).toContain(`content: "${tile.artifact.content}"`);
  });
});

describe("the read-out degrades instead of guessing", () => {
  it("returns null for an artifact carrying no OTP facts", () => {
    // The digits are already on the tile; a period invented here would be a
    // countdown against a number nobody computed.
    expect(otpCodeReadout("228746", undefined)).toBeNull();
    expect(otpCodeReadout("228746", {})).toBeNull();
  });

  it("returns null for a body that is not a code", () => {
    expect(otpCodeReadout("not-a-code", { otpMode: "totp" })).toBeNull();
    expect(otpCodeReadout("", { otpMode: "totp" })).toBeNull();
  });

  it("says what is missing in a sentence, so a null view is not a blank tile", () => {
    expect(kindById("otp-code").empty.length).toBeGreaterThan(20);
    expect(kindById("otp-code").view({ artifact: { content: "228746" }, masked: false })).toBeNull();
  });

  it("groups digits for reading without changing the value", () => {
    expect(groupOtpCode("228746")).toEqual(["228", "746"]);
    expect(groupOtpCode("12345678")).toEqual(["1234", "5678"]);
    expect(groupOtpCode("1234567")).toEqual(["1234", "567"]);
    expect(groupOtpCode("228746").join("")).toBe("228746");
  });
});

describe("nothing on this tile computes a new code (§37a)", () => {
  it("declares Copy and Download and nothing else", () => {
    const kind = kindById("otp-code");
    expect(kind.actions).toEqual(["copy", "download"]);
    expect(kind.actions).not.toContain("key.publish");
    // No action named that the table does not define, so no button silently
    // missing from the row.
    expect(actionsFor(kind).length).toBe(kind.actions.length);
  });

  it("never reaches the OTP library from the widget", () => {
    // The structural version of the rule: a card that cannot import `totp` or
    // `hotp` cannot recompute a code however the countdown is later edited.
    const code = stripComments(CARD_SRC);
    expect(code).not.toMatch(/lib\/otp\//);
    expect(code).not.toMatch(/\botp-ops\b/);
    expect(code).not.toMatch(/\b(totp|hotp)\s*\(/);
    // The digits it draws come from the artifact's own body, nowhere else.
    expect(code).toMatch(/otpCodeReadout\(content, traits\)/);
  });

  it("has no refresh affordance", () => {
    const code = stripComments(CARD_SRC);
    expect(code).not.toMatch(/<button/);
    expect(code).not.toMatch(/onClick/);
  });

  it("ticks a clock rather than a value", () => {
    const code = stripComments(CARD_SRC);
    // The interval writes the *time*, and the only thing downstream of it is
    // the remaining-seconds arithmetic.
    expect(code).toMatch(/setInterval\(\(\) => setTick\(Date\.now\(\)\), 1000\)/);
    expect(code).toMatch(/clearInterval/);
  });

  it("declares no publicView, because a code is never masked", () => {
    // A body that renders while masked would be a claim about a state this
    // kind cannot reach — the `ssh-public` argument.
    expect(kindById("otp-code").publicView).toBeUndefined();
  });
});
