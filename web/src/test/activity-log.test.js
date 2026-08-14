/**
 * The Activity log (§36, design_handoff_artifact_actions).
 *
 * Moving dispositions onto buttons costs the recipe its status as a complete
 * record of what happened. This is the accepted answer: recipes record
 * derivations, this records dispositions, neither pretends to be the other.
 * What is worth pinning is the honesty of the record — that it holds digests
 * rather than values, that it records the quiet actions as well as the loud
 * ones, and that it does not survive a session.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  activityAsText,
  activityCount,
  clearActivity,
  formatActivityTime,
  listActivity,
  onActivityChange,
  recordActivity,
} from "../lib/toolkit/activity-log.js";

const SRC = readFileSync(
  fileURLToPath(new URL("../lib/toolkit/activity-log.js", import.meta.url)),
  "utf8"
);
/** Comments stripped, for assertions about what the code *does*. The header
 *  explains why localStorage is avoided, in prose that names it. */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const SRC_CODE = stripComments(SRC);
/**
 * The render path, across both files it spans since §33a split the tile out
 * of the list. "Appended from exactly one place" is a claim about the path,
 * not about `OutputList.tsx`, and reading only the file the runner *used* to
 * live in would turn that assertion into a tautology the moment it moved.
 */
const OUTPUT_LIST = ["ArtifactTile", "OutputList"]
  .map((f) =>
    readFileSync(
      fileURLToPath(new URL(`../toolkit/widgets/${f}.tsx`, import.meta.url)),
      "utf8"
    )
  )
  .join("\n");
const HOOK = readFileSync(
  fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url)),
  "utf8"
);

beforeEach(() => clearActivity());

describe("digests, never values", () => {
  it("records a digest of the content and never the content itself", async () => {
    const secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nnotreally\n";
    await recordActivity({
      action: "copy",
      label: "Copy",
      artifact: "kp · private JWK",
      tier: "inert",
      content: secret,
    });
    const [entry] = listActivity();
    expect(entry.digest).toMatch(/^[0-9a-f]{16}$/);
    // The value must appear nowhere — not in the entry, not in the export.
    expect(JSON.stringify(entry)).not.toContain("notreally");
    expect(activityAsText()).not.toContain("notreally");
  });

  it("uses the same digest function receipts use, so the two cross-read", () => {
    expect(SRC).toMatch(/import \{ digestText \} from "\.\/receipt\.js"/);
  });
});

describe("every tier is recorded, not only the dramatic ones", () => {
  it("logs inert actions too", async () => {
    // Copy and Download are how a secret leaves the notebook. A log that
    // records only Publish answers the wrong question at 2am.
    await recordActivity({ action: "copy", label: "Copy", artifact: "a", tier: "inert" });
    await recordActivity({
      action: "keyring.add",
      label: "Add to keyring",
      artifact: "b",
      tier: "local",
    });
    expect(listActivity().map((e) => e.tier)).toEqual(["local", "inert"]);
  });

  it("is appended from exactly one place, so a new action cannot forget", () => {
    // The runner logs; individual actions do not. That is the same structural
    // move as routing every outcome through ActionResult.
    expect((OUTPUT_LIST.match(/recordActivity\(/g) || []).length).toBe(1);
  });

  it("records only what actually happened", () => {
    // Logged in `.then`, never in `.catch`: an action that threw moved
    // nothing, and recording it as though it had is the least forgivable
    // direction for this log to lie in. Asserted as *position* in the chain
    // rather than as one literal expression — the `.then` body grew a
    // `setPending(null)` when §34c gave outward actions a confirmation to
    // dismiss, and a regex pinned to the old one-liner would have failed on a
    // change that kept the property exactly.
    const code = stripComments(OUTPUT_LIST);
    const then = code.indexOf(".then((result)");
    const log = code.indexOf("recordActivity(", then);
    const caught = code.indexOf(".catch(", then);
    expect(then, ".then((result) not found").toBeGreaterThan(-1);
    expect(log, "recordActivity not inside the .then").toBeGreaterThan(then);
    expect(log, "recordActivity is not before the .catch").toBeLessThan(caught);
    expect(code).not.toMatch(/catch\([\s\S]{0,200}recordActivity/);
  });
});

describe("newest first on screen, oldest first in the export", () => {
  it("lists newest first", async () => {
    await recordActivity({ action: "a", label: "First", artifact: "x", tier: "inert" });
    await recordActivity({ action: "b", label: "Second", artifact: "y", tier: "inert" });
    expect(listActivity().map((e) => e.label)).toEqual(["Second", "First"]);
  });

  it("exports chronologically, because a transcript is read start to finish", async () => {
    await recordActivity({ action: "a", label: "First", artifact: "x", tier: "inert" });
    await recordActivity({ action: "b", label: "Second", artifact: "y", tier: "inert" });
    const text = activityAsText();
    expect(text.indexOf("First")).toBeLessThan(text.indexOf("Second"));
  });

  it("puts the destination on its own line when there is one", async () => {
    await recordActivity({
      action: "keyring.add",
      label: "Add to keyring",
      artifact: "kp",
      tier: "local",
      detail: "My Keys SHA256:Ur1h…",
    });
    expect(activityAsText()).toMatch(/→ My Keys SHA256:Ur1h…/);
  });
});

describe("session-scoped, and it says so structurally", () => {
  it("never touches localStorage or IndexedDB", () => {
    // It names key ids and directory URLs, and localStorage is XSS-readable.
    expect(SRC_CODE).not.toMatch(/localStorage|sessionStorage|indexedDB/);
  });

  it("clears with sensitive data, alongside the outputs", () => {
    expect(HOOK).toMatch(/clearActivity\(\)/);
    expect(HOOK).toMatch(/clearApprovalGrants\(\)/);
  });

  it("empties on clear", async () => {
    await recordActivity({ action: "a", label: "A", artifact: "x", tier: "inert" });
    expect(activityCount()).toBe(1);
    clearActivity();
    expect(activityCount()).toBe(0);
    expect(activityAsText()).toBe("");
  });
});

describe("it cannot break the thing it observes", () => {
  it("never throws, even on a hostile entry", async () => {
    // The action already happened; refusing to record it does not un-happen
    // it, and surfacing that as a failure would be a lie the other way.
    await expect(
      recordActivity({
        action: "x",
        label: "X",
        artifact: "y",
        tier: "inert",
        get content() {
          throw new Error("boom");
        },
      })
    ).resolves.toBeUndefined();
  });

  it("survives a subscriber that throws", async () => {
    const off = onActivityChange(() => {
      throw new Error("bad subscriber");
    });
    await expect(
      recordActivity({ action: "a", label: "A", artifact: "x", tier: "inert" })
    ).resolves.toBeUndefined();
    expect(activityCount()).toBe(1);
    off();
  });
});

describe("time is shown to the second", () => {
  it("formats as HH:MM:SS, because order matters at 2am", () => {
    const at = new Date(2026, 0, 2, 14, 7, 22).getTime();
    expect(formatActivityTime(at)).toBe("14:07:22");
  });
});

describe("a receipt is the only record that an action changed something", () => {
  // `recordActivity` stored `receipt` and nothing read it — not the Activity
  // panel, not `activityAsText`. Seven of the eight receipts say what the
  // label already implies, which is why the omission never looked wrong. The
  // eighth is why it was: adding a key returns "Added to My Keys" or
  // "Already in My Keys" from the same label, artifact, digest and detail, so
  // dropping the receipt drops the whole difference between the two.
  //
  // Pinned on both readers rather than on the storage. The field was always
  // stored correctly; what was missing was anybody looking at it, so a test
  // that asserted `recordActivity` keeps it would have passed throughout.
  const added = {
    action: "save-key",
    label: "Add to My Keys",
    artifact: "ada@example.test",
    tier: "vault",
    detail: "ada@example.test",
  };

  it("tells an addition from a no-op in the exported minutes", async () => {
    clearActivity();
    await recordActivity({ ...added, receipt: "Added to My Keys" });
    const first = activityAsText();

    clearActivity();
    await recordActivity({ ...added, receipt: "Already in My Keys" });
    const second = activityAsText();

    expect(first).toContain("Added to My Keys");
    expect(second).toContain("Already in My Keys");
    // The point of the pair: everything else about these two entries is the
    // same, so a transcript missing the receipt cannot tell them apart.
    expect(first).not.toBe(second);
    expect(first.replace(/Added to My Keys/g, "")).toBe(
      second.replace(/Already in My Keys/g, "")
    );
  });

  it("puts the outcome above the thing it acted on", async () => {
    clearActivity();
    await recordActivity({ ...added, receipt: "Added to My Keys" });
    const text = activityAsText();
    expect(text.indexOf("Added to My Keys")).toBeLessThan(text.indexOf("→"));
  });

  it("omits the line rather than printing an empty one", async () => {
    clearActivity();
    await recordActivity({ action: "c", label: "Copy", artifact: "x", tier: "inert" });
    expect(activityAsText().split("\n")).toHaveLength(1);
  });

  it("is drawn by the panel, which is the reader that was missing", () => {
    // The source assertion is the one that fails if the panel stops rendering
    // it — the same shape `session-flow.test.js` uses for consumers, and the
    // reason this defect survived: every layer below the panel was correct.
    const SHELL = readFileSync(
      fileURLToPath(new URL("../toolkit/ToolkitShell.tsx", import.meta.url)),
      "utf8"
    );
    expect(SHELL).toMatch(/e\.receipt \?/);
    expect(SHELL).toMatch(/className="activity-receipt"/);
    // Declared in the stylesheet, never inline.
    const CSS = readFileSync(
      fileURLToPath(new URL("../css/toolkit.css", import.meta.url)),
      "utf8"
    );
    expect(CSS).toContain(".activity-receipt");
  });
});
