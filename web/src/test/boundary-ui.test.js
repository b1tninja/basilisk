/**
 * The boundary's three visible surfaces (§26): the shelf, the tool card,
 * and the approval banner.
 *
 * `agent.unlock | gpg.sign` and `agent.sign` produce the same signature
 * with opposite security properties, so if the UI renders both as ordinary
 * chips the distinction lives only in the reader's head. These pin the
 * treatments that make it visible — including the asymmetry, which is the
 * design: the leak is marked, the safe path is not.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SHELF_META, getStep } from "../lib/toolkit/registry.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const TOOLCARD = read("../toolkit/widgets/ToolCard.tsx");
const BANNER = read("../toolkit/widgets/ApprovalBanner.tsx");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const CHIP = read("../toolkit/widgets/SuggestChip.tsx");
const FLOW = read("../toolkit/widgets/RecipeChipFlow.tsx");
const RUNBAR = read("../toolkit/widgets/RunBar.tsx");
const CSS = read("../css/toolkit.css");

describe("the shelf teaches the boundary first (§26b)", () => {
  it("puts Boundary above Vault", () => {
    expect(SHELF_META.boundary.order).toBe(0);
    expect(SHELF_META.vault.order).toBe(1);
  });

  it("files the boundary ops on the boundary shelf and the rest on vault", () => {
    expect(getStep("agent.sign").shelf).toBe("boundary");
    expect(getStep("agent.decrypt").shelf).toBe("boundary");
    for (const n of ["agent.unlock", "agent.pub", "agent.list", "agent.save"]) {
      expect(getStep(n).shelf, n).toBe("vault");
    }
  });

  it("names the concept rather than describing it", () => {
    // "Sign & decrypt" reads fine and leaves the concept nameless — and a
    // concept you cannot name is one you cannot warn about.
    expect(SHELF_META.boundary.label).toBe("Boundary");
  });
});

describe("exposure is declared, not special-cased (§26d)", () => {
  it("marks agent.unlock and nothing else", () => {
    expect(getStep("agent.unlock").exposure).toBe("exports-secret");
    for (const n of ["agent.sign", "agent.decrypt", "agent.pub", "agent.save"]) {
      expect(getStep(n).exposure, n).toBeUndefined();
    }
  });

  it("steers toward the boundary ops in its own doc", () => {
    const doc = getStep("agent.unlock").doc;
    expect(doc).toMatch(/Exports the private key into the run/);
    expect(doc).toMatch(/prefer `agent\.sign` \/ `agent\.decrypt`/);
  });

  it("renders from the declared field, in the warn tone", () => {
    // --warn, not --error: an error tone on a legitimate, sometimes-necessary
    // op cries wolf, and this codebase reserves --error for things that failed.
    expect(TOOLCARD).toMatch(/exposure === "exports-secret"/);
    expect(TOOLCARD).toMatch(/Hands the private key to the pipeline/);
    expect(TOOLCARD).toMatch(/var\(--warn\)/);
    expect(TOOLCARD).not.toMatch(/exposure[\s\S]{0,200}var\(--error\)/);
  });
});

describe("the approval banner shows facts, not reassurance (§27b)", () => {
  it("renders every field the engine actually held", () => {
    for (const field of [
      "stepText",
      "keyId",
      "keyLabel",
      "keyKind",
      "keyProtection",
      "payloadBytes",
      "payloadSha256",
    ]) {
      expect(BANNER, field).toContain(`request.${field}`);
    }
  });

  it("previews text payloads and says so when it cannot", () => {
    // A digest alone is honest but unauditable; the preview is what lets a
    // human notice "that is not my commit message".
    expect(BANNER).toMatch(/show payload/);
    expect(BANNER).toMatch(/digest only/);
  });

  it("explains the namespace rather than just printing it", () => {
    expect(BANNER).toMatch(/cannot be replayed under another namespace/);
  });

  it("keeps 'once' the easy path — session is a checkbox, not a third button", () => {
    expect(BANNER).toMatch(/onDecide\("deny"\)/);
    expect(BANNER).toMatch(/onDecide\(forSession \? "session" : "once"\)/);
    expect(BANNER).toMatch(/type="checkbox"/);
  });

  it("offers the run batch only when a real count is known (§27d)", () => {
    expect(BANNER).toMatch(/remaining > 0[\s\S]{0,400}onDecide\("run"\)/);
    expect(BANNER).toMatch(/request\.runTotal > request\.requestIndex/);
  });

  it("states the consequence when the session box is checked", () => {
    expect(BANNER).toMatch(/with this key without\s+asking/);
    expect(BANNER).toMatch(/expires in 5 minutes/);
  });
});

describe("the shell wires the gate and can revoke it (§27c)", () => {
  it("registers and unregisters the approval surface", () => {
    expect(SHELL).toMatch(/setApprovalGate\(\s*\(request\)/);
    expect(SHELL).toMatch(/setApprovalGate\(null\)/);
  });

  it("renders the banner inline, not as a modal", () => {
    // A modal hides the very context needed to judge the request.
    expect(SHELL).toMatch(/<ApprovalBanner/);
    expect(BANNER).not.toMatch(/position:\s*fixed|Dialog|Modal/);
  });

  it("revokes grants on Lock and on Lock all", () => {
    expect(SHELL).toMatch(/revokeApprovalGrants\(k\.fingerprint\)/);
    expect(SHELL).toMatch(/lockAllSessions[\s\S]{0,400}clearApprovalGrants\(\)/);
  });

  it("shows a live, counting grant on the Keyring row", () => {
    expect(SHELL).toMatch(/data-approval-grant/);
    expect(SHELL).toMatch(/approved: \{g\.use\}/);
    expect(SHELL).toMatch(/\{g\.uses\}/);
  });
});

describe("the pipeline traces the leak (§26c)", () => {
  it("carries the mark from the trace to the chip", () => {
    // Computed by exposureTrace over the whole notebook, not per-cell: a key
    // exported in cell 1 is still a key in cell 4.
    expect(SHELL).toMatch(/exposureTrace\(nb\.chains\)\.steps/);
    expect(SHELL).toMatch(/keyExposed: exposedSteps\.has\(s\)/);
    // Nested bodies and tee branches too — a buried step is exactly where a
    // hostile recipe would put the interesting one.
    expect((SHELL.match(/keyExposed: exposedSteps\.has\(/g) || []).length).toBe(3);
    expect(FLOW).toMatch(/keyExposed=\{step\.keyExposed\}/);
    expect(CHIP).toMatch(/data-key-exposed=\{keyExposed \|\| undefined\}/);
  });

  it("marks both chip shapes, removable and not", () => {
    expect((CHIP.match(/data-key-exposed=/g) || []).length).toBe(2);
  });

  it("underlines in warn, and never tints the chip as an error", () => {
    expect(CSS).toMatch(/\.suggest-chip\[data-key-exposed\]::after[^}]*background: var\(--warn\)/s);
    expect(CSS).not.toMatch(/\[data-key-exposed\][^}]*var\(--error\)/s);
  });
});

describe("the run bar says why it stopped (§27a)", () => {
  it("has a waiting-approval state beside waiting-peer", () => {
    expect(RUNBAR).toMatch(/"waiting-approval"/);
    expect(RUNBAR).toMatch(/a step wants to use a key/);
  });

  it("offers Stop and nothing that decides about the key", () => {
    // The decision belongs to the banner at the requesting cell; a bar-level
    // Approve would be exactly the context-free click-through §27a rejects.
    const block = RUNBAR.match(/state === "waiting-approval" \? \([\s\S]*?\) : state === "waiting-peer"/);
    expect(block, "waiting-approval block not found").toBeTruthy();
    expect(block[0]).toMatch(/onClick=\{onStop\}/);
    expect(block[0]).not.toMatch(/Approve|Deny/);
  });

  it("is driven by a live request, not by a busy flag", () => {
    expect(SHELL).toMatch(/approvalAsk\s*\?\s*"waiting-approval"/);
  });
});
