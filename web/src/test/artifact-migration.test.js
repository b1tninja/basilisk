/**
 * §38 — what this design changes for recipes that already exist, and what it
 * refuses to change (design_handoff_artifact_actions).
 *
 * Migration is the section most likely to be read once and then contradicted
 * by a later commit, because every clause of it is a *negative*: an op that is
 * not added, a name that is not retired, a store that is not bumped. Negatives
 * do not fail loudly on their own, so they are asserted here.
 *
 * Two of §38's own premises were checked against the code before this file
 * existed, and one of them was wrong — see the CLI test below.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { listSteps, getStep } from "../lib/toolkit/registry.js";
import { RECEIPT_VERSION, parseReceipt } from "../lib/toolkit/receipt.js";
import { ARTIFACT_KINDS } from "../toolkit/artifact-kinds/registry.tsx";
import { migrateRecipe } from "../lib/toolkit/recipe.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
/** Assertions about absence have to ignore the prose explaining the absence. */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

describe("§38a — agent.save stays, and its doc says why to prefer a button", () => {
  it("is still registered, because there is nothing to rewrite it to", () => {
    // The repo's rule is that retired names are removed and rewritten by
    // `migrateRecipe` — `to`/`from`, `quorum.send/recv`, `hex`/`unhex`. This
    // op's replacement is a click, and `migrateRecipe` cannot emit one, so
    // every saved workspace and shared link holding it would fail live parse.
    expect(getStep("agent.save")).toBeTruthy();
    expect(migrateRecipe("genkey ed25519 | agent.save").recipe).toMatch(/agent\.save/);
  });

  it("leads with the consequence of putting it in a portable object", () => {
    // A recipe is shared as a link, saved as a workspace, and re-run by other
    // people. This is the one op in the toolbox that writes durable state on
    // whoever runs it, so that goes first rather than in a trailing clause.
    const doc = getStep("agent.save").doc;
    expect(doc).toMatch(/^Writes to the keyring of \*whoever runs the recipe\*/);
    expect(doc).toMatch(/nothing in the recipe undoes it/);
  });

  it("does not repeat the charter's claim that it exists for CLI runs", () => {
    // It does not work there at all: `basilisk run` refuses the whole `agent`
    // toolbox at pre-flight with exit 4, verified against the built CLI. A doc
    // that steered people toward a headless use would be steering them into an
    // error message.
    const doc = getStep("agent.save").doc;
    expect(doc).toMatch(/Not available headlessly/);
    expect(doc).toMatch(/exit 4/);
  });

  it("classes the whole agent toolbox as browser-bound, which is what makes that true", () => {
    const CAP = read("../../cli/capability.js");
    expect(CAP).toMatch(/agent:\s*"storage"/);
    for (const n of ["agent.save", "agent.unlock", "agent.sign", "agent.decrypt"]) {
      expect(getStep(n).toolbox, n).toBe("agent");
    }
  });
});

describe("§38b — publishing stays a UI path, and never becomes an op", () => {
  it("registers no publish op at all", () => {
    // A recipe that publishes on behalf of whoever runs it is the worst
    // instance of the hazard this whole capability exists to remove.
    const names = listSteps().map((s) => s.name);
    expect(names.filter((n) => /publish/i.test(n))).toEqual([]);
  });

  it("has no upstream write path to name, so the banner cannot name one", () => {
    // `connect-src` allows keys.openpgp.org and keys.mailvelope.com, but
    // `upstream-hkp.js` only implements lookup. Wording that could name a
    // keyserver would be a lie about where the key went.
    const UPSTREAM = stripComments(read("../lib/upstream-hkp.js"));
    expect(UPSTREAM).not.toMatch(/method:\s*["']POST["']/);
    expect(UPSTREAM).not.toMatch(/pks\/add/);
  });

  it("declares Publish on exactly one kind, matching what the function enforces", () => {
    const kinds = ARTIFACT_KINDS.filter((k) => (k.actions || []).includes("key.publish"));
    expect(kinds.map((k) => k.id)).toEqual(["openpgp-public"]);
    expect(kinds[0].match.role).toBe("public-key");
    const HOOK = read("../toolkit/useNotebook.ts");
    expect(HOOK).toMatch(/only public-key exports are publishable/);
  });
});

describe("§38c — the receipt break is named, not reported as a mismatch", () => {
  it("is at version 2, because role is inside the digest", () => {
    expect(RECEIPT_VERSION).toBe(2);
  });

  it("tells a v1 holder the description changed and the run did not", () => {
    // Reporting this as "digest mismatch" would send someone hunting a
    // nonexistent tampering, which is the expensive kind of wrong answer.
    const v1 = JSON.stringify({ kind: "basilisk.run-receipt", v: 1, cells: [] });
    expect(() => parseReceipt(v1)).toThrow(/predates a change in how artifact roles are recorded/);
    expect(() => parseReceipt(v1)).toThrow(/Its run was not necessarily different/);
    expect(() => parseReceipt(v1)).not.toThrow(/digest mismatch/);
  });

  it("keeps role inside the digest rather than dropping it to dodge the break", () => {
    // `role` is a claim about what an artifact *is*, made by the run. A
    // witness should be able to check that the ceremony's third artifact was a
    // share and not a public key.
    const RECEIPT = stripComments(read("../lib/toolkit/receipt.js"));
    expect(RECEIPT).toMatch(/SAFE_ARTIFACT_FIELDS[\s\S]{0,300}"role"/);
  });
});

describe("§38d — nothing this design adds is persisted", () => {
  it("keeps workspaces to title and recipe, so they load with no migration", () => {
    const STORE = stripComments(read("../lib/toolkit/workspace-store.js"));
    for (const field of ["publishedAs", "directoryUrl", "artifacts", "role", "tags"]) {
      expect(STORE, field).not.toMatch(new RegExp(`\\b${field}\\b`));
    }
  });

  it("keeps the activity log out of localStorage entirely", () => {
    // It names key ids and directory URLs; `workspace-store.js` already
    // states why that does not go in localStorage.
    const LOG = stripComments(read("../lib/toolkit/activity-log.js"));
    expect(LOG).not.toMatch(/localStorage|sessionStorage|indexedDB/);
  });

  it("adds no migrateRecipe entry, because no recipe text changed", () => {
    const before = "gpg.genkey a@b.c | out @kp";
    const after = migrateRecipe(before);
    expect(after.recipe).toBe(before);
    expect(after.changes).toEqual([]);
  });
});

describe("§38e — the ops that stay recipe-only, listed so nobody re-proposes them", () => {
  it("declares none of them as a tile action", () => {
    // Every one takes an input the tile does not have — a key, a payload, a
    // peer, a second artifact — and every one produces a value that belongs in
    // the recipe that will be re-run. §37a is the rule; this is the list.
    const recipeOnly = [
      "gpg.decrypt",
      "ssh.verify",
      "run.verify",
      "sss.combine",
      "vss.combine",
      "rtc.send",
      "age.decrypt",
    ];
    const declared = new Set(ARTIFACT_KINDS.flatMap((k) => k.actions || []));
    for (const name of recipeOnly) {
      expect(getStep(name), `${name} is not registered`).toBeTruthy();
      expect([...declared].some((id) => id.includes(name.split(".").pop())), name).toBe(false);
    }
  });

  it("keeps every declared action to moving an artifact, never computing one", () => {
    // The one rule §37a states, in the form a reviewer can apply: a tile
    // action's id names a *disposition* (copy, publish), not an operation.
    const declared = [...new Set(ARTIFACT_KINDS.flatMap((k) => k.actions || []))];
    for (const id of declared) {
      expect(id, `${id} names a computation`).not.toMatch(
        /decrypt|encrypt|sign|verify|combine|split|derive/i
      );
    }
  });
});
