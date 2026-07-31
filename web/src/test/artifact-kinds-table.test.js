/**
 * The artifact-kind table (§32e/§32f, design_handoff_artifact_actions).
 *
 * The resolver's semantics are pinned in `artifact-kinds.test.js`; this file
 * is about the table itself — that it is unambiguous, that it claims the roles
 * it says it claims, and that folding the three existing renderers in did not
 * require changing them.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { ARTIFACT_ROLES } from "../lib/toolkit/types.js";
import {
  ARTIFACT_KINDS,
  FALLBACK_KIND,
} from "../toolkit/artifact-kinds/registry.tsx";
import { ambiguousPairs, resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";

const TABLE_SRC = readFileSync(
  fileURLToPath(new URL("../toolkit/artifact-kinds/registry.tsx", import.meta.url)),
  "utf8"
);
/** Source with comments removed, for assertions about what the code *does*. */
const CODE_ONLY = TABLE_SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(
  /\/\/[^\n]*/g,
  ""
);

/**
 * Roles with no kind entry yet. This list may only ever shrink: §35 and §37
 * of the design fill it in, and until then an honest test records the gap
 * rather than asserting a coverage that does not exist. A role added without
 * a kind fails here, which is the point.
 */
const UNCLAIMED_ROLES = [
  "text",
  "secret",
  "key",
  "public-key",
  "share",
  "recipients",
  "ciphertext",
  "envelope",
  "sshsig",
  "diagnostic",
  "receipt",
  "qr",
];

describe("the table is unambiguous", () => {
  it("has no two entries that could both claim the same artifact", () => {
    expect(ambiguousPairs(ARTIFACT_KINDS)).toEqual([]);
  });

  it("gives every entry a stable id, a label and an empty-state sentence", () => {
    const ids = new Set();
    for (const kind of ARTIFACT_KINDS) {
      expect(kind.id, "id").toBeTruthy();
      expect(ids.has(kind.id), `duplicate id ${kind.id}`).toBe(false);
      ids.add(kind.id);
      expect(typeof kind.view, `${kind.id} view`).toBe("function");
      // An empty state is a sentence explaining what is missing and what would
      // produce it — never "N/A", which tells the reader nothing.
      expect(kind.empty.length, `${kind.id} empty`).toBeGreaterThan(20);
      expect(kind.empty, `${kind.id} empty`).not.toMatch(/^N\/A|^none$/i);
    }
  });

  it("only claims roles that exist in the vocabulary", () => {
    for (const kind of ARTIFACT_KINDS) {
      expect(ARTIFACT_ROLES, kind.id).toContain(kind.match.role);
    }
  });
});

describe("role coverage", () => {
  const claimed = new Set(ARTIFACT_KINDS.map((k) => k.match.role));

  it("claims netvalue, inspect and token", () => {
    for (const role of ["netvalue", "inspect", "token"]) {
      expect(claimed.has(role), role).toBe(true);
    }
  });

  it("records exactly the roles still without a kind", () => {
    // Shrinks as §35/§37 land. If it needs to *grow*, a role was added
    // without a kind and this is where that is caught.
    const unclaimed = ARTIFACT_ROLES.filter((r) => !claimed.has(r));
    expect([...unclaimed].sort()).toEqual([...UNCLAIMED_ROLES].sort());
  });
});

describe("the fallback is a kind, not a crash (§32f)", () => {
  it("claims nothing, so it is only ever reached by falling through", () => {
    expect(ARTIFACT_ROLES).not.toContain(FALLBACK_KIND.match.role);
  });

  it("renders no view of its own, leaving the raw body to show", () => {
    // Deliberately not an error tile and not a warning: the value is real and
    // correct, and only our description of it is missing. Converting an engine
    // metadata omission into a user-visible failure inverts the severity.
    expect(FALLBACK_KIND.view({ artifact: { content: "x" }, masked: false })).toBeNull();
  });

  it("catches an unclaimed role today", () => {
    const kind = resolveArtifactKind(
      { role: "receipt" },
      ARTIFACT_KINDS,
      FALLBACK_KIND
    );
    expect(kind.id).toBe("fallback");
  });
});

describe("the existing renderers were folded in, not rewritten (§32e)", () => {
  it("imports all three unmodified", () => {
    expect(TABLE_SRC).toMatch(/import \{ NetworkArtifact \} from "\.\.\/widgets\/NetworkArtifact"/);
    expect(TABLE_SRC).toMatch(
      /import \{ InspectorArtifact \} from "\.\.\/widgets\/InspectorArtifact"/
    );
    expect(TABLE_SRC).toMatch(
      /import \{ JwtArtifact, hasJoseRenderer \} from "\.\.\/widgets\/JwtArtifact"/
    );
  });

  it("no longer keys the render path off hasNetworkRenderer", () => {
    // The seven network bases are now the definition of role "netvalue" in the
    // type projection, so the list of renderable network types lives with the
    // types instead of being duplicated in a widget.
    // Asserted against the source with comments stripped: the header explains
    // why the predicate is gone, in prose that names and calls it. Forbidding
    // the word outright would delete the explanation along with the thing it
    // explains — the same trap the threat-model and ScrollArea tests hit.
    expect(CODE_ONLY).not.toMatch(/hasNetworkRenderer/);
  });

  it("demotes hasJoseRenderer to a body check inside a view", () => {
    // It answers "is this body shaped like a token body", which is the right
    // question for it — but it is no longer what decides the kind.
    const jose = ARTIFACT_KINDS.find((k) => k.id === "jose-token");
    expect(jose.match.role).toBe("token");
    expect(TABLE_SRC).toMatch(/view: \(\{ artifact \}\) =>\s*hasJoseRenderer/);
  });

  it("renders the empty state rather than a different kind when a body is missing", () => {
    // The if/else chain would have fallen through to raw text here, silently
    // treating a token as untyped. The kind is matched from identity, so a
    // token with no decoded body is still a token.
    const jose = ARTIFACT_KINDS.find((k) => k.id === "jose-token");
    expect(jose.view({ artifact: { content: "eyJ…", jose: undefined }, masked: false })).toBeNull();
    expect(jose.empty).toMatch(/jose\.verify/);
  });
});
