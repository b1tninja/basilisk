/**
 * The artifact-kind resolver (§32b, design_handoff_artifact_actions).
 *
 * The behaviour worth pinning is not "does it pick a kind" but the three
 * things the if/else chain it replaces got wrong: that specificity decides
 * rather than declaration order, that a tie is an error rather than a race,
 * and that an unknown artifact still renders instead of blanking a cell.
 */
import { describe, expect, it } from "vitest";
import {
  AmbiguousArtifactKindError,
  ambiguousPairs,
  matchScore,
  resolveArtifactKind,
} from "../toolkit/artifact-kinds/resolve.ts";

const kind = (id, role, tags) => ({
  id,
  match: tags ? { role, tags } : { role },
  label: id,
  view: () => null,
  empty: `nothing to show for ${id}`,
});

const FALLBACK = kind("raw", "__fallback__");

describe("matching", () => {
  it("requires the role to match exactly", () => {
    expect(matchScore(kind("k", "key"), { role: "key" })).toBe(0);
    expect(matchScore(kind("k", "key"), { role: "text" })).toBe(-1);
    expect(matchScore(kind("k", "key"), {})).toBe(-1);
  });

  it("requires every listed tag, and scores by how many", () => {
    const k = kind("kp", "key", ["keypair", "public"]);
    expect(matchScore(k, { role: "key", tags: ["keypair", "public"] })).toBe(2);
    // Extra tags on the artifact are fine — the match is a required subset.
    expect(matchScore(k, { role: "key", tags: ["keypair", "public", "ed25519"] })).toBe(2);
    // A missing required tag is no match, not a weaker one.
    expect(matchScore(k, { role: "key", tags: ["keypair"] })).toBe(-1);
  });
});

describe("specificity, not declaration order", () => {
  const generic = kind("key-generic", "key");
  const specific = kind("keypair-public", "key", ["keypair", "public"]);

  it("prefers the kind that matched more tags", () => {
    const artifact = { role: "key", tags: ["keypair", "public"] };
    expect(resolveArtifactKind(artifact, [generic, specific], FALLBACK).id).toBe(
      "keypair-public"
    );
    // Reversed declaration order must not change the answer — that is the
    // whole difference from an if/else chain.
    expect(resolveArtifactKind(artifact, [specific, generic], FALLBACK).id).toBe(
      "keypair-public"
    );
  });

  it("falls back to the general kind when the specific one does not fit", () => {
    const artifact = { role: "key", tags: ["openpgp"] };
    expect(resolveArtifactKind(artifact, [generic, specific], FALLBACK).id).toBe(
      "key-generic"
    );
  });
});

describe("ties are errors", () => {
  it("throws naming both kinds rather than silently picking one", () => {
    const a = kind("a", "token", ["jose"]);
    const b = kind("b", "token", ["jose"]);
    expect(() =>
      resolveArtifactKind({ role: "token", tags: ["jose"] }, [a, b], FALLBACK)
    ).toThrow(AmbiguousArtifactKindError);
    expect(() =>
      resolveArtifactKind({ role: "token", tags: ["jose"] }, [a, b], FALLBACK)
    ).toThrow(/both claim role="token"/);
  });

  it("reports unconditionally ambiguous pairs from the table alone", () => {
    const pairs = ambiguousPairs([
      kind("a", "token", ["jose", "jws"]),
      kind("b", "token", ["jws", "jose"]),
      kind("c", "token", ["jose", "jwe"]),
    ]);
    // a and b are the same match written two ways; c differs.
    expect(pairs).toEqual([["a", "b"]]);
  });

  it("does not flag kinds that merely share a role and tag count", () => {
    // `["keypair","public"]` vs `["keypair","private"]` collide only for an
    // artifact carrying both, which is a question about the engine, not the
    // table — and the resolver throws if such an artifact ever appears.
    expect(
      ambiguousPairs([
        kind("pub", "key", ["keypair", "public"]),
        kind("priv", "key", ["keypair", "private"]),
      ])
    ).toEqual([]);
  });
});

describe("the fallback is a kind, not a crash", () => {
  it("returns it for an unknown role", () => {
    expect(resolveArtifactKind({ role: "invented" }, [kind("k", "key")], FALLBACK).id).toBe(
      "raw"
    );
  });

  it("returns it for an artifact with no role at all", () => {
    // Nothing should be role-less after §32c's projection floor, but an
    // artifact arriving from an older kernel or a partial fixture must render
    // its content rather than blanking the cell.
    expect(resolveArtifactKind({}, [kind("k", "key")], FALLBACK).id).toBe("raw");
    expect(() => resolveArtifactKind({}, [], FALLBACK)).not.toThrow();
  });
});
