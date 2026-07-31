/**
 * Resolving an artifact to its kind (§32b, design_handoff_artifact_actions).
 *
 * `OutputList` currently picks a renderer with an if/else chain over three
 * bespoke predicates — `hasNetworkRenderer(a.netType)`, then
 * `a.inspectSnapshot`, then `hasJoseRenderer(a.jose)` — each keyed off a
 * *parallel data field* rather than off what the artifact is. That conflates
 * two questions: `hasJoseRenderer` really asks "did an op leave a JOSE body
 * here", which is not the same as "this artifact is a token". An artifact
 * whose body failed to parse then silently becomes a different kind.
 *
 * Here the kind is matched from the artifact's identity — `role` plus a
 * required subset of `tags`, both stamped by the type projection (§32c) — and
 * the *view* reads the body. A `jose-token` with no JOSE body renders that
 * kind's empty state, which is a sentence explaining what is missing, rather
 * than falling through to raw text as if it were something else.
 *
 * Matching deliberately does not use `pipeType` even though it is richer: the
 * refined type is a structure, and matching on it would put a second
 * `matchOverload` mini-language in the widget layer.
 */

import type { ReactNode } from "react";

/** What an artifact must look like for a kind to claim it. */
export type ArtifactMatch = {
  /** Exact match against `artifact.role`. */
  role: string;
  /** Every listed tag must be present on the artifact. */
  tags?: string[];
};

/** The subset of an artifact the resolver reads. */
export type ResolvableArtifact = {
  role?: string;
  tags?: string[];
};

export type ArtifactKind<A = unknown, S = unknown> = {
  /** Stable id — rides `data-artifact-kind` and names the catalog fixture. */
  id: string;
  match: ArtifactMatch;
  /** Human name for the kind badge ("Keypair", "Token"). */
  label: string;
  /** KIND_GLYPHS key. Omitted renders no glyph, never a guess. */
  glyph?: string;
  view: (ctx: { artifact: A; masked: boolean; services: S }) => ReactNode | null;
  /** Shown when `view` returns null — a sentence, not "N/A". */
  empty: string;
  /** Shown when `view` throws; the raw body still renders beneath. */
  failed?: (err: Error) => string;
  /** Action ids, resolved against the action table (§33c). */
  actions?: string[];
  expandable?: boolean;
};

/**
 * Does this kind claim this artifact, and by how many tags?
 * Returns -1 for no match, otherwise the number of tags matched (0 when the
 * kind requires none) — the specificity score.
 */
export function matchScore(kind: ArtifactKind, artifact: ResolvableArtifact): number {
  if (!artifact?.role || kind.match.role !== artifact.role) return -1;
  const required = kind.match.tags || [];
  if (!required.length) return 0;
  const have = new Set((artifact.tags || []).map(String));
  for (const t of required) {
    if (!have.has(t)) return -1;
  }
  return required.length;
}

/**
 * Two kinds claiming the same artifact with equal specificity is a bug in the
 * table, not a race to be settled by declaration order. It surfaces as a
 * thrown error in the coverage test rather than as whichever entry happened to
 * be listed first — the `toolbox-dot-css.test.js` precedent of guarding a
 * duplication mechanically instead of remembering it.
 */
export class AmbiguousArtifactKindError extends Error {
  constructor(artifact: ResolvableArtifact, ids: string[]) {
    super(
      `artifact kinds ${ids.join(" and ")} both claim role="${artifact.role}" ` +
        `tags=[${(artifact.tags || []).join(", ")}] with equal specificity — ` +
        `one of them needs a narrower match`
    );
    this.name = "AmbiguousArtifactKindError";
  }
}

/**
 * Pick the kind for an artifact: highest specificity wins, ties throw.
 *
 * `fallback` is returned when nothing claims it. The fallback is a real kind
 * with a real view (§32f), not null and not a crash — an artifact the table
 * does not know about must still render its content, because the alternative
 * is a blank cell where a value used to be.
 */
export function resolveArtifactKind<K extends ArtifactKind>(
  artifact: ResolvableArtifact,
  kinds: readonly K[],
  fallback: K
): K {
  let best: K | null = null;
  let bestScore = -1;
  let tied: K | null = null;

  for (const kind of kinds) {
    const score = matchScore(kind, artifact);
    if (score < 0) continue;
    if (score > bestScore) {
      best = kind;
      bestScore = score;
      tied = null;
    } else if (score === bestScore) {
      tied = kind;
    }
  }

  if (best && tied) throw new AmbiguousArtifactKindError(artifact, [best.id, tied.id]);
  return best || fallback;
}

/**
 * Kind pairs that are *unconditionally* ambiguous: same role, same tag set.
 * No artifact can ever distinguish them, so this is a defect in the table
 * regardless of what the engine emits, and the coverage test fails on it.
 *
 * Deliberately not flagged: two kinds with equal-length but different tag
 * sets (`["keypair","public"]` vs `["keypair","private"]`). Those collide only
 * for an artifact carrying the union of both, which is a question about what
 * the engine emits, not about the table. The coverage test answers that one by
 * resolving real artifacts and letting `resolveArtifactKind` throw.
 */
export function ambiguousPairs(kinds: readonly ArtifactKind[]): [string, string][] {
  const out: [string, string][] = [];
  const key = (k: ArtifactKind) =>
    `${k.match.role}|${[...(k.match.tags || [])].sort().join(",")}`;
  for (let i = 0; i < kinds.length; i++) {
    for (let j = i + 1; j < kinds.length; j++) {
      if (key(kinds[i]) === key(kinds[j])) out.push([kinds[i].id, kinds[j].id]);
    }
  }
  return out;
}
