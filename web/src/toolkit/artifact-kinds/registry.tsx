/**
 * The artifact-kind table (§32e, design_handoff_artifact_actions).
 *
 * One declared list replaces the if/else chain in `OutputList`. The three
 * renderers that chain dispatched to are imported here **unmodified** — that
 * is the acceptance test for this abstraction. If folding them in had required
 * editing `NetworkArtifact`, `InspectorArtifact` or `JwtArtifact` internals,
 * the abstraction would be wrong and this file would be a fourth way of doing
 * the same thing rather than a replacement for the first three.
 *
 * Note what stopped being a render-path predicate. `hasNetworkRenderer(netType)`
 * asked a widget which network types it could draw; the seven network bases are
 * now the *definition* of `role: "netvalue"` in `artifactMetaFromType`, so that
 * list lives with the types instead of being duplicated in the UI.
 * `hasJoseRenderer` survives, demoted from kind check to body check inside a
 * view — which is the question it actually answers.
 */

import type { ArtifactTile } from "../notebook-types";
import { NetworkArtifact } from "../widgets/NetworkArtifact";
import { InspectorArtifact } from "../widgets/InspectorArtifact";
import { JwtArtifact, hasJoseRenderer } from "../widgets/JwtArtifact";
import { KeyCard } from "../widgets/KeyCard";
import type { ArtifactKind } from "./resolve";

/** What a view is handed. Kept small on purpose; kinds read the artifact. */
export type ArtifactViewContext = {
  artifact: ArtifactTile & Record<string, unknown>;
  masked: boolean;
};

export type ToolkitArtifactKind = ArtifactKind<
  ArtifactViewContext["artifact"],
  never
> & {
  view: (ctx: ArtifactViewContext) => React.ReactNode | null;
  /**
   * A body that renders *while masked* (§33e), because it derives only from
   * public material. This is not a hole in the mask: the rule is stated once —
   * a masked tile may render only what does not derive from the masked value —
   * and `publicView` is where a kind asserts it, in code review, per kind,
   * rather than by each tile deciding for itself.
   */
  publicView?: (ctx: ArtifactViewContext) => React.ReactNode | null;
};

/**
 * An artifact matching no entry (§32f).
 *
 * `view` returns null so the tile falls through to the raw body it would have
 * rendered anyway. There is deliberately no "unknown type" warning: a user who
 * wrote a recipe and got a correct value should not be told the UI is
 * confused. The value is fine; only our description of it is missing, and the
 * raw view is what every artifact gets today regardless.
 *
 * The gap is made visible in a test instead — `artifact-kinds-table.test.js`
 * asserts every role in `ARTIFACT_ROLES` is claimed, so adding a role without
 * a kind fails CI rather than silently landing here.
 */
export const FALLBACK_KIND: ToolkitArtifactKind = {
  id: "fallback",
  match: { role: "__none__" },
  label: "",
  view: () => null,
  empty: "",
};

const keyCardFor = (publicOnly: boolean) =>
  function KeyCardView({ artifact }: ArtifactViewContext) {
    const traits = (artifact.traits || {}) as { alg?: string; fingerprint?: string };
    return (
      <KeyCard
        content={artifact.content}
        alg={traits.alg}
        fingerprint={traits.fingerprint}
        publicOnly={publicOnly}
      />
    );
  };

export const ARTIFACT_KINDS: readonly ToolkitArtifactKind[] = [
  {
    id: "keypair-public",
    match: { role: "key", tags: ["keypair", "public"] },
    label: "Public key",
    glyph: "key",
    view: keyCardFor(true),
    empty: "No exportable public half — the key was generated non-extractable.",
    actions: ["copy", "download", "expand"],
  },
  {
    id: "keypair-private",
    match: { role: "key", tags: ["keypair", "private"] },
    label: "Private key",
    glyph: "key",
    view: keyCardFor(false),
    // §35d: a masked private-key tile is no longer blank. Algorithm,
    // fingerprint and public line derive from public material, so they render
    // while the secret stays masked; the masked line sits under them.
    publicView: keyCardFor(true),
    empty: "No exportable private half — the key was generated non-extractable.",
    actions: ["copy", "download", "expand"],
  },
  {
    /**
     * Any key with no half declared — the auto-emitted pipeline tip, a single
     * `key` handle, a PEM/DER export (§35e). Least specific, so the tagged
     * keypair kinds above still win when the `out` path named a half; that
     * ordering is the resolver's job, not declaration order's.
     */
    id: "key",
    match: { role: "key" },
    label: "Key",
    glyph: "key",
    view: keyCardFor(false),
    publicView: keyCardFor(true),
    empty: "No exportable key material — the key was generated non-extractable.",
    actions: ["copy", "download", "expand"],
  },
  {
    id: "network-value",
    match: { role: "netvalue" },
    label: "Network",
    // No glyph on purpose: kind-glyphs.tsx leaves candidate/session/connstate
    // abstract because a pictogram asserts a real-world reading a negotiating
    // connection has not earned. That decision is respected here, not
    // re-litigated.
    view: ({ artifact }) => (
      <NetworkArtifact
        netType={String(artifact.netType || "")}
        netKind={artifact.netKind as string | undefined}
        data={artifact.netData}
        content={artifact.content}
        onConfigureTurn={artifact.onConfigureTurn as (() => void) | undefined}
      />
    ),
    empty: "No structured body for this value — showing the raw text.",
    actions: ["copy", "download", "expand"],
    expandable: true,
  },
  {
    id: "inspect-snapshot",
    match: { role: "inspect" },
    label: "Inspect",
    glyph: "inspect",
    view: ({ artifact }) =>
      artifact.inspectSnapshot ? (
        <InspectorArtifact snapshot={artifact.inspectSnapshot as never} />
      ) : null,
    // The absence is a decision, not a gap: a snapshot of a sensitive value
    // would retain raw private JWK fields the masked text dump does not.
    empty:
      "This value is sensitive, so no structured snapshot was kept — the text dump is below.",
    actions: ["copy", "download", "expand"],
    expandable: true,
  },
  {
    id: "jose-token",
    match: { role: "token" },
    label: "Token",
    glyph: "signature",
    view: ({ artifact }) =>
      hasJoseRenderer(artifact.jose) ? <JwtArtifact data={artifact.jose} /> : null,
    empty: "No decoded token body — run jose.verify to read and check it.",
    actions: ["copy", "download", "expand"],
    expandable: true,
  },
];
