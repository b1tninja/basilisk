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
import { OpenPgpKeyCard } from "../widgets/OpenPgpKeyCard";
import { PacketMapCard } from "../widgets/PacketMapCard";
import { QrArtifact } from "../widgets/QrArtifact";
import { ReceiptCard } from "../widgets/ReceiptCard";
import { RecipientsCard } from "../widgets/RecipientsCard";
import { ShareIdentity } from "../widgets/ShareIdentity";
import { SshSigCard } from "../widgets/SshSigCard";
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
  /**
   * Copy is not a kind's privilege — every artifact can be copied, and the
   * fallback claims most of them. Omitting this took the Copy button off the
   * majority of tiles the moment the bespoke one was replaced by the table:
   * a kind that declares no actions renders no buttons, which is correct for
   * a kind's *own* actions and wrong for the universal one.
   */
  actions: ["copy"],
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

const pgpCardFor = (publicOnly: boolean) =>
  function OpenPgpView({ artifact }: ArtifactViewContext) {
    const traits = (artifact.traits || {}) as { fingerprint?: string };
    return (
      <OpenPgpKeyCard
        content={artifact.content}
        fingerprint={traits.fingerprint}
        publicOnly={publicOnly}
      />
    );
  };

export const ARTIFACT_KINDS: readonly ToolkitArtifactKind[] = [
  {
    /**
     * The armored public key `gpg.genkey` emits. The only kind that gets
     * Publish (§35f) — and Publish stays on the tile's existing confirm
     * flow until §34c's ConsequenceBanner lands, rather than being declared
     * here twice.
     */
    id: "openpgp-public",
    match: { role: "public-key" },
    label: "OpenPGP public key",
    glyph: "openpgp-key",
    view: pgpCardFor(true),
    empty: "Not a readable OpenPGP key — showing the armor.",
    actions: ["copy", "key.copyFingerprint"],
  },
  {
    /**
     * The armored private half. No Publish, ever — it is not declared, so
     * there is no button and nothing to reason about at runtime.
     */
    id: "openpgp-private",
    match: { role: "key", tags: ["openpgp", "private"] },
    label: "OpenPGP private key",
    glyph: "openpgp-key",
    view: pgpCardFor(false),
    // Uid, fingerprint and dates are public facts about the key, so they
    // render while the secret stays masked (§34b).
    publicView: pgpCardFor(true),
    empty: "Not a readable OpenPGP key — showing the armor.",
    actions: ["copy", "key.copyFingerprint"],
  },
  {
    id: "keypair-public",
    match: { role: "key", tags: ["keypair", "public"] },
    label: "Public key",
    glyph: "key",
    view: keyCardFor(true),
    empty: "No exportable public half — the key was generated non-extractable.",
    actions: ["copy", "key.copyFingerprint", "key.copyPublicLine"],
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
    // No public line here: the private tile's job is the secret, and the
    // public half is one tile over. Copy fingerprint stays — it is a public
    // fact and works while masked (§35d).
    actions: ["copy", "key.copyFingerprint"],
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
    actions: ["copy", "key.copyFingerprint", "key.copyPublicLine"],
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
    // Expand and Download remain tile-level affordances for now (the tile
    // derives Expand from the kind's `expandable`), so they are not declared
    // here — a declared action that duplicates a shipped button is worse than
    // one not yet migrated.
    actions: ["copy"],
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
    // Expand and Download remain tile-level affordances for now (the tile
    // derives Expand from the kind's `expandable`), so they are not declared
    // here — a declared action that duplicates a shipped button is worse than
    // one not yet migrated.
    actions: ["copy"],
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
    // Expand and Download remain tile-level affordances for now (the tile
    // derives Expand from the kind's `expandable`), so they are not declared
    // here — a declared action that duplicates a shipped button is worse than
    // one not yet migrated.
    actions: ["copy"],
    expandable: true,
  },

  // ── §37, the rest of the inventory ────────────────────────────────────────
  //
  // Two things decided almost every entry below. §37a's rule — *a button may
  // move an artifact, never compute a new one* — is why none of these declares
  // Decrypt with…, Verify threshold, Send to peer or Save as group. And §37a's
  // corollary, which is the more useful half: several of the brief's candidate
  // actions are really *views*. "Inspect packets" on a ciphertext is not a
  // button; it is what the ciphertext tile should already show. Applying that
  // turned a list of actions nobody would click into a set of tiles worth
  // looking at, which is what these are.
  //
  // Every entry declares `copy` and nothing else, for the same reason the rest
  // of the table does: `download`, `expand` and `shares.print` are still tile
  // affordances or unbuilt services, and a declared action that duplicates a
  // shipped button — or names a service that is not injected — is worse than
  // one not yet migrated.
  {
    /**
     * The armored message `gpg.encrypt` produces. §37b's read-out: the packet
     * framing, which is in the clear, over the armor, which is one toggle
     * away. *Decrypt with…* is rejected by §37a — it would produce a value
     * with no derivation behind it, no type, and no place in the recipe or
     * the receipt, which is the thing the CLI could not reproduce.
     */
    id: "ciphertext",
    match: { role: "ciphertext" },
    label: "Ciphertext",
    view: ({ artifact }) => <PacketMapCard content={artifact.content} />,
    empty:
      "This body is not OpenPGP-framed, so there are no packets to map — the armor is below.",
    actions: ["copy"],
  },
  {
    /**
     * The recovery envelope of a ceremony. Same body, same read-out, a
     * different *artifact*: the engine already labels it "required for
     * recovery (not a share)", and that sentence is the reason the role
     * exists — a witness who mistakes the envelope for a share will destroy a
     * ceremony by counting it toward the threshold.
     */
    id: "envelope",
    match: { role: "envelope" },
    label: "Envelope",
    view: ({ artifact }) => <PacketMapCard content={artifact.content} />,
    empty:
      "This body is not OpenPGP-framed, so there are no packets to map — the armor is below.",
    actions: ["copy"],
  },
  {
    /**
     * One share of a split.
     *
     * No `view`, deliberately, and this is the one entry where the absence is
     * the design rather than a deferral. A share's value *is* its own words,
     * and the tile already renders words with a format bar, a Hide button and
     * the 15s auto-hide; a widget that redrew the body would have taken all
     * three away to add nothing. What the tile could not say is which share
     * this is and how many recover the secret — both public, neither derived
     * from the masked material — so that is exactly what `publicView` adds,
     * on the tile where it was missing: the masked one.
     *
     * `ShareCards` is not mounted here even though §37b names it. It is the
     * *set's* surface — one card per share, its own per-mount reveal, its own
     * print warning — and it is reachable from the ceremony. Mounting it
     * per-tile would put a second reveal gate behind the tile's first one and
     * print one card at a time.
     */
    id: "share",
    match: { role: "share" },
    label: "Share",
    glyph: "share",
    view: () => null,
    publicView: ({ artifact }) => <ShareIdentity artifact={artifact} />,
    empty:
      "A share is its own words — the body below is the whole share, and nothing else about it is kept.",
    // *Verify threshold* is rejected by §37a (it computes a verdict), and
    // *Check a share…* already exists under More ▸ — a second copy on the
    // tile is how one of them starts drifting from the other.
    actions: ["copy"],
  },
  {
    /**
     * A recipient list, from `hkp.search` / `hkp.filter` / the cache.
     * *Save as group* is rejected: no group concept exists in the engine, and
     * inventing one in a tile is how a parallel vocabulary starts.
     */
    id: "recipients",
    match: { role: "recipients" },
    label: "Recipients",
    glyph: "recipients",
    view: ({ artifact }) => <RecipientsCard content={artifact.content} />,
    empty:
      "No recipients in this list — hkp.filter may have removed them all, or the search found none.",
    actions: ["copy"],
    expandable: true,
  },
  {
    /**
     * An sshsig signature block. Namespace, hash and signer — no verify
     * button: verification needs a key and the payload, and the tile has
     * neither. That is `ssh.verify` (§37b, §38e).
     */
    id: "sshsig",
    match: { role: "sshsig" },
    label: "SSH signature",
    glyph: "signature",
    view: ({ artifact }) => <SshSigCard content={artifact.content} />,
    empty:
      "This armor did not parse as an sshsig envelope — showing it as text instead.",
    actions: ["copy"],
  },
  {
    /**
     * `stun.check` and friends — a read-out with a verdict, drawn by the same
     * `NetworkArtifact` the netvalue kind uses, because it is the same
     * structured body with the same pair matrix.
     *
     * The "Configure TURN" affordance is not declared here: the tile already
     * renders it from `diagnosticAction`, wired to the shell's caret jump.
     * §37b files it as the one action that is neither inert nor a
     * disposition — it *navigates* — and it stays where it is until the
     * action table can carry a navigation service.
     */
    id: "diagnostic",
    match: { role: "diagnostic" },
    label: "Diagnostic",
    glyph: "diag",
    view: ({ artifact }) => (
      <NetworkArtifact
        netType={String(artifact.netType || "")}
        netKind={artifact.netKind as string | undefined}
        data={artifact.netData}
        content={artifact.content}
        onConfigureTurn={artifact.onConfigureTurn as (() => void) | undefined}
      />
    ),
    empty: "No structured diagnostic body — showing the raw report.",
    actions: ["copy"],
    expandable: true,
  },
  {
    /**
     * A run receipt. The digest table, in the order `run.verify` walks it —
     * and no "verify this" button, because verifying means re-running the
     * recipe and comparing, which is an op with a receipt as its input. A
     * button here could only ever re-run *this* notebook.
     */
    id: "receipt",
    match: { role: "receipt" },
    label: "Receipt",
    view: ({ artifact }) => <ReceiptCard content={artifact.content} />,
    empty:
      "This is not a receipt this build can read — a v1 receipt predates the artifact-role change; run.verify explains it.",
    actions: ["copy"],
    expandable: true,
  },
  {
    /**
     * An SVG QR rendering of another artifact — the one artifact whose raw
     * form is useless: nobody reads a QR by reading its path data.
     *
     * §37b drops Copy here ("copying SVG source is not a thing anyone wants").
     * It stays, for now, because `download` and `shares.print` are not actions
     * yet: dropping Copy first would leave this tile with no affordance at all,
     * which is a worse tile than one with a slightly odd button. It goes when
     * Download lands.
     */
    id: "qr",
    match: { role: "qr" },
    label: "QR",
    view: ({ artifact }) => (
      <QrArtifact content={artifact.content} label={artifact.label} />
    ),
    empty: "This body is not an SVG, so there is no code to draw — showing it as text.",
    actions: ["copy"],
  },
  {
    /**
     * Anything with no better description, and its sensitive twin.
     *
     * Both are claimed with **no view of their own**, which is a real answer
     * rather than a gap: the raw body, its format bar and its reveal gate are
     * already the right rendering of an opaque value, and a widget invented to
     * fill the row would be a worse one. What claiming them buys is that the
     * table now says so — `data-artifact-kind="text"` instead of `"fallback"`,
     * a label for the badge, and a sentence for the case where there is no
     * body at all. The fallback goes back to meaning what §32f says it means:
     * an artifact the table does not know about.
     *
     * `text` is also where sshsig, PEM and DER exports still land — they carry
     * their own tags but the type projection's `key` role is not taken up for
     * them yet (the key card reads JWK, not armor; §35e).
     */
    id: "text",
    match: { role: "text" },
    label: "Text",
    glyph: "text",
    view: () => null,
    empty: "This artifact has no body — the step that produced it emitted nothing.",
    actions: ["copy"],
  },
  {
    id: "secret",
    match: { role: "secret" },
    label: "Secret",
    glyph: "secret",
    view: () => null,
    // No `publicView`. A scalar or a master secret has no public half to
    // draw — unlike a keypair, where the algorithm and fingerprint are facts
    // about the public side. Inventing a line here would mean deriving it
    // from the masked material, which is the one thing §34b forbids.
    empty:
      "This secret has no body to show — reveal it, if the recipe asked for it, to see the value.",
    actions: ["copy"],
  },
];
