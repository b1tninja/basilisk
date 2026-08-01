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
import { OtpCodeCard, hasOtpReadout } from "../widgets/OtpCodeCard";
import { PacketMapCard } from "../widgets/PacketMapCard";
import { QrArtifact } from "../widgets/QrArtifact";
import { ReceiptCard } from "../widgets/ReceiptCard";
import { RecipientsCard } from "../widgets/RecipientsCard";
import { ShareIdentity } from "../widgets/ShareIdentity";
import { SshKeyCard } from "../widgets/SshKeyCard";
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
   *
   * Download is universal for the same reason and by the same test. §33d asks
   * "is this meaningful for this object", and for a body the answer is yes
   * wherever Copy's is: the two are one motion — a value leaving the notebook
   * — with two destinations, one to paste once and one to keep. Whether *this*
   * body can be written here and now is the other question, and `available()`
   * answers it with a sentence.
   */
  actions: ["copy", "download"],
};

type KeyTraits = { alg?: string; fingerprint?: string; publicJwk?: string };

const keyCardFor = (
  publicOnly: boolean,
  half?: "public" | "private" | "both" | "secret"
) =>
  function KeyCardView({ artifact }: ArtifactViewContext) {
    const traits = (artifact.traits || {}) as KeyTraits;
    return (
      <KeyCard
        content={artifact.content}
        jwk={traits.publicJwk}
        alg={traits.alg}
        fingerprint={traits.fingerprint}
        half={half}
        publicOnly={publicOnly}
      />
    );
  };

/**
 * The whole-keypair card — the tip of a bare `genkey`, drawn from its public
 * half alone.
 *
 * The same component the halves use, given the two things that make it
 * unmistakable at a glance: a caption that names *both* halves, and a sentence
 * saying the private one is held back and what to write to get it. `publicOnly`
 * is passed because there is no body to toggle open — not because this is a
 * public key, which is the conflation that produced the bug.
 *
 * `view` and `publicView` are the same function deliberately. A tile with no
 * body has nothing a reveal could add, so masked and unmasked must render
 * identically — and making that structural means no future reveal path can
 * turn into a leak here.
 */
function KeypairCard({ artifact }: ArtifactViewContext) {
  const traits = (artifact.traits || {}) as KeyTraits;
  return (
    <KeyCard
      content=""
      jwk={traits.publicJwk}
      alg={traits.alg}
      fingerprint={traits.fingerprint}
      half="both"
      publicOnly
      /*
       * Stays a literal here, and the tail of `artifact-reasons.js` says why:
       * it shares `neverAskedFor`'s *condition* but not its voice — a caption
       * in the lowercase register of the two beside it on this card, not a
       * refusal spoken by a control. It is pinned verbatim in
       * `artifact-kinds-table.test.js`, which is the thing it was missing.
       */
      withheld="private half not shown — add `out @kp` to the recipe to write both halves"
    />
  );
}

/**
 * The JOSE reader, drawn from the engine's own `meta.jose` body.
 *
 * A single function so `view` and `publicView` can be *the same reference*
 * rather than two copies that agree today — the `KeypairCard` arrangement, and
 * the property `artifact-kinds-table.test.js` pins there. Nothing here parses
 * the token: `header`, `claims`, `payloadText` and `timing` were computed by
 * the op that ran, which is the only party that knows whether a signature was
 * checked. A view that re-derived them could only ever report "unverified".
 */
function JoseTokenCard({ artifact }: ArtifactViewContext) {
  return hasJoseRenderer(artifact.jose) ? <JwtArtifact data={artifact.jose} /> : null;
}

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
     * The armored public key `gpg.genkey` emits, and the only kind that gets
     * Publish (§35f/§38b). It is declared here rather than passed in as a
     * per-artifact callback, so "which artifacts can be published" is one
     * answer in the table instead of a `publishable` boolean the shell
     * recomputes — the same consolidation the badge mapping needed.
     */
    id: "openpgp-public",
    /**
     * The `openpgp` tag is required now that `public-key` is every public
     * half's role rather than OpenPGP's alone. Without it this kind would
     * claim a WebCrypto public JWK at specificity 0 and draw armor for it.
     */
    match: { role: "public-key", tags: ["openpgp"] },
    label: "OpenPGP public key",
    glyph: "key-public",
    sensitivity: "public",
    view: pgpCardFor(true),
    empty: "Not a readable OpenPGP key — showing the armor.",
    actions: ["copy", "download", "key.copyFingerprint", "key.publish"],
  },
  {
    /**
     * The armored private half. No Publish, ever — it is not declared, so
     * there is no button and nothing to reason about at runtime.
     */
    id: "openpgp-private",
    match: { role: "key", tags: ["openpgp", "private"] },
    label: "OpenPGP private key",
    glyph: "key-secret",
    sensitivity: "secret",
    view: pgpCardFor(false),
    // Uid, fingerprint and dates are public facts about the key, so they
    // render while the secret stays masked (§34b).
    publicView: pgpCardFor(true),
    empty: "Not a readable OpenPGP key — showing the armor.",
    actions: ["copy", "download", "key.copyFingerprint", "keyring.add"],
  },
  {
    /**
     * Both halves, body withheld (§35g).
     *
     * Its own role rather than a tag on `key`, because the badge on a tile is
     * its role and the confusion this fixes is a glance-level one: `genkey
     * ed25519` with no `out` used to fall to the least-specific `key` kind,
     * whose masked body is `keyCardFor(true)` — the *public half* card. The
     * type was never wrong; the rendering was. Side by side with
     * `keypair-public` this now differs in the badge (KEYPAIR, not KEY), the
     * caption ("public + private halves", not "public half"), the withheld
     * line, and the absence of a JWK body.
     *
     * `keyring.add` is not declared. It needs a private half in the *body*,
     * and this tile's body is empty by design — a disabled button whose stated
     * reason is "carries no key material" would be true of the artifact and
     * false of the keypair, which is the worst kind of accurate.
     * `key.copyFingerprint` and `key.copyPublicLine` are declared, and work,
     * because both derive from the public JWK on `traits` (§34b).
     */
    id: "keypair",
    match: { role: "keypair" },
    label: "Keypair",
    glyph: "key-pair",
    /**
     * **Secret, and this is the one that had an argument on both sides.**
     *
     * The case for public is real: everything this tile *draws* is a public
     * fact. `view` and `publicView` are the same function, deliberately, and
     * the body it renders is the algorithm, the fingerprint and the public
     * JWK. Read as a rendering, it is the most public tile in the section.
     *
     * It is still secret, because the badge names the **artifact** and not
     * the view. `@kp` holds both halves; Copy and Download move both; the
     * withheld line exists precisely to say that the half you cannot see is
     * in there. A tier that described what is currently painted would flip
     * from public to secret the moment a recipe added `out @kp`, which is the
     * definition of a label that does not name its object.
     *
     * And the two errors are not the same size. Tinting a keypair public is a
     * disclosure — the user hands over a file believing it is a public half.
     * Tinting it secret costs a magenta chip on a tile whose contents are
     * genuinely half-secret. The asymmetric one loses.
     */
    sensitivity: "secret",
    view: KeypairCard,
    publicView: KeypairCard,
    empty:
      "This keypair was generated non-extractable, so even its public half cannot be shown — regenerate it to see the algorithm and fingerprint.",
    actions: ["copy", "download", "key.copyFingerprint", "key.copyPublicLine"],
  },
  {
    id: "keypair-public",
    match: { role: "public-key", tags: ["keypair", "public"] },
    label: "Public key",
    glyph: "key-public",
    sensitivity: "public",
    view: keyCardFor(true, "public"),
    empty: "No exportable public half — the key was generated non-extractable.",
    actions: ["copy", "download", "key.copyFingerprint", "key.copyPublicLine"],
  },
  {
    /**
     * A public half with no pair beside it — an `import spki` tip, a projected
     * `:public`. Least specific of the three `public-key` kinds, so the
     * OpenPGP and paired ones win where they apply.
     *
     * No `publicView`: a public key is never masked, so a body that rendered
     * while masked would be a claim about a state this kind cannot reach.
     */
    id: "public-key",
    match: { role: "public-key" },
    label: "Public key",
    glyph: "key-public",
    sensitivity: "public",
    view: keyCardFor(true, "public"),
    empty: "No exportable public key — the key was generated non-extractable.",
    actions: ["copy", "download", "key.copyFingerprint", "key.copyPublicLine"],
  },
  {
    id: "keypair-private",
    match: { role: "key", tags: ["keypair", "private"] },
    label: "Private key",
    glyph: "key-secret",
    sensitivity: "secret",
    view: keyCardFor(false, "private"),
    // §35d: a masked private-key tile is no longer blank. Algorithm,
    // fingerprint and public line derive from public material, so they render
    // while the secret stays masked; the masked line sits under them.
    //
    // The half is stated on both, and stating it is the fix: `publicOnly` used
    // to caption the card as well as hide the raw toggle, so this — the masked
    // *private* tile — said "public half" about itself.
    publicView: keyCardFor(true, "private"),
    empty: "No exportable private half — the key was generated non-extractable.",
    // No public line here: the private tile's job is the secret, and the
    // public half is one tile over. Copy fingerprint stays — it is a public
    // fact and works while masked (§35d). So does Add to My Keys, for the
    // opposite reason: it moves the secret into storage without showing it,
    // and this tile is masked by default.
    actions: ["copy", "download", "key.copyFingerprint", "keyring.add"],
  },
  {
    /**
     * A symmetric key — `genkey aes/256`, `genkey hmac/sha256`, an `hkdf` or
     * `unwrap` tip. Its own kind because it is its own *kind of thing*: not a
     * half, not one of a pair, and nothing about it is publishable.
     *
     * Until the shape fix this artifact was typed the private half of a
     * keypair, so it landed on `keypair-private` and captioned itself "private
     * half" — of a pair with no public one. `key.copyFingerprint` and
     * `key.copyPublicLine` are **not declared**, and that is §33d rather than
     * an oversight: both derive from public material, a symmetric key has
     * none, and a disabled button would teach that one exists. `keyring.add`
     * is omitted for the same reason `agent.save` refuses these outright —
     * there is no public half to list.
     */
    id: "secret-key",
    match: { role: "secret-key" },
    label: "Secret key",
    glyph: "key-secret",
    sensitivity: "secret",
    view: keyCardFor(false, "secret"),
    // Masked, the algorithm still shows — it is a public fact about the key,
    // which is the §34b rule the private-key tile already follows.
    publicView: keyCardFor(true, "secret"),
    empty: "No exportable key material — the key was generated non-extractable.",
    actions: ["copy", "download"],
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
    glyph: "key-secret",
    /**
     * **`sensitivity` is undeclared here, and the omission is the answer.**
     *
     * This kind by construction does not know which half it holds — the same
     * fact its `view` already acts on by passing no `half` and captioning
     * nothing. Declaring `"secret"` would tint every PEM export and every
     * auto-emitted pipeline tip as live key material; declaring `"public"`
     * would do the reverse on a body that is usually private. Either is the
     * least-specific kind pretending to be specific.
     *
     * So it defers, and `badgeTier` falls through to the artifact's own
     * `sensitive` flag — the engine's claim about *this* value, which is the
     * only claim anyone here is entitled to make.
     */
    // No half passed, and the omission is the §33d answer in the card's own
    // vocabulary: this kind by construction does not know which half it holds
    // — that is what makes it the least specific — so it says nothing rather
    // than captioning every lone key "keypair", which is what it used to do.
    view: keyCardFor(false),
    publicView: keyCardFor(true),
    empty: "No exportable key material — the key was generated non-extractable.",
    /**
     * Add to My Keys is declared here even though this kind cannot know
     * whether its body has a private half — that is what makes it the least
     * specific kind. "Is this meaningful for a key" is answered yes, by the
     * declaration; "does *this* body have something to store" is answered at
     * runtime, with a sentence, by `available()`. That is the §33d split
     * working, not a compromise around it. The two public key kinds omit it
     * outright, because a disabled button on a public tile would teach that
     * public keys belong in a vault.
     */
    actions: [
      "copy",
      "download",
      "key.copyFingerprint",
      "key.copyPublicLine",
      "keyring.add",
    ],
  },
  {
    /**
     * The one-line public form `ssh.encode` emits — `type base64 comment`.
     *
     * It had no kind at all until now, so it resolved as `text`: a tile whose
     * whole body was one unreadable base64 run, and a Download that wrote
     * `pub.txt` because a kind is the only thing allowed to correct an
     * extension. The card answers the question the line cannot — *which key is
     * this* — with the `SHA256:…` fingerprint `ssh-keygen -lf` prints.
     *
     * No `publicView`: a public line is never masked, so a body that renders
     * while masked would be a claim about a state this kind cannot reach.
     */
    id: "ssh-public",
    match: { role: "ssh-public" },
    label: "SSH public key",
    glyph: "key-public",
    sensitivity: "public",
    view: ({ artifact }) => <SshKeyCard content={artifact.content} />,
    empty:
      "This line did not parse as an SSH public key — showing it as text instead.",
    /**
     * *Copy public line* is not declared, and its absence is the §33d answer
     * rather than an oversight: this artifact **is** the public line, so Copy
     * already copies it. Two buttons for one motion is how they start
     * disagreeing about what "the line" means.
     */
    actions: ["copy", "download", "key.copyFingerprint"],
    /**
     * The extension every SSH tool expects, and the one the pipeline could not
     * have known: the line is `text` on the wire, so `out` named it `.txt`.
     * `ssh-copy-id`, `ssh-add` and every "paste your public key" field are
     * indifferent to the name, but the file beside `id_ed25519` has been
     * `id_ed25519.pub` since 1999, and a download called `pub.txt` is one
     * rename away from being the file you meant.
     */
    download: { ext: "pub" },
  },
  {
    /**
     * The openssh-key-v1 block — the private half, masked by default (§29f).
     *
     * `publicView` is the reason this kind exists at all. The key type, the
     * fingerprint and the comment all come off the *public* blob the container
     * carries, so they render while the secret stays masked — the same
     * correction §35d made for `keypair-private`, on the one tile where a
     * blank body is most expensive: a private key you cannot identify without
     * revealing it.
     *
     * A passphrase-protected block cannot be parsed at all (bcrypt-KDF, which
     * this build does not run), and that is not an error to raise at anyone —
     * the read-out returns null, the view draws nothing, and the sentence
     * below stands in.
     *
     * No `key.publish`, ever. Publishing a private key is not a thing, so by
     * §33d it is an omission and not a disabled button — there is nothing to
     * reason about at runtime and nothing to teach the wrong lesson.
     */
    id: "ssh-private",
    match: { role: "ssh-private" },
    label: "SSH private key",
    glyph: "key-secret",
    sensitivity: "secret",
    view: ({ artifact }) => <SshKeyCard content={artifact.content} />,
    publicView: ({ artifact }) => (
      <SshKeyCard content={artifact.content} withRaw={false} />
    ),
    empty:
      "This block is passphrase-protected or not an OpenSSH key, so there is nothing to read from it — the armor is below.",
    /**
     * Copy fingerprint stays enabled while masked, because a fingerprint is a
     * public fact (§34b). So does Add to My Keys, for the opposite reason: it
     * moves the secret into storage without ever displaying it, and
     * `keyring-service.js` already decodes an openssh-key-v1 block through
     * `ssh.decode` — the same route `agent.save` takes, so a key added by a
     * click lands under the id a recipe would have given it.
     */
    actions: ["copy", "download", "key.copyFingerprint", "keyring.add"],
    /**
     * `ssh-keygen` writes the private half with **no** extension at all
     * (`id_ed25519`, beside `id_ed25519.pub`), and the namer always produces
     * one — so this is the closest honest name rather than a copy of what the
     * tool does. `.txt` is the lie worth removing: it hands a private key to a
     * text editor by default. `.pem` was rejected as the worse lie — it claims
     * PKCS#8, which this block is not.
     */
    download: { ext: "key" },
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
    // Expand remains a tile-level affordance (the tile derives it from the
    // kind's `expandable`), so it is not declared here — a declared action
    // that duplicates a shipped button is worse than one not yet migrated.
    // Download is no longer in that sentence: it was never a shipped button,
    // only a comment saying it was, and it is a declared action now.
    actions: ["copy", "download"],
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
    // Expand remains a tile-level affordance (the tile derives it from the
    // kind's `expandable`), so it is not declared here — a declared action
    // that duplicates a shipped button is worse than one not yet migrated.
    // Download is no longer in that sentence: it was never a shipped button,
    // only a comment saying it was, and it is a declared action now.
    actions: ["copy", "download"],
    expandable: true,
  },
  {
    id: "jose-token",
    match: { role: "token" },
    label: "Token",
    glyph: "signature",
    view: JoseTokenCard,
    /**
     * **A JWS stays `sensitive`, and this is what it withholds instead.**
     *
     * The question was whether a signed token is a secret at all, and both
     * readings are defensible. A JWS is *signed, not encrypted*: its header
     * and payload are base64url, so nobody holding the token learns anything
     * from reading them that they did not already have. But a signed token is
     * almost always a **bearer credential**, and possessing one is using it —
     * which is the reading `jose-ops.js` took when it stamped `sensitive:
     * true`, and it is the right one. `sensitive` here means *displayability*
     * (that is the axis `keyring.add` stays enabled on while Copy and
     * Download do not), and a compact JWS on screen is a credential on screen.
     *
     * So the flag is correct and the **absence of a `publicView` was the
     * defect**: the best read-out in the codebase was behind a Reveal that
     * the list re-masks after fifteen seconds, on the only tile that ever
     * renders it. This is `ssh-private`'s shape exactly — that kind draws the
     * key type, fingerprint and comment while withholding the openssh block —
     * and the split lands in the same place. The header and the claims say
     * *which* token this is; the **signature** is what makes it usable, and
     * `JwtArtifact` has no path that renders it: `meta.jose` carries
     * `header`, `claims`, `payloadText` and `timing`, and the third segment
     * is not among them. The compact token stays behind the mask, where
     * Reveal is still what lets Copy and Download move it.
     *
     * Same function as `view` for that reason, like `KeypairCard` — there is
     * no raw toggle to withhold, so masked and unmasked must draw
     * identically, and making that structural means no future edit to the
     * reader can turn this into a leak.
     *
     * **A JWE is the other case and needs no exception.** It really is
     * encrypted, and it arrives here with `claims: null`, so the same reader
     * draws its `alg`/`enc` header — in the clear on the wire, it is the
     * AEAD's own AAD — and says the payload is encrypted. The decrypted
     * plaintext is a *different artifact*: `jose.decrypt` emits `text/json`
     * or `text/opaque`, which projects to `secret`, not `token`, so it lands
     * on the `secret` kind, which declares no `publicView` and draws nothing
     * while masked. The two are not being treated as one thing.
     */
    publicView: JoseTokenCard,
    empty: "No decoded token body — run jose.verify to read and check it.",
    // Expand remains a tile-level affordance (the tile derives it from the
    // kind's `expandable`), so it is not declared here — a declared action
    // that duplicates a shipped button is worse than one not yet migrated.
    // Download is no longer in that sentence: it was never a shipped button,
    // only a comment saying it was, and it is a declared action now.
    actions: ["copy", "download"],
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
  // Every entry declares `copy` and `download` and nothing else, for the same
  // reason the rest of the table does: `expand` is still a tile affordance and
  // `shares.print` is an unbuilt service, and a declared action that duplicates
  // a shipped button — or names a service that is not injected — is worse than
  // one not yet migrated. `download` left that list when it stopped being a
  // comment and became an action with a service behind it.
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
    actions: ["copy", "download"],
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
    /**
     * **The clause that prevents the accident, where it cannot be cut.**
     *
     * The engine's label already says it — "OpenPGP envelope — required for
     * recovery (not a share)" — and the row gives that label a `title`, so
     * the full sentence is reachable on hover. In a narrow panel the row
     * still cuts it at "OpenPGP envelope — required f…", and the half that
     * gets cut is the load-bearing half. Hover is not an answer for the one
     * artifact where being misread costs a ceremony: a witness who counts
     * this toward the threshold has destroyed it, and they will be reading a
     * printed sheet or a phone, neither of which has a pointer.
     *
     * Restructuring the identity row was the other candidate and is the wrong
     * size of fix — it would change every tile's measured anatomy to serve one
     * label. A caption in the card's own register costs one line on one kind,
     * and unlike the label it has the full row width and no `truncate`.
     *
     * Not a duplicated *fact* either: the label is the artifact's **name**,
     * this is the **instruction**, and after the role fix in `engine.js` this
     * kind claims only the master-key wrap — a `mode=passphrase` message is a
     * `ciphertext` and never reaches this sentence.
     */
    view: ({ artifact }) => (
      <>
        <p
          className="font-mono text-[10px] italic text-[var(--muted-foreground)]"
          data-envelope-note
        >
          not a share — required to recover the secret, and never counted toward
          the threshold
        </p>
        <PacketMapCard content={artifact.content} />
      </>
    ),
    empty:
      "This body is not OpenPGP-framed, so there are no packets to map — the armor is below.",
    actions: ["copy", "download"],
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
    actions: ["copy", "download"],
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
    actions: ["copy", "download"],
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
    actions: ["copy", "download"],
    /**
     * The one extension the pipeline could not have got right. An sshsig block
     * is `text` on the wire, so `out` names it `${stem}.txt`, and `ssh-keygen
     * -Y verify` wants a `.sig` beside the file it signed — a download called
     * `sig.txt` is one rename away from being usable, which is exactly the
     * friction this action exists to remove. The MIME stays the engine's:
     * `.sig` is a name, and the body really is armored ASCII.
     */
    download: { ext: "sig" },
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
    actions: ["copy", "download"],
    expandable: true,
  },
  {
    /**
     * A run receipt. The digest table, in the order `run.verify` walks it —
     * and no "verify this" button, because verifying means re-running the
     * recipe and comparing, which is an op with a receipt as its input. A
     * button here could only ever re-run *this* notebook.
     *
     * No `download` extension, deliberately. A receipt is JSON until
     * `gpg.sign` makes it a clearsigned block, and the ceremony's own recipe
     * signs it — both are still this kind, so a declared `.json` would be
     * wrong for the half that matters most. The engine's `.txt` is honest
     * about both, and this is the case that keeps `download` a correction
     * rather than a naming scheme.
     */
    id: "receipt",
    match: { role: "receipt" },
    label: "Receipt",
    view: ({ artifact }) => <ReceiptCard content={artifact.content} />,
    empty:
      "This is not a receipt this build can read — a v1 receipt predates the artifact-role change; run.verify explains it.",
    actions: ["copy", "download"],
    expandable: true,
  },
  {
    /**
     * An SVG QR rendering of another artifact — the one artifact whose raw
     * form is useless: nobody reads a QR by reading its path data.
     *
     * §37b drops Copy here ("copying SVG source is not a thing anyone wants"),
     * and this is the moment it named: Copy stayed only because dropping it
     * before Download existed would have left this tile with no affordance at
     * all, which is a worse tile than one with a slightly odd button. Download
     * exists, so Copy goes — the only kind in the table that does not declare
     * it, and the absence is the §33d answer rather than a disabled state.
     *
     * `shares.print` is still unbuilt, and the ceremony's own card printer is
     * where a share's QR gets printed anyway.
     */
    id: "qr",
    match: { role: "qr" },
    label: "QR",
    view: ({ artifact }) => (
      <QrArtifact content={artifact.content} label={artifact.label} />
    ),
    empty: "This body is not an SVG, so there is no code to draw — showing it as text.",
    actions: ["download"],
    /**
     * The engine already names these `.svg`, so this changes nothing today.
     * It is declared because this is now the one kind whose *only* affordance
     * is the download: an emit site that ever named a QR body something else
     * would break the one thing this tile can do, and a kind that states its
     * format cannot be broken that way.
     */
    download: { ext: "svg", mime: "image/svg+xml" },
  },
  {
    /**
     * The code `otp.code` produced — role `text`, claimed by a tag.
     *
     * **No new role, and the probe is why.** The SSH halves needed two words
     * because `role` is stamped from *sensitivity* at the text emit sites, so
     * one private block arrived as `secret` through `out @priv` and `text`
     * through a dangling tip, and `ArtifactMatch.role` is exact. A code is
     * never sensitive — that is `otp-ops.js`'s deliberate decision, since it
     * expires in one step and exists to be read — so both paths stamp `text`,
     * every time. Running the enrolment template and the bare tip through
     * `runRecipe` says so: `role: "text"`, `tags: ["otp-code"]`, both. There is
     * no second spelling to disown, so there is nothing for a role to fix, and
     * `ARTIFACT_ROLES` is frozen precisely so a word is added when the
     * vocabulary is short of one rather than when a tile wants a badge.
     *
     * The tag carries it instead, which is what `matchScore`'s specificity is
     * for: this entry scores 1 against a code and the `text` entry scores 0, so
     * the code gets the card and every other text artifact is untouched.
     *
     * No glyph declared. The badge string is the artifact's *role*, and this
     * kind shares `text` with the kind below it — a glyph named here could only
     * ever render as `text`'s, so declaring one would be a decoration that
     * looks like a decision. `network-value` omits it for the same class of
     * reason.
     *
     * No `publicView`. A code is never masked, so a body that renders while
     * masked would be a claim about a state this kind cannot reach — the
     * `ssh-public` argument, and the counterpart to `ssh-private`, which needs
     * one badly. If an OTP tile ever wants a masked read-out it will be the
     * `otpauth://` URI's, not this one's.
     *
     * Actions: Copy and Download, and nothing else. There is no "publish an
     * OTP code", and *refresh* is the action §37a exists to refuse — a
     * recomputed code would be a value with no step behind it, no place in the
     * recipe and nothing the receipt could describe. The card answers the
     * question that button was for as a *view*: the countdown keeps ticking
     * honestly toward zero and then says so.
     *
     * One kind, three shapes, and that is the point rather than a compromise —
     * a live TOTP code counts down, a HOTP code shows its counter, and a code
     * pinned with `at=` states its instant and does not tick. Same badge, same
     * actions, same digits at the same weight; the value varies, the type does
     * not. `traits.otpMode` and `traits.otpPinnedAt` are what tell them apart,
     * which is why both had to be on the artifact rather than inferred by the
     * widget from a body that is six characters long.
     */
    id: "otp-code",
    match: { role: "text", tags: ["otp-code"] },
    label: "One-time code",
    /**
     * The badge said **TEXT**, which is true and useless.
     *
     * `match` can only be `role: "text"` — the engine's role ternary turns on
     * whether a value is secret, and a code that exists to be typed into a
     * prompt never is — so the tag is what claims this kind, and the role is
     * what the chip was rendering. That is the whole defect, and it is why the
     * name is declared here rather than by inventing an `otp` role: the role
     * is correct, it is just not a name.
     *
     * TOTP or HOTP rather than the static `label`, because the artifact is
     * genuinely one or the other and `traits.otpMode` says which — the same
     * trait `OtpCodeCard` reads to draw "counter N" for the HOTP shape. Four
     * characters, so it costs the row nothing: measured at 49px against
     * TEXT's 48px, where `One-time code` would have been 100px and truncates
     * a real filename in a 320px panel.
     */
    badge: (artifact) =>
      (artifact?.traits as { otpMode?: string } | undefined)?.otpMode === "hotp"
        ? "HOTP"
        : "TOTP",
    /**
     * `otp`, not the `text` its role would have found. The glyph channel had
     * the same conflation as the name: this kind drew AlignLeft — lines of
     * prose — for a six-digit code with a countdown.
     */
    glyph: "otp",
    view: ({ artifact }) =>
      hasOtpReadout(artifact.content, artifact.traits as Record<string, unknown>) ? (
        <OtpCodeCard
          content={artifact.content}
          traits={artifact.traits as Record<string, unknown> | undefined}
        />
      ) : null,
    empty:
      "The digits are the whole value, and this run did not record which token or which step they belong to — the code is below.",
    actions: ["copy", "download"],
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
    actions: ["copy", "download"],
  },
  {
    id: "secret",
    match: { role: "secret" },
    label: "Secret",
    glyph: "secret",
    sensitivity: "secret",
    view: () => null,
    // No `publicView`. A scalar or a master secret has no public half to
    // draw — unlike a keypair, where the algorithm and fingerprint are facts
    // about the public side. Inventing a line here would mean deriving it
    // from the masked material, which is the one thing §34b forbids.
    empty:
      "This secret has no body to show — reveal it, if the recipe asked for it, to see the value.",
    actions: ["copy", "download"],
  },
];
