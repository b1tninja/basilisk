import { PresetMenu } from "basilisk-portal";

/*
 * Templates — the way a notebook starts as something other than a blank page.
 *
 * A preset is a recipe, not a wizard: loading one fills the notebook with text
 * a person can read and edit before running anything. That is why `recipe` is
 * shown rather than hidden behind the title, and why the menu offers Load and
 * Append as separate verbs — appending a ceremony onto an existing notebook is
 * how the second half of a two-party flow gets added.
 *
 * `pair` is the shared-notebook case. Some ceremonies only make sense as two
 * halves held by different people — one deals, the other accepts — and Add
 * both puts the matching pair in together so neither side is left constructing
 * its counterpart by hand.
 *
 * Every cell renders `open`; a closed menu photographs as a button.
 */

const frame = { padding: "0 0 260px" };

const PRESETS = [
  {
    id: "split-secret",
    group: "Recovery",
    title: "Split a secret into shares",
    blurb: "Shamir split with a printable card per share.",
    recipe: "secret $root\n\nsss.split n=5 threshold=3 | out $shares\n\n$shares | sharecard | out $cards",
  },
  {
    id: "restore-secret",
    group: "Recovery",
    title: "Restore from shares",
    blurb: "Combine enough shares to reconstruct the secret.",
    recipe: "sss.combine | out $root",
  },
  {
    id: "rotate-signing-key",
    group: "Recovery",
    title: "Rotate a signing key",
    blurb: "New key, cross-signed by the old one, with a revocation for the old.",
    recipe: "gpg.genkey name=… email=… | out $new\n\ngpg.revoke key=$old reason=superseded | out $rev",
  },
  // A pair is two presets sharing one `pair` id — the forward half and its
  // inverse. One preset carrying a `pair` nothing else shares pairs with
  // nothing, and the companion control never appears.
  {
    id: "witness-sign-signer",
    group: "Shared notebook",
    title: "Witnessed signature — signer",
    blurb: "You sign, and hand the signature to a witness.",
    recipe: "@me\nagent.sign key=$id mode=detached | out $sig\n\n$sig | publish",
    pair: "witness-sign",
  },
  {
    id: "witness-sign-witness",
    group: "Shared notebook",
    title: "Witnessed signature — witness",
    blurb: "You attest to a signature you watched being made.",
    recipe: "@witness\n$sig | attest | out $attestation\n\n$attestation | publish",
    pair: "witness-sign",
  },
  {
    id: "two-party-decrypt",
    group: "Shared notebook",
    title: "Two-party decrypt",
    blurb: "Each side decrypts with their own key; neither key moves.",
    recipe: "@alice\nagent.decrypt key=$a | out $half\n\n@bob\nagent.decrypt key=$b | out $other",
  },
];

/**
 * The menu as a person meets it, grouped. Recovery playbooks and shared-
 * notebook ceremonies are different kinds of thing — one you run alone under
 * pressure, the other needs someone else present — and mixing them into one
 * list would put a template that cannot run without a peer next to one that
 * exists precisely for when nobody else is reachable.
 */
export const Default = () => (
  <div style={frame}>
    <PresetMenu
      open
      presets={PRESETS}
      groups={["Recovery", "Shared notebook"]}
      onLoad={() => {}}
      onAppend={() => {}}
      onAddBoth={() => {}}
      onOpenChange={() => {}}
    />
  </div>
);

/**
 * A single group, and a custom trigger label. Useful when the menu is scoped
 * to one context — a disaster-recovery playbook drawer has no reason to offer
 * a ceremony that needs a live peer.
 */
export const RecoveryOnly = () => (
  <div style={frame}>
    <PresetMenu
      open
      label="Playbooks"
      presets={PRESETS.filter((p) => p.group === "Recovery")}
      groups={["Recovery"]}
      onLoad={() => {}}
      onAppend={() => {}}
      onAddBoth={() => {}}
      onOpenChange={() => {}}
    />
  </div>
);

/**
 * The shared-notebook ceremonies, which the grouped cell above cannot show:
 * the menu opens on the first category, so `Recovery` is what a reader sees
 * there and these stay one click away and invisible to a screenshot.
 *
 * This is the half that matters for a multi-party session. The two witnessed-
 * signature rows share one `pair` id, so the companion control (⇄) offers to
 * add both halves at once — the ceremony needs the signer's cell *and* the
 * witness's, and leaving someone to hand-write the counterpart is how the two
 * drift apart. Two-party decrypt carries no `pair`, so it shows the ordinary
 * row beside them.
 */
export const SharedNotebookCeremonies = () => (
  <div style={frame}>
    <PresetMenu
      open
      label="Ceremonies"
      presets={PRESETS.filter((p) => p.group === "Shared notebook")}
      groups={["Shared notebook"]}
      onLoad={() => {}}
      onAppend={() => {}}
      onAddBoth={() => {}}
      onOpenChange={() => {}}
    />
  </div>
);
