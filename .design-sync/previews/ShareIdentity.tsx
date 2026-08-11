import { ShareIdentity } from "basilisk-portal";

/*
 * The one-line answer to "which share is this?", drawn beside a share artifact
 * rather than replacing it — and drawable while the share itself stays masked.
 *
 * That is the point. Which share this is, and how many are needed, are facts
 * about the *split*: they are printed on the card and said aloud in the room,
 * and neither derives from the masked material. Before this, a masked share
 * tile said "sensitive — value not shown" and nothing else, so the one
 * question a custodian actually has could only be answered by revealing the
 * secret.
 *
 * Deliberately tiny: the artifact tile already renders the share's own words
 * with its format bar, its Hide button and its auto-hide timer, so this states
 * only the identity and leaves the body alone.
 *
 * `traits.shareOf` is the share **number**, despite a name that reads like "of
 * N" — the engine sets it from `shareIndex`, and `shareOf` wins over
 * `shareIndex` when both are present. Putting a total there renumbers the
 * share, which is the one thing this line must never get wrong.
 */

const wrap = { display: "grid", gap: 10, maxWidth: 440 };
const label = {
  fontSize: 10.5,
  fontWeight: 700,
  textTransform: "uppercase" as const,
  letterSpacing: "0.06em",
  color: "var(--muted-foreground)",
  margin: "0 0 4px",
};
const dashed = {
  border: "1px dashed color-mix(in srgb, var(--border) 90%, transparent)",
  borderRadius: 4,
  padding: "6px 8px",
  minHeight: 18,
};

/**
 * The complete statement, on a real BLIP39 share: which share, how many
 * recover the secret, and what kind of thing the holder is looking at.
 */
export const Default = () => (
  <ShareIdentity
    artifact={{ tags: ["mnemonic", "blip39"], traits: { shareOf: 2, threshold: 3 } }}
  />
);

/**
 * What it says as facts drop away.
 *
 * With no `threshold` it states the position and stops — no invented quorum.
 * With neither, there is nothing to say and it renders nothing at all, which
 * is why the last row is deliberately empty rather than showing a placeholder.
 * These artifacts come from recipes of varying completeness, so each line has
 * to be true of the artifact beside it rather than of the best case.
 */
export const PartialFacts = () => (
  <div style={wrap}>
    <div>
      <p style={label}>share number · threshold</p>
      <div style={dashed}>
        <ShareIdentity artifact={{ traits: { shareOf: 2, threshold: 3 } }} />
      </div>
    </div>
    <div>
      <p style={label}>share number only — threshold not recorded</p>
      <div style={dashed}>
        <ShareIdentity artifact={{ traits: { shareOf: 2 } }} />
      </div>
    </div>
    <div>
      <p style={label}>from shareIndex, no traits</p>
      <div style={dashed}>
        <ShareIdentity artifact={{ shareIndex: 4 }} />
      </div>
    </div>
    <div>
      <p style={label}>nothing to state — renders nothing</p>
      <div style={dashed}>
        <ShareIdentity artifact={{}} />
      </div>
    </div>
  </div>
);

/**
 * The three flavours, which come from `tags` and change what a custodian is
 * being told to look for.
 *
 * `encrypted` is checked before `blip39` on purpose: a GPG-encrypted share
 * carries both tags, because it is armor *around* a mnemonic. Calling it a
 * mnemonic would tell someone to read words off a tile that holds none.
 */
export const Flavours = () => (
  <div style={wrap}>
    {(
      [
        ["BLIP39 mnemonic", ["mnemonic", "blip39"]],
        ["encrypted — armor around a mnemonic", ["blip39", "encrypted"]],
        ["raw share", ["raw"]],
      ] as const
    ).map(([caption, tags]) => (
      <div key={caption}>
        <p style={label}>{caption}</p>
        <div style={dashed}>
          <ShareIdentity artifact={{ tags: [...tags], traits: { shareOf: 2, threshold: 3 } }} />
        </div>
      </div>
    ))}
  </div>
);
