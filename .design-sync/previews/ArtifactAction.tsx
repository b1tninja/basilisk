import { ArtifactAction } from "basilisk-portal";

const noop = () => {};

/**
 * The three tiers, which are the whole point of this control. They encode
 * what happens if you click: inert is local and reversible, local changes
 * durable state on this device, outward leaves the machine and may be
 * irreversible. Flattening them into equal buttons is how a mis-click
 * becomes unrecoverable.
 */
export const Tiers = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
    <ArtifactAction label="Copy" tier="inert" onClick={noop} />
    <ArtifactAction label="Download" tier="inert" onClick={noop} />
    <ArtifactAction label="Add to keyring" tier="local" onClick={noop} />
    <ArtifactAction label="Publish" tier="outward" onClick={noop} />
  </div>
);

/**
 * A realistic row: several inert actions, one local, one outward. The amber
 * appears exactly once, so this reads quiet → solid → outlined rather than
 * as a toolbar.
 */
export const InAnActionRow = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
    <ArtifactAction label="Expand" tier="inert" onClick={noop} />
    <ArtifactAction label="Copy" tier="inert" onClick={noop} />
    <ArtifactAction label="Download" tier="inert" onClick={noop} />
    <ArtifactAction label="Copy public line" tier="inert" onClick={noop} />
    <ArtifactAction label="Add to keyring" tier="local" onClick={noop} />
    <ArtifactAction label="Publish" tier="outward" onClick={noop} />
  </div>
);

/**
 * Disabled always carries a reason, and the reason stays readable — the
 * label holds full-strength muted text and the *affordance* is removed
 * instead. A dotted underline marks that an explanation is attached.
 * A disabled local or outward action drops to inert weight deliberately:
 * a Publish that cannot publish should not wear the colour promising
 * "this leaves the machine".
 */
export const DisabledWithReason = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
    <ArtifactAction
      label="Copy"
      tier="inert"
      onClick={noop}
      reason="Reveal this value first — a masked value cannot leave the notebook."
    />
    <ArtifactAction
      label="Add to keyring"
      tier="local"
      onClick={noop}
      reason="My Keys is unavailable in this browser (no IndexedDB)."
    />
    <ArtifactAction
      label="Publish"
      tier="outward"
      onClick={noop}
      reason="Publishing needs a connection to this site's directory."
    />
  </div>
);

/**
 * In flight. The control is `aria-busy`, never `disabled` — a disabled
 * control loses its accessible name in some screen-reader pairings at
 * exactly the moment the user most wants to know what is happening.
 */
export const Busy = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
    <ArtifactAction
      label="Add to keyring"
      busyLabel="Adding…"
      busy
      tier="local"
      onClick={noop}
    />
    <ArtifactAction label="Publishing…" busyLabel="Publishing…" busy tier="outward" onClick={noop} />
  </div>
);
