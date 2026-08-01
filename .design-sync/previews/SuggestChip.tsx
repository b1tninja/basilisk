import { SuggestChip } from "basilisk-portal";

/**
 * A step in a recipe pipeline. The chip is the unit the whole notebook is
 * built from — every op the user places renders as one.
 */
export const Placed = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
    <SuggestChip label="genkey" variant="placed" />
    <SuggestChip label="ssh.encode" variant="placed" hint="text" />
    <SuggestChip label="out @pub" variant="placed" />
  </div>
);

/**
 * The variant axis: `placed` is a step already in the recipe, `ghost` is a
 * suggestion not yet taken, `selector` is a branch label on a tee.
 */
export const Variants = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
    <SuggestChip label="gpg.sign" variant="placed" />
    <SuggestChip label="gpg.verify" variant="ghost" />
    <SuggestChip label=":public" variant="selector" />
  </div>
);

export const Selected = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
    <SuggestChip label="agent.sign" variant="placed" selected />
    <SuggestChip label="agent.decrypt" variant="placed" />
  </div>
);

/**
 * Error, and the key-exposure trace. `keyExposed` draws a thin warn
 * underline on any step handling a private key that was exported into the
 * pipeline — it follows the key rather than marking one op, so it lands on
 * `agent.unlock` and on everything downstream still holding it.
 */
export const ErrorAndExposure = () => (
  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
    <SuggestChip label="aes-gcm" variant="placed" error />
    <SuggestChip label="agent.unlock" variant="placed" keyExposed />
    <SuggestChip label="gpg.sign key=@me" variant="placed" keyExposed />
  </div>
);

/**
 * Removable — the × is a separate hit target, so clicking the chip body
 * still selects the step rather than deleting it.
 */
export const Removable = () => (
  <SuggestChip label="blip39" variant="placed" onRemove={() => {}} />
);
