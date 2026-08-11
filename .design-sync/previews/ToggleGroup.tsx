import { ToggleGroup, ToggleGroupItem } from "basilisk-portal";

/*
 * The segmented control for exclusive choices that are always visible — the
 * notebook's view mode, an artifact's encoding, which half of a key you are
 * looking at.
 *
 * `type` is required by the underlying primitive and decides everything:
 * `single` is a radio group, `multiple` is a set of checkboxes that happen to
 * be adjacent. They look nearly identical and mean different things, so both
 * are shown here rather than left for a reader to guess.
 *
 * Each cell is `value`-controlled with no `onValueChange`, which pins the
 * selection for the shot. In use these are controlled by the caller.
 */

const wrap = { display: "grid", gap: 14 };
const label = {
  fontSize: 10.5,
  fontWeight: 700,
  textTransform: "uppercase" as const,
  letterSpacing: "0.06em",
  color: "var(--muted-foreground)",
  margin: "0 0 6px",
};

/**
 * Exclusive choice — how an artifact's bytes are shown. One encoding is in
 * effect at a time, so anything other than `single` would be wrong here.
 */
export const Default = () => (
  <ToggleGroup type="single" value="hex">
    <ToggleGroupItem value="hex">hex</ToggleGroupItem>
    <ToggleGroupItem value="base64">base64</ToggleGroupItem>
    <ToggleGroupItem value="utf8">utf-8</ToggleGroupItem>
  </ToggleGroup>
);

/**
 * Both types side by side. The filter row is genuinely multi-select — a reader
 * narrowing a roster wants "verified *and* relayed", not one or the other —
 * and it is the case where reaching for `single` out of habit produces a
 * control that silently drops the user's previous choice.
 */
export const SingleAndMultiple = () => (
  <div style={wrap}>
    <div>
      <p style={label}>type=&quot;single&quot; — one at a time</p>
      <ToggleGroup type="single" value="mesh">
        <ToggleGroupItem value="mesh">Mesh</ToggleGroupItem>
        <ToggleGroupItem value="direct">Direct</ToggleGroupItem>
      </ToggleGroup>
    </div>
    <div>
      <p style={label}>type=&quot;multiple&quot; — a set</p>
      <ToggleGroup type="multiple" value={["verified", "relayed"]}>
        <ToggleGroupItem value="verified">Verified</ToggleGroupItem>
        <ToggleGroupItem value="relayed">Relayed</ToggleGroupItem>
        <ToggleGroupItem value="failed">Failed</ToggleGroupItem>
      </ToggleGroup>
    </div>
  </div>
);

/**
 * Nothing selected. Worth photographing because it is a reachable state — the
 * primitive returns `""` when a `single` group is deselected — and a design
 * that assumes something is always active will render an empty-looking control
 * it never accounted for.
 */
export const NoneSelected = () => (
  <ToggleGroup type="single" value="">
    <ToggleGroupItem value="hex">hex</ToggleGroupItem>
    <ToggleGroupItem value="base64">base64</ToggleGroupItem>
    <ToggleGroupItem value="utf8">utf-8</ToggleGroupItem>
  </ToggleGroup>
);
