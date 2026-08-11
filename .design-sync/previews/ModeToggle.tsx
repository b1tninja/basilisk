import { ModeToggle } from "basilisk-portal";

/*
 * The notebook's own segmented control — `ToggleGroup` with the labelling and
 * the always-one-selected guarantee the app relies on.
 *
 * It exists rather than callers reaching for `ToggleGroup` directly because
 * these choices are never empty: a notebook is always in some view, so the
 * deselected state the raw primitive allows would be meaningless here. Reach
 * for `ToggleGroup` when nothing-selected is a real answer, and this when it
 * is not.
 *
 * `title` is the hover explanation for a label too short to explain itself,
 * which is most of them — these controls sit in a toolbar where a word is all
 * the room there is.
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
 * How the notebook is being viewed. Recipe is the text a run is reproducible
 * from; Cells is the same notebook as editable blocks.
 */
export const Default = () => (
  <ModeToggle
    value="cells"
    ariaLabel="Notebook view"
    options={[
      { value: "cells", label: "Cells", title: "Editable blocks" },
      { value: "recipe", label: "Recipe", title: "The notebook as reproducible text" },
    ]}
    onChange={() => {}}
  />
);

/**
 * The session-scoped choices this control is used for, each with the selection
 * that matters shown active.
 *
 * "Who runs it" is the shared-notebook one: a cell runs where its private
 * input lives, and switching to a named peer is the deliberate override. The
 * default reads as a policy rather than a peer, which is what keeps placement
 * inferred unless someone says otherwise.
 */
export const SessionChoices = () => (
  <div style={wrap}>
    <div>
      <p style={label}>Who runs it</p>
      <ModeToggle
        value="infer"
        ariaLabel="Placement"
        options={[
          { value: "infer", label: "Where the input is", title: "Derived from which peer holds the private input" },
          { value: "named", label: "A named peer", title: "Override — assign this cell explicitly" },
        ]}
        onChange={() => {}}
      />
    </div>
    <div>
      <p style={label}>Transport</p>
      <ModeToggle
        value="direct"
        ariaLabel="Transport"
        options={[
          { value: "direct", label: "Direct", title: "Peer to peer only" },
          { value: "relay", label: "Allow relay", title: "Fall back to a TURN relay if no direct path exists" },
        ]}
        onChange={() => {}}
      />
    </div>
    <div>
      <p style={label}>Three options</p>
      <ModeToggle
        value="detached"
        ariaLabel="Signature mode"
        options={[
          { value: "cleartext", label: "Cleartext" },
          { value: "detached", label: "Detached" },
          { value: "inline", label: "Inline" },
        ]}
        onChange={() => {}}
      />
    </div>
  </div>
);
