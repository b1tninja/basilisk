import { Button } from "basilisk-portal";

/**
 * The canonical use: a labelled action.
 */
export const Default = () => <Button>Run recipe</Button>;

/**
 * The variant axis — what most changes a button's meaning in this app.
 * `secondary` is the workhorse inside toolkit panels; `ghost` is for actions
 * that should not compete with the value they sit beside; `destructive` is
 * reserved for things that lose data.
 */
export const Variants = () => (
  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
    <Button>Run</Button>
    <Button variant="secondary">Copy</Button>
    <Button variant="outline">Expand</Button>
    <Button variant="ghost">Deny</Button>
    <Button variant="destructive">Lock all</Button>
  </div>
);

/**
 * Sizes as the toolkit uses them — `sm` is the panel default, because a
 * 22px control row is the densest surface in the product.
 */
export const Sizes = () => (
  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
    <Button size="sm" variant="secondary">Small</Button>
    <Button variant="secondary">Default</Button>
    <Button size="lg" variant="secondary">Large</Button>
  </div>
);

/**
 * There is no `disabled` prop, and that is the system's strongest opinion
 * about controls: a boolean cannot say *why*, so a button that declines
 * carries the sentence instead. `disabledReason` is what makes it inert — the
 * refusal and its explanation are one value and cannot drift apart.
 *
 * The button keeps its place in the tab order (`aria-disabled`, never the
 * `disabled` attribute) and renders the sentence beneath itself, pointed at by
 * `aria-describedby`. Write the state the reader is in, not "Unavailable".
 */
export const Refused = () => (
  <div style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
    <Button disabledReason="No recipe is loaded — place a step first.">Run recipe</Button>
    <Button variant="secondary" disabledReason="This step has produced no output yet.">
      Copy
    </Button>
  </div>
);

/**
 * Busy is not a refusal. An in-flight control has declined nothing and owes no
 * explanation — it says what is happening in its own label — so it gets
 * `aria-busy` and the same re-entry guard, never `aria-disabled`.
 */
export const Busy = () => (
  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
    <Button busy>Checking…</Button>
  </div>
);
