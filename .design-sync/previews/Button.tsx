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

export const Disabled = () => (
  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
    <Button disabled>Run recipe</Button>
    <Button variant="secondary" disabled>Copy</Button>
  </div>
);
