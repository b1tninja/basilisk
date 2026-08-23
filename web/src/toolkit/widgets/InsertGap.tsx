import type { DragEvent } from "react";
import { cn } from "@/lib/cn";

type Props = {
  label?: string;
  /** Dragging an op tile over this gap right now. */
  active?: boolean;
  /** This is the notebook's pendingInsert position — renders the HERE caret. */
  pending?: boolean;
  /** 'nested' = 14px hit target inside a compound-op chip (§20f). */
  scale?: "default" | "nested";
  /**
   * Render the label text beside the +, not only as title/aria. Used where a
   * bare + would be ambiguous about which scope it inserts into — a nested
   * branch/body gap names its scope ("+ step in :public") so it can never be
   * confused with the continue-main-chain gap (design turn 46).
   */
  showLabel?: boolean;
  onClick?: () => void;
  onDragOver?: (e: DragEvent) => void;
  onDragLeave?: (e: DragEvent) => void;
  onDrop?: (e: DragEvent) => void;
  className?: string;
  /** data-* passthrough for legacy hosts */
  "data-gap-stem"?: number;
  "data-gap-branch"?: number;
  "data-gap-body"?: number;
  "data-cell"?: number;
};

/** Insert-at-index caret — click to focus insert, drop target for reorder/ops (§19d). */
export function InsertGap({
  label = "Insert step here",
  active = false,
  pending = false,
  scale = "default",
  showLabel = false,
  onClick,
  onDragOver,
  onDragLeave,
  onDrop,
  className,
  ...data
}: Props) {
  const shared = {
    "data-gap-insert": "1",
    "data-cell": data["data-cell"],
    "data-gap-stem": data["data-gap-stem"],
    "data-gap-branch": data["data-gap-branch"],
    "data-gap-body": data["data-gap-body"],
    onClick,
    onDragOver,
    onDragLeave,
    onDrop,
  } as const;

  const caret = (
    <>
      <span className="cell-recipe-gap-caret-bar" aria-hidden />
      <span className="cell-recipe-gap-caret-label" aria-hidden>
        HERE
      </span>
    </>
  );

  if (pending && !(active && onClick)) {
    /**
     * **The HERE caret is a control exactly when a press has somewhere to go.**
     *
     * It used to be a `<button>` either way, and one of the five call sites
     * passes no `onClick` at all — the armed-branch caret in `RecipeChipFlow`,
     * which is aimed by clicking the ghost chip that armed the branch and
     * cancelled by the × on the selector chip beside it. So that one took a tab
     * stop, announced itself as a button, and answered Enter with nothing.
     *
     * The rule is keyed on the handler rather than on the site because that is
     * the fact it is actually about: a marker is not a control, and "nothing is
     * wired" is how this component learns which it is.
     *
     * **The other four keep the button, and that is not a concession.** They
     * spread `bindGap`/`stemGap`, whose `onClick` calls `onGap(path)` — which in
     * the shell focuses the cell the caret is in, clears any open chip editor and
     * re-aims `pendingInsert`. Pressing an *already* pending gap is therefore not
     * a no-op: `focusedCell` moves independently (clicking another cell's header
     * sets it and leaves `pendingInsert` where it was), and the shelf's caret
     * banner reads `describeCaretPosition(pendingInsert, focusedCell, …)` — one
     * sentence built from both — so while they disagree the banner names a
     * position that is not where the caret is drawn, and this press is what
     * repairs it.
     *
     * There is a second reason not to make the wired four inert, and it is the
     * one that would have been the regression. Both branches here render the
     * same element type, so when a keyboard user presses a `+` gap React updates
     * that DOM node in place and focus survives into the pending state. Swapping
     * to a `<span>` would unmount the focused button and mount a span, dropping
     * focus to the body — activating a control would throw away the caller's
     * place in the page.
     *
     * The span keeps everything the button carried except the two things that
     * were the defect: it is still the drop target (`onDragOver`/`onDrop` bind to
     * any element — HTML5 drag and drop is pointer-only and never wanted the
     * button), still carries `data-gap-insert` and the `data-cell`/`data-gap-*`
     * attributes hosts and stylesheets select on, still draws through
     * `.cell-recipe-gap-caret`, and is still *named*: `role="note"` is what lets
     * `aria-label` apply to a non-interactive element, so a screen reader still
     * reaches "insert position" and is no longer promised a press.
     *
     * **What `active` outranking `pending` is actually for, and where it
     * stops.** A drag hovering a gap returns the `+` wearing
     * `.cell-recipe-gap-drop-active` — bigger, blue, bordered — which is the
     * only thing on screen that says the gap will take the drop. That takeover
     * is worth a shape change *because the `+` it hands back is pressable*. On
     * an unwired gap it is not: `active && !onClick` used to fall past this
     * branch and hand back the dead button in a different shape, so the armed
     * caret was left with no drop accent at all rather than that.
     *
     * So the condition is `pending && !(active && onClick)` — the `+` takeover
     * is scoped to gaps where a `+` would be a control, and the marker keeps
     * its own shape and takes the accent as a class instead
     * (`.cell-recipe-gap-caret-drop-active`, same blue and same 1.15 scale, so
     * the two states read as one). The element type does not change under a
     * drag hover in either branch now, which is the same property the wired
     * four rely on for focus, held for a reason that has nothing to do with
     * focus: a `<span>` that unmounts mid-drag would cancel the drop.
     */
    if (!onClick) {
      return (
        <span
          className={cn(
            "cell-recipe-gap-caret",
            active && "cell-recipe-gap-caret-drop-active",
            className
          )}
          role="note"
          aria-label={`${label} — insert position`}
          title={label}
          {...shared}
        >
          {caret}
        </span>
      );
    }
    return (
      <button
        type="button"
        className={cn("cell-recipe-gap-caret", className)}
        aria-label={`${label} — insert position`}
        title={label}
        {...shared}
      >
        {caret}
      </button>
    );
  }

  return (
    <button
      type="button"
      className={cn(
        "cell-recipe-gap-add",
        scale === "nested" && "cell-recipe-gap-nested",
        showLabel && "cell-recipe-gap-labeled",
        active && "cell-recipe-gap-drop-active",
        className
      )}
      aria-label={label}
      title={label}
      {...shared}
    >
      <span aria-hidden>+</span>
      {showLabel ? (
        <span className="cell-recipe-gap-label" aria-hidden>
          {label}
        </span>
      ) : null}
    </button>
  );
}
