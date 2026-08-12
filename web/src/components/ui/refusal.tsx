import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * A control that refuses says why, on screen, in a sentence a screen reader
 * reads out.
 *
 * Four bug reports in one week reduced to one shape: a control that declines to
 * do something without saying so. "Nothing happens when I click Start shared
 * session" was a `disabled` attribute with no reason attached; a paste that
 * matched nothing and a key chooser that was empty were the same defect at
 * other controls. A sweep found 37 disabled controls in the toolkit and 4 that
 * sat near any explanation at all.
 *
 * The fix is not 33 careful edits, because the next control will be the 34th.
 * It is that **the refusal and the reason are the same value**. There is no
 * boolean here: a refusal is a string, its presence is what makes the control
 * inert, and a caller with no sentence to write has no way to spell the state.
 * `ArtifactAction` proved the shape on one widget — "`disabled` without
 * `reason` is a type error rather than a convention" — and this is that rule
 * extracted so every control in the app inherits it.
 *
 * Three properties the old `disabled` attribute could not give:
 *
 * 1. **The reason reaches assistive technology.** `aria-describedby` points at
 *    the sentence. A `title` cannot do this: it is unreachable by touch and by
 *    keyboard, and several screen readers never announce it.
 * 2. **The refused control stays focusable.** `aria-disabled`, never the
 *    `disabled` attribute — which removes the button from the tab order and so
 *    puts its description out of reach of exactly the users the description was
 *    written for. Because the button stays clickable, `guard` has to make the
 *    refusal real: an omitted `onClick` is not a refusal, the click still
 *    happens and still bubbles to whatever is listening above it.
 * 3. **The sentence is on screen.** The reports were from someone looking
 *    straight at the control. `note` is ordinary rendered text, and the sweep in
 *    `disabled-needs-reason.test.js` refuses `sr-only` on anything carrying
 *    `data-disabled-reason` so it cannot quietly become invisible later.
 *
 * **Busy is not refused.** An in-flight control has not declined anything and
 * owes no explanation — it is already saying what is happening, usually in its
 * own label ("Checking…"). It gets `aria-busy` and the same re-entry guard, and
 * never `aria-disabled`: a disabled control loses its accessible name in some
 * screen-reader pairings at exactly the moment its user most wants it.
 */

/**
 * Where the sentence is already on screen, `reasonId` points at it instead of
 * emitting a second copy.
 *
 * Not an escape hatch from stating a reason — the reason is still required, and
 * still becomes the accessible description. It is an escape hatch from stating
 * it *twice*: `SessionStart` already lists `startIssues` above its button, and
 * two buttons plus one visible sentence would be three announcements of one
 * refusal. The target element has to carry `data-disabled-reason`, which is
 * what the visibility sweep looks for.
 */
export type RefusalOptions = {
  /** This control's own action is in flight. `aria-busy`, never a refusal. */
  busy?: boolean;
  /** Id of an element already stating this reason visibly. */
  reasonId?: string;
};

export type Refusal = {
  /** The control declined. False while merely busy. */
  refused: boolean;
  /** Refused *or* busy — either way the click must not run the action. */
  inert: boolean;
  /** Spread onto the control element. */
  aria: {
    "aria-disabled"?: true;
    "aria-busy"?: true;
    "aria-describedby"?: string;
  };
  /** Wrap a handler so a refused or busy control cannot run it. */
  guard: <E extends React.SyntheticEvent>(
    handler?: (event: E) => void
  ) => (event: E) => void;
  /**
   * The sentence, as an element, or null when there is nothing to render —
   * either the control is live, or `reasonId` says it is already on screen.
   * Render it immediately after the control.
   */
  note: React.ReactNode;
};

/**
 * Text that reads as a refusal without being one.
 *
 * "Unavailable" restates `aria-disabled`; it makes an audit pass while leaving
 * the reader exactly where they were. Refused wholesale rather than warned
 * about, because a placeholder is how the 33 dead controls would come back with
 * a clean test run behind them.
 */
export const CONTENTLESS_REASONS = Object.freeze([
  "unavailable",
  "not available",
  "disabled",
  "n/a",
  "no",
  "nope",
  "cannot",
  "can't",
  "not allowed",
  "not possible",
  "not ready",
  "error",
  "invalid",
  "blocked",
  "—",
  "-",
]);

/** Shared look for the sentence: full-strength muted text, never dimmed. */
export const REASON_CLASS =
  "max-w-[40ch] text-[length:10.5px] leading-snug text-[var(--muted-foreground)]";

/**
 * @param reason Why this control declines, or undefined while it does not.
 */
export function useRefusal(reason?: string, options?: RefusalOptions): Refusal {
  const busy = !!options?.busy;
  const borrowedId = options?.reasonId;
  /**
   * `useId`, because the id was once derived from the control's label and a
   * list of nine tiles emitted `…-why-download` nine times — every
   * `aria-describedby` on the page then resolved to the first one, so 9 of 10
   * refusals announced a sentence about a different artifact. Unique per mount
   * by construction rather than by every call site remembering a key.
   */
  const uid = React.useId();
  const refused = !!reason;
  const ownId = refused && !borrowedId ? `why-${uid}` : undefined;
  const describedBy = borrowedId || ownId;
  const inert = refused || busy;

  return {
    refused,
    inert,
    aria: {
      "aria-disabled": refused || undefined,
      "aria-busy": busy || undefined,
      "aria-describedby": describedBy,
    },
    guard:
      <E extends React.SyntheticEvent>(handler?: (event: E) => void) =>
      (event: E) => {
        if (inert) {
          event.preventDefault();
          event.stopPropagation();
          return;
        }
        handler?.(event);
      },
    note: ownId ? (
      <span id={ownId} className={REASON_CLASS} data-disabled-reason>
        {reason}
      </span>
    ) : null,
  };
}

/**
 * Control and sentence as one unit in whatever layout the control sat in.
 *
 * The sentence has to go *somewhere*, and a bare sibling becomes another item
 * in the parent's flex row — a paragraph of prose wedged between two buttons.
 * A column wrapper puts it under the control it belongs to, and only appears
 * when there is a refusal to explain, so a live control's layout is byte for
 * byte what it was.
 */
export function RefusalLayout({
  note,
  children,
  className,
}: {
  note: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  if (!note) return <>{children}</>;
  return (
    <span className={cn("inline-flex min-w-0 flex-col items-start gap-[3px]", className)}>
      {children}
      {note}
    </span>
  );
}
