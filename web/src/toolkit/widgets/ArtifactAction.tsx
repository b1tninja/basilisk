import { useId } from "react";
import { cn } from "@/lib/cn";

/**
 * One action on an artifact tile (§33b/§33d/§41, design_handoff_artifact_actions).
 *
 * The tiers are not decoration. They encode what happens if you click:
 *
 *   inert    — local, reversible, no state changes (Copy, Download)
 *   local    — changes durable state on this device (Add to keyring)
 *   outward  — leaves the machine, and may be irreversible (Publish)
 *
 * Flattening them into a row of equal buttons is how a mis-click becomes
 * unrecoverable, which is why the weight is a declared property rather than a
 * per-call-site class.
 *
 * Two rules this component exists to enforce, because both were being got
 * wrong by hand:
 *
 * 1. **A disabled action always carries a reason.** "Is this meaningful for
 *    this object?" — no, then the kind never declares it, and nothing renders.
 *    "Is it possible here, now?" — no, then it renders disabled *with a
 *    sentence*. A dead button with no reason is worse than no button, so
 *    `disabled` without `reason` is a type error rather than a convention.
 * 2. **Disabled does not dim.** The shipped `disabled:opacity-50` puts the
 *    reason at 2.20:1 in light, and a reason nobody can read is the same as no
 *    reason. The affordance is removed instead; the label stays legible. See
 *    the `.artifact-action[aria-disabled="true"]` rule in toolkit.css.
 * 3. **A refused action is still focusable.** `aria-disabled`, never the
 *    `disabled` attribute — see the comment on `refuse` below. This is the one
 *    of the three that was written down here as a known defect and shipped
 *    anyway: the comment beside `aria-describedby` said `title` alone is
 *    unreachable by keyboard, while `disabled` took the button out of the tab
 *    order and made the description unreachable by keyboard too.
 */
export type ActionTier = "inert" | "local" | "outward";

type Props = {
  label: string;
  tier: ActionTier;
  onClick: () => void;
  /**
   * Present only when the action is unavailable *here and now*. Its presence
   * is what disables the button — the two cannot drift apart.
   */
  reason?: string;
  /** Progressive label while the action runs ("Adding…"). */
  busyLabel?: string;
  busy?: boolean;
  /**
   * The id of an element that already states this reason **visibly**, for the
   * case where every action in a row refuses for the same reason and the row
   * says it once (`gatedRowReason`). Given one, this component points at it
   * instead of emitting a private `sr-only` copy — two buttons and one visible
   * sentence would otherwise be three announcements of one refusal, which is
   * `artifact-reasons.js`'s "one condition, one explanation" arriving through
   * the DOM the same way the label-derived id defect did.
   */
  describedBy?: string;
  className?: string;
};

export function ArtifactAction({
  label,
  tier,
  onClick,
  reason,
  busyLabel,
  busy = false,
  describedBy,
  className,
}: Props) {
  const disabled = !!reason;
  /**
   * Unique per mounted action, because the id was built from the *label*.
   *
   * `artifact-action-why-download` is the same string on every tile, so a list
   * of nine key artifacts emitted the id thirteen times and every
   * `aria-describedby` on the page resolved to the **first** one. Measured on
   * the catalog's key section: 9 of 10 disabled actions pointed at a sentence
   * belonging to a different artifact — every disabled Download announced
   * "This artifact has no body to save" about a 927-byte armored private key
   * whose real reason was "Reveal this value first".
   *
   * That is precisely what `artifact-reasons.js` exists to prevent — one
   * condition acquiring two explanations — arriving through the DOM rather
   * than through the strings, and invisible to `tsc` and to the suite because
   * neither renders two tiles into one document.
   *
   * `useId` rather than a counter: it is stable across renders, so the
   * association does not break when a reason changes, and it is unique per
   * mount by construction rather than by everyone remembering to pass a key.
   */
  const uid = useId();
  /** Only when the row has not already put the sentence on screen for us. */
  const ownReasonId =
    disabled && !describedBy ? `artifact-action-why-${slug(label)}-${uid}` : undefined;
  const reasonId = describedBy || ownReasonId;
  /**
   * **The refusal, which is what buys the reason its reachability.**
   *
   * `disabled` removes a button from the tab order, so `aria-describedby` fires
   * for nobody who navigates by keyboard: the sentence reached mouse users
   * through `title`, and screen-reader users only in browse mode, where you
   * have to already be reading the button to find out why it is dead. The
   * feature of a disabled action is its reason, and the attribute that made it
   * look disabled was the thing hiding it.
   *
   * `aria-disabled` announces the state and keeps the button focusable — and
   * keeps it **clickable**, which is why this handler exists rather than the
   * old `onClick={disabled ? undefined : onClick}`. An undefined handler on an
   * aria-disabled button is not a refusal: the click still happens, it still
   * bubbles, and anything listening above it still fires. So the refusal is
   * explicit and it stops the event, because `ArtifactTile` draws these inside
   * a row and the tray draws that row inside a list.
   *
   * Busy takes the same branch. It was already never `disabled` (an in-flight
   * control that loses its accessible name is the worst moment to lose it),
   * and it was already refusing by the same `undefined` — which had the same
   * hole, one double-click wide.
   */
  const refuse = disabled || busy;
  return (
    <>
      <button
        type="button"
        className={cn(
          "artifact-action inline-flex h-[22px] shrink-0 items-center gap-1 rounded-[5px] border px-2 text-[10px] font-semibold transition-colors",
          className
        )}
        data-action-tier={tier}
        aria-disabled={disabled || undefined}
        // Busy is `aria-busy`, never `disabled`: a disabled control loses its
        // accessible name in some screen-reader pairings at exactly the moment
        // the user most wants to know what is happening.
        aria-busy={busy || undefined}
        aria-describedby={reasonId}
        title={reason || undefined}
        onClick={(e) => {
          if (refuse) {
            e.preventDefault();
            e.stopPropagation();
            return;
          }
          onClick();
        }}
      >
        {busy ? <span className="artifact-action-spin" aria-hidden /> : null}
        {busy && busyLabel ? busyLabel : label}
      </button>
      {ownReasonId ? (
        // Visually hidden but read: the sentence is the feature, and `title`
        // alone is unreachable by keyboard and by touch.
        <span id={ownReasonId} className="sr-only">
          {reason}
        </span>
      ) : null}
    </>
  );
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
