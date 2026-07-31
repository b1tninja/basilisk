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
 *    the `.artifact-action:disabled` rule in toolkit.css.
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
  className?: string;
};

export function ArtifactAction({
  label,
  tier,
  onClick,
  reason,
  busyLabel,
  busy = false,
  className,
}: Props) {
  const disabled = !!reason;
  const reasonId = disabled ? `artifact-action-why-${slug(label)}` : undefined;
  return (
    <>
      <button
        type="button"
        className={cn(
          "artifact-action inline-flex h-[22px] shrink-0 items-center gap-1 rounded-[5px] border px-2 text-[10px] font-semibold transition-colors",
          className
        )}
        data-action-tier={tier}
        disabled={disabled}
        // Busy is `aria-busy`, never `disabled`: a disabled control loses its
        // accessible name in some screen-reader pairings at exactly the moment
        // the user most wants to know what is happening.
        aria-busy={busy || undefined}
        aria-describedby={reasonId}
        title={reason || undefined}
        onClick={disabled || busy ? undefined : onClick}
      >
        {busy ? <span className="artifact-action-spin" aria-hidden /> : null}
        {busy && busyLabel ? busyLabel : label}
      </button>
      {reasonId ? (
        // Visually hidden but read: the sentence is the feature, and `title`
        // alone is unreachable by keyboard and by touch.
        <span id={reasonId} className="sr-only">
          {reason}
        </span>
      ) : null}
    </>
  );
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
