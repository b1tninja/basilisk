import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

/**
 * One blocker keeping a cell from running. Callers pass the list already
 * priority-ordered (design v2 §20e): 1. missing recipient/key binding,
 * 2. missing runtime secret, 3. blocked required param, 4. upstream cell
 * hasn't run. Only the first is named; the rest are counted.
 */
export type ReadinessBlocker = {
  id: string;
  /** Sentence fragment after "One thing left: " — e.g. "recipients aren't bound". */
  label: string;
  /** Action button text — always matches the named blocker, never a generic "Fix". */
  action: string;
  onAction: () => void;
};

type Props = {
  blockers: ReadinessBlocker[];
  /**
   * So a refused Run can point `aria-describedby` here instead of printing its
   * own copy of the same blocker three inches above. The line is the visible
   * half of that button's explanation, which is why it carries
   * `data-disabled-reason` — the sweep in `disabled-needs-reason.test.js`
   * refuses to let anything a control describes itself with become invisible.
   */
  id?: string;
  className?: string;
};

/**
 * Per-cell readiness triage line (design v2 §20e). Hidden entirely on a clean
 * cell — no green checkmark row. "+N more" stays silent about what the rest
 * are; the cell's own inline dims already say which.
 */
export function ReadinessBar({ blockers, id, className }: Props) {
  if (!blockers.length) return null;
  const [first] = blockers;
  const rest = blockers.length - 1;
  return (
    <div
      id={id}
      data-disabled-reason
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-[7px] border border-[color-mix(in_srgb,var(--warn)_25%,transparent)] bg-[color-mix(in_srgb,var(--warn)_6%,transparent)] px-2.5 py-2",
        className
      )}
      data-readiness
    >
      <span className="h-[6px] w-[6px] shrink-0 rounded-full bg-[var(--warn)]" aria-hidden />
      <span className="text-[length:11px] text-[var(--foreground)]">
        One thing left: {first.label}
        {rest > 0 ? ` — plus ${rest} more` : ""}.
      </span>
      <Button
        size="sm"
        className="ml-auto h-[22px] shrink-0 rounded-[5px] bg-[var(--warn)] px-[9px] text-[10px] font-bold text-[#1a1405] hover:opacity-90"
        onClick={(e) => {
          e.stopPropagation();
          first.onAction();
        }}
      >
        {first.action}
      </Button>
    </div>
  );
}
