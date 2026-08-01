import type { ComponentPropsWithoutRef, ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * The shell every "something consequential is about to happen, and you have to
 * choose" moment renders in (§43a, design_handoff_artifact_actions/visual).
 *
 * Extracted from `ApprovalBanner` (§27b) with no change to a single class, and
 * that constraint is the whole point rather than tidiness. A user who has
 * learned that *a warn-bordered inline panel with a facts table means a
 * decision* should not have to learn a second visual language for the same
 * sentence. A second confirmation grammar teaches that confirmations are
 * decorative, which is the failure mode that makes every confirmation in the
 * product worthless.
 *
 * It also makes an *absence* legible. §43b's argument for the publish
 * confirmation is that it has no session checkbox, no batch offer and no
 * request counter — and that reads as a decision only if everything around it
 * is identical, so the eye lands where the checkbox was and finds nothing
 * there. Two independently-written banners could not deliver that.
 *
 * Structure, top to bottom, all of it fixed here so no caller can drift:
 *
 *   container   2px `--warn` left edge, warn-8% ground, padding 10px 14px
 *   header      11.5px/600, with optional 10px mono meta pushed right
 *   facts       `<dl>` on a 68px + 1fr grid, 10.5px, gaps 4px / 8px
 *   actions     10px below, gap 8px, ghost first then secondary
 *   footnote    optional, under the actions
 *
 * Deliberately *not* here: focus management and Escape. §33g says the
 * confirmation banner moves focus to its first control and resolves Escape as
 * cancel "matching `ApprovalBanner`" — but `ApprovalBanner` has never done
 * either, and unit 4.4's contract is that its behaviour does not change. So
 * both are opt-in (`onEscape`, `autoFocus` on the caller's own button) and the
 * approval banner does not opt in. Making them shell defaults would have
 * changed the one component this extraction promised to leave alone, in the
 * direction that is hardest to notice: a keystroke that used to do nothing
 * suddenly denying a signing request.
 */
type GateBannerProps = {
  /** Accessible name for the `alertdialog`. */
  label: string;
  /** The question, in one line. */
  heading: ReactNode;
  /** Right-aligned mono context — the approval's request counter, and nothing on the others. */
  meta?: ReactNode;
  /** `<dt>`/`<dd>` pairs, usually via `GateFact`. */
  facts: ReactNode;
  /** Buttons, ghost-cancel first (§43c). */
  actions: ReactNode;
  /** A consequence spelled out under the buttons once a choice widens it. */
  footnote?: ReactNode;
  /** Resolves Escape. Absent means Escape does nothing, as in the approval banner. */
  onEscape?: () => void;
  className?: string;
} & Omit<ComponentPropsWithoutRef<"div">, "title">;

export function GateBanner({
  label,
  heading,
  meta,
  facts,
  actions,
  footnote,
  onEscape,
  className,
  ...rest
}: GateBannerProps) {
  return (
    <div
      className={cn(
        "border-l-2 border-[var(--border)] border-l-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_8%,transparent)] px-3.5 py-2.5",
        className
      )}
      role="alertdialog"
      aria-label={label}
      onKeyDown={
        onEscape
          ? (e) => {
              if (e.key !== "Escape") return;
              // Stops the Sheet or a popover above from also closing: the
              // banner is the innermost dismissible thing, and Escape should
              // resolve one layer at a time.
              e.stopPropagation();
              onEscape();
            }
          : undefined
      }
      {...rest}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-[length:11.5px] font-semibold text-[var(--foreground)]">
          {heading}
        </span>
        {meta != null ? (
          <span className="ml-auto font-mono text-[length:10px] text-[var(--muted-foreground)]">
            {meta}
          </span>
        ) : null}
      </div>

      <dl className="mt-2 grid grid-cols-[68px_minmax(0,1fr)] gap-x-2 gap-y-1 text-[length:10.5px]">
        {facts}
      </dl>

      <div className="mt-2.5 flex flex-wrap items-center gap-2">{actions}</div>
      {footnote}
    </div>
  );
}

/**
 * One row of the facts table.
 *
 * A fragment, not a wrapper: `<dt>` and `<dd>` have to stay direct children of
 * the grid, or the 68px column stops meaning anything.
 */
export function GateFact({
  term,
  detailClassName,
  children,
}: {
  term: ReactNode;
  /** For the rows that are mono, or break-all, or both. */
  detailClassName?: string;
  children: ReactNode;
}) {
  return (
    <>
      <dt className="font-semibold text-[var(--muted-foreground)]">{term}</dt>
      <dd className={cn("min-w-0", detailClassName)}>{children}</dd>
    </>
  );
}
