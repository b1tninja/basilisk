import { useEffect, type ReactNode } from "react";
import { Play, Square } from "lucide-react";
import { cn } from "@/lib/cn";
import { setCssVar } from "@/lib/css-vars.js";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export type RunBarState = "idle" | "blocked" | "running" | "waiting-peer";

type Props = {
  /** Derive: running while the kernel is busy, blocked when a readiness blocker exists, else idle. */
  state: RunBarState;
  /** Human-readable reason the notebook can't run (blocked state's inline chip). */
  blocker?: string | null;
  /** Disable Run all even when idle (e.g. recipe validation failed). */
  runDisabled?: boolean;
  /** Focused cell index — shows "Run from [N]" when > 0. */
  focusedCell?: number;
  /** Running-state progress; null while busy but between cells. */
  progress?: { cell: number; total: number } | null;
  onRunAll: () => void;
  onRunFrom?: (from: number) => void;
  onStop?: () => void;
  /** Blocked-state "Bind now" action (opens the tray's Inputs tab in the shell). */
  onBind?: () => void;
  /** waiting-peer: which cell the run is paused at (design v2 §21a). */
  waitingCell?: number;
  /** waiting-peer: shareable invite line — shows Copy invite when set. */
  sessionInvite?: string;
  onCopyInvite?: () => void;
  onCancelSession?: () => void;
  /** Right-aligned actions (Copy link / Clear session / Tray toggle in the shell). */
  children?: ReactNode;
};

/** Execution bar — Run all / Run from / blocker chip / running progress (design v2 §19g). */
export function RunBar({
  state,
  blocker = null,
  runDisabled = false,
  focusedCell = 0,
  progress = null,
  onRunAll,
  onRunFrom,
  onStop,
  onBind,
  waitingCell,
  sessionInvite,
  onCopyInvite,
  onCancelSession,
  children,
}: Props) {
  // Publish the fill percentage as a custom property rather than a style prop.
  // Cleared to 0 when no run is in flight so a stale bar never lingers.
  useEffect(() => {
    const pct =
      progress && progress.total > 0
        ? Math.max(0, Math.min(100, (progress.cell / progress.total) * 100))
        : 0;
    setCssVar("--run-progress", pct, "%");
  }, [progress?.cell, progress?.total]);
  return (
    <div
      className={cn(
        "flex min-h-[44px] flex-wrap items-center gap-2.5 border-b bg-[var(--background)] px-3.5 py-1.5",
        state === "waiting-peer"
          ? "border-[color-mix(in_srgb,var(--caret)_30%,var(--border))]"
          : "border-[var(--border)]"
      )}
      data-run-state={state}
    >
      {state === "waiting-peer" ? (
        <>
          <Button
            variant="outline"
            className="border-transparent bg-[var(--surface-raised)] text-[var(--error)] hover:bg-[var(--surface-raised)]"
            onClick={onStop}
          >
            <Square />
            Stop
          </Button>
          <span className="font-mono text-[length:11.5px] text-[var(--caret)]">
            {waitingCell != null
              ? `Paused at cell [${waitingCell}] — waiting for peer…`
              : "Waiting for peer…"}
          </span>
          <span className="ml-auto flex items-center gap-1.5">
            {sessionInvite && onCopyInvite ? (
              <Button
                size="sm"
                variant="secondary"
                className="h-[24px] rounded-[5px] px-2.5 text-[10.5px]"
                onClick={onCopyInvite}
              >
                Copy invite
              </Button>
            ) : null}
            {onCancelSession ? (
              <Button
                size="sm"
                variant="ghost"
                className="h-[24px] rounded-[5px] px-2.5 text-[10.5px] text-[var(--muted-foreground)]"
                onClick={onCancelSession}
              >
                Cancel
              </Button>
            ) : null}
          </span>
        </>
      ) : state === "running" ? (
        <>
          <Button
            variant="outline"
            className="border-transparent bg-[var(--surface-raised)] text-[var(--error)] hover:bg-[var(--surface-raised)]"
            onClick={onStop}
          >
            <Square />
            Stop
          </Button>
          <span className="font-mono text-[length:11.5px] text-[var(--caret)]">
            {progress
              ? `Running cell ${progress.cell} of ${progress.total}…`
              : "Running…"}
          </span>
          {progress ? (
            <div
              className="ml-1.5 h-[3px] max-w-[200px] flex-1 overflow-hidden rounded-full bg-[var(--surface-raised)]"
              role="progressbar"
              aria-valuenow={progress.cell}
              aria-valuemin={0}
              aria-valuemax={progress.total}
            >
              {/* Fill width rides `--run-progress` (lib/css-vars): a continuous
                  value, so no enumerated rule fits, and a style prop is
                  blocked by `style-src 'self'`. */}
              <div className="run-progress-fill h-full bg-[var(--caret)] transition-[width]" />
            </div>
          ) : null}
        </>
      ) : (
        <>
          <Tooltip>
            <TooltipTrigger asChild>
              <span>
                <Button
                  disabled={state === "blocked" || runDisabled}
                  title={blocker || "Run all cells"}
                  onClick={onRunAll}
                  className="disabled:bg-[var(--surface-raised)] disabled:text-[var(--muted-foreground)] disabled:opacity-100"
                >
                  <Play />
                  Run all
                </Button>
              </span>
            </TooltipTrigger>
            {blocker ? <TooltipContent>{blocker}</TooltipContent> : null}
          </Tooltip>
          {focusedCell > 0 && onRunFrom ? (
            <Button variant="outline" onClick={() => onRunFrom(focusedCell)}>
              Run from{" "}
              <code className="font-mono text-[var(--muted-foreground)]">
                [{focusedCell}]
              </code>
            </Button>
          ) : null}

          {state === "blocked" && blocker ? (
            <>
              <div className="h-[18px] w-px bg-[var(--border)]" />
              <div className="flex items-center gap-1.5 rounded-md border border-[color-mix(in_srgb,var(--warn)_28%,var(--border))] bg-[color-mix(in_srgb,var(--warn)_9%,transparent)] px-2.5 py-1">
                <span
                  className="h-[6px] w-[6px] shrink-0 rounded-full bg-[var(--warn)]"
                  aria-hidden
                />
                <span className="text-[length:11.5px]">{blocker}</span>
                {onBind ? (
                  <Button
                    size="sm"
                    className="h-auto shrink-0 rounded-[4px] bg-[var(--warn)] px-[8px] py-[2px] text-[10.5px] font-bold text-[var(--background)] hover:opacity-90"
                    onClick={onBind}
                  >
                    Bind now
                  </Button>
                ) : null}
              </div>
            </>
          ) : null}
        </>
      )}

      {children && state !== "waiting-peer" ? (
        <div className="ml-auto flex flex-wrap items-center gap-1">{children}</div>
      ) : null}
    </div>
  );
}
