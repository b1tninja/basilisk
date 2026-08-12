import { useEffect, useId, type ReactNode } from "react";
import { Play, Square } from "lucide-react";
import { cn } from "@/lib/cn";
import { setCssVar } from "@/lib/css-vars.js";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export type RunBarState =
  | "idle"
  | "blocked"
  | "running"
  | "waiting-peer"
  | "waiting-approval";

/**
 * What the notebook is holding, on the one row that is never collapsed.
 *
 * Whether a private key is open in this browser was computed the whole time and
 * was reachable only by opening the tray *and* selecting the Keys tab — two
 * deliberate acts to find out that a key has been decrypted in memory for the
 * last four minutes. That is precisely backwards: the state nobody thinks to
 * look for is the one that has to be in view.
 *
 * `power` is `key-power.js`'s closed vocabulary and rides as a `data` attribute
 * for the same reason `data-run-state` does — the stylesheet enumerates it, and
 * `style-src 'self'` refuses the alternative.
 */
export type KeyChip = {
  /** The strongest thing any held key can do — `absent` when nothing is held. */
  power: "absent" | "unusable" | "held" | "loaded" | "ready";
  /** How many keys have armor in the agent session right now. */
  loaded: number;
  /**
   * When the first of them is dropped, or null when none is.
   *
   * `sessionEarliestExpiry()` in `vault-session.js` is exactly this value and
   * had no caller anywhere in the app: correct, exported, and reaching nothing.
   */
  expiresAt: number | null;
};

type Props = {
  /** Derive: running while the kernel is busy, blocked when a readiness blocker exists, else idle. */
  state: RunBarState;
  /** Human-readable reason the notebook can't run (blocked state's inline chip). */
  blocker?: string | null;
  /**
   * Why Run all refuses even though nothing is blocked — the compiler's own
   * words, not a flag.
   *
   * It was `runDisabled?: boolean`, set from `!nb.compiled.validation?.ok`, and
   * it is the clearest case in the app of a control that could not have said
   * why: the shell holds `validation.errors`, the bar held one bit of it, and
   * the bit is the half that does not survive the trip. So the reason travels
   * instead of the boolean — the same fix `MenuPopover.disabledReason` needed,
   * and the reason this prop is a sentence and not a count.
   */
  runRefusal?: string | null;
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
  /** What this browser is holding — see `KeyChip`. Absent where nothing is. */
  keyChip?: KeyChip | null;
  /** Ticked by the shell; the countdown reads it rather than a timer of its own. */
  now?: number;
  /** Opens the tray's Keys tab — the chip is a way in, not only a readout. */
  onOpenKeys?: () => void;
  /** Right-aligned actions (Copy link / Clear session / Tray toggle in the shell). */
  children?: ReactNode;
};

/** m:ss, matching the tray's rows so one clock is not printed two ways. */
function countdown(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
}

/**
 * The key chip — always on screen while anything is open, and never otherwise.
 *
 * Nothing held is not drawn at all: a permanent "0 keys" would be noise on
 * every notebook that never touches one, and the tray's own tab already says
 * zero by having no number. What this exists for is the opposite case, where
 * something *is* decrypted and the reader has no reason to go looking.
 */
function KeyChipView({
  chip,
  now,
  onOpenKeys,
}: {
  chip: KeyChip;
  now: number;
  onOpenKeys?: () => void;
}) {
  const left = chip.expiresAt == null ? null : countdown(chip.expiresAt - now);
  const label =
    chip.loaded === 1 ? "1 key open" : `${chip.loaded} keys open`;
  const body = (
    <>
      <span className="key-power" data-key-power={chip.power}>
        {label}
      </span>
      {left ? (
        // The soonest expiry, not a per-key list: what a reader needs from a
        // strip this size is when the first thing goes away.
        <span className="font-mono text-[10.5px] text-[var(--warn)]">{left} left</span>
      ) : null}
    </>
  );
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--surface-raised)] px-2 py-[3px] text-[length:11px]"
      data-key-chip={chip.power}
    >
      {onOpenKeys ? (
        <Button
          size="sm"
          variant="ghost"
          className="h-auto gap-1.5 px-0 py-0 text-[length:11px]"
          onClick={onOpenKeys}
        >
          {body}
        </Button>
      ) : (
        body
      )}
    </span>
  );
}

/** Execution bar — Run all / Run from / blocker chip / running progress (design v2 §19g). */
export function RunBar({
  state,
  blocker = null,
  runRefusal = null,
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
  keyChip = null,
  now = 0,
  onOpenKeys,
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
  const chipId = useId();
  /** The warn chip beside Run all — on screen only in the blocked state. */
  const blockedChipShown = state === "blocked" && !!blocker;
  return (
    <div
      className={cn(
        "flex min-h-[44px] flex-wrap items-center gap-2.5 border-b bg-[var(--background)] px-3.5 py-1.5",
        state === "waiting-peer"
          ? "border-[color-mix(in_srgb,var(--caret)_30%,var(--border))]"
          : state === "waiting-approval"
            ? "border-[color-mix(in_srgb,var(--warn)_35%,var(--border))]"
            : "border-[var(--border)]"
      )}
      data-run-state={state}
    >
      {state === "waiting-approval" ? (
        <>
          {/* The decision lives in the banner at the requesting cell (§27a);
              this bar only says the run is stopped and offers the way out
              that is not a decision about the key. */}
          <Button
            variant="outline"
            className="border-transparent bg-[var(--surface-raised)] text-[var(--error)] hover:bg-[var(--surface-raised)]"
            onClick={onStop}
          >
            <Square />
            Stop
          </Button>
          <span className="font-mono text-[length:11.5px] text-[var(--warn)]">
            {waitingCell != null
              ? `Paused at cell [${waitingCell}] — a step wants to use a key`
              : "Waiting for approval — a step wants to use a key"}
          </span>
        </>
      ) : state === "waiting-peer" ? (
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
                  // `state === "blocked"` is derived from `blocker` in the one
                  // caller, so the state and its sentence arrive together; the
                  // compiler's refusal is the other half, and used to be a
                  // bare boolean with the words left behind in the shell.
                  disabledReason={runRefusal || blocker || undefined}
                  // Only when the chip below is already showing it. Otherwise
                  // the button prints its own, because a `title` reaches
                  // neither touch nor most screen readers — which is how a
                  // validation error stayed invisible next to a dead button.
                  reasonId={blockedChipShown ? chipId : undefined}
                  onClick={onRunAll}
                  className="aria-disabled:bg-[var(--surface-raised)] aria-disabled:text-[var(--muted-foreground)] aria-disabled:opacity-100"
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
                <span id={chipId} className="text-[length:11.5px]" data-disabled-reason>
                  {blocker}
                </span>
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

      {/* Beside the run controls in every state that has room for it, because
          "a key is open" is not news about the run — it is news about this
          browser, and it is true while a run is in flight as much as before
          one. The two peer states own the whole bar and are excluded for the
          same reason `children` is. */}
      {keyChip && keyChip.loaded > 0 && state !== "waiting-peer" && state !== "waiting-approval" ? (
        <KeyChipView chip={keyChip} now={now} onOpenKeys={onOpenKeys} />
      ) : null}

      {children && state !== "waiting-peer" && state !== "waiting-approval" ? (
        <div className="ml-auto flex flex-wrap items-center gap-1">{children}</div>
      ) : null}
    </div>
  );
}
