import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { otpCodeReadout, otpTimeLeft } from "../../lib/toolkit/artifact-readouts.js";

/**
 * The one-time code read-out (§37b).
 *
 * A code is the one artifact whose whole value is legible at a glance and
 * whose whole problem is *how long you have*. So the tile leads with the
 * digits at a size you can read across a desk while typing them into another
 * window, and puts the two facts the string cannot carry underneath: which
 * account it belongs to, and how much of its step is left.
 *
 * ## The countdown does not recompute anything
 *
 * This is the design decision the widget exists to hold, and it is worth
 * stating plainly because the obvious feature — a Refresh button — is the one
 * §37a forbids. *A button may move an artifact; it may never compute a new
 * one.* A freshly computed code would be a value with no step behind it in the
 * recipe, nothing in the receipt describing it, and no way for the CLI to
 * reproduce it. The code shown here is always the code `otp.code` produced,
 * which is the value the run receipt digested.
 *
 * What ticks is the *clock*, not the value. `otpCodeReadout` turns the run's
 * `otpStep` and `otpPeriod` into an absolute expiry instant — a TOTP step ends
 * at `(step + 1) × period` from the Unix epoch, whatever happens afterwards —
 * so a one-second tick against `Date.now()` is honest about an artifact that
 * has been sitting on screen for four minutes: the bar drains, the seconds
 * count down, and then it says **expired** and stays there, still showing the
 * value it always showed. A tile that silently produced a fresh code instead
 * would be lying about which value the receipt covers, which is the more
 * expensive of the two mistakes by a wide margin.
 *
 * Re-running the cell is what produces the next code, and the tile says so
 * rather than offering to do it — that sentence is the *view* answer to what
 * would otherwise be a forbidden action.
 *
 * ## A pinned code has a clock, but not this one
 *
 * `otp.code at=1700000000` names an instant, and the code for that instant is
 * the same six digits on every run, forever. This card used to draw the same
 * draining bar over it, land on **expired**, and finish with *run the cell
 * again for the current one* — advice that `at=` guarantees cannot work. The
 * two cases were indistinguishable because the op emitted identical traits for
 * both; `traits.otpPinnedAt` now records the intent, and:
 *
 * > A card may tick only against an instant the recipe did not choose.
 *
 * So a pinned code does not tick, draws no bar, and never says *expired* —
 * that word is about wall-clock now, and a pinned code's relationship to now
 * was never the question. It states the instant instead, plus the fact that
 * makes pinning worth doing: this is the reproducible case, the one a receipt
 * can be checked against with `run.verify`, where a live code is not.
 *
 * The digits are untouched by any of it. A live artifact may vary its value,
 * never its type — same card, same weight, same actions, one sentence
 * different.
 *
 * ## HOTP has no countdown
 *
 * Not a disabled one, not a zeroed one: none. A HOTP code answers to an event
 * counter, not a clock, so it does not expire — it gets spent. §33d's split
 * says "is this meaningful for this object" is answered by omission, so the
 * timer is simply not drawn and the counter takes its place.
 *
 * Tones and the draining bar ride `data-otp-*` attributes enumerated in
 * toolkit.css, because `style-src 'self'` refuses an inline style; the bar is
 * bucketed into twelfths for the same reason `JwtArtifact`'s is, and twelfths
 * are finer than the eye reads off a bar this size.
 */

type Tone = "ok" | "warn" | "error" | "muted";

/** Seconds of remaining step below which the countdown escalates. */
export const OTP_URGENT_SECONDS = 5;

/**
 * The tone a remaining step deserves.
 *
 * Exported because it is the one decision in the widget, and a test can walk
 * it across the boundaries without waiting out a real 30-second step.
 */
export function otpTone(secondsLeft: number | null): Tone {
  if (secondsLeft == null) return "muted";
  if (secondsLeft <= 0) return "error";
  if (secondsLeft <= OTP_URGENT_SECONDS) return "warn";
  return "ok";
}

/**
 * True when an artifact carries enough for this card to draw.
 *
 * Exported and called by the kind, not left to the component, for the reason
 * `hasJoseRenderer` is: `renderKindView` decides whether the tile falls through
 * to the raw body by whether the *view* returned null, and a component that
 * returns null from inside a rendered element is still a rendered element. A
 * card that drew nothing while claiming the row would hide the digits — the one
 * thing this artifact certainly has.
 */
export function hasOtpReadout(
  content: string | undefined,
  traits: Record<string, unknown> | null | undefined
): boolean {
  return !!otpCodeReadout(content ?? "", traits);
}

function fmtClock(seconds: number): string {
  try {
    return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
  } catch {
    return String(seconds);
  }
}

export function OtpCodeCard({
  content,
  traits,
  className,
  /** Injectable for tests and the catalog; production ticks the real clock. */
  nowMs,
}: {
  content: string;
  traits?: Record<string, unknown> | null;
  className?: string;
  nowMs?: number;
}) {
  // Read before the hooks, not after, so the interval can ask whether this
  // artifact has a clock at all. `otpTimeLeft` is the single place that
  // decides — null for HOTP, which has no clock, and null for a pinned code,
  // whose instant the recipe chose — so the timer honours the same rule the
  // sentence below does instead of re-deriving the condition and drifting from
  // it. A plain function call is not a hook; the hooks that follow stay
  // unconditional.
  const readout = otpCodeReadout(content, traits);
  const ticks = otpTimeLeft(readout, 0) != null;
  const pinnedAt = readout?.pinnedAt ?? null;

  const [tick, setTick] = useState(() => nowMs ?? Date.now());
  useEffect(() => {
    if (nowMs != null) {
      setTick(nowMs);
      return undefined;
    }
    if (!ticks) return undefined;
    const id = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, [nowMs, ticks]);

  // Nothing to add to the digits the tile already shows (§32d) — a body that
  // is not a code, or an artifact carrying no OTP facts.
  if (!readout) return null;

  const left = otpTimeLeft(readout, tick / 1000);
  const tone = otpTone(left ? left.seconds : null);
  // A step with life left never rounds down to empty: 0 is reserved for
  // expired, which is the one state that should read as an empty bar.
  const bucket = left
    ? left.expired
      ? 0
      : Math.max(1, Math.round(left.fraction * 12))
    : 12;

  return (
    <div
      className={cn("flex flex-col gap-1.5 pl-[1px]", className)}
      data-otp-card
      data-otp-mode={readout.mode}
      data-otp-expired={left?.expired ? "true" : "false"}
      data-otp-pinned={pinnedAt != null ? "true" : "false"}
    >
      {readout.label ? (
        <span className="truncate text-[10.5px] text-[var(--muted-foreground)]">
          {readout.label}
        </span>
      ) : null}

      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        {/* The digits, grouped for reading. The value is unchanged — Copy
            still copies the code the recipe produced, and the grouping is a
            gap between spans, not a character in the string. */}
        <span
          className="otp-code flex gap-2 font-mono"
          data-otp-tone={tone}
          aria-label={`One-time code ${readout.code}`}
        >
          {readout.groups.map((g, i) => (
            <span key={`${g}-${i}`}>{g}</span>
          ))}
        </span>
        {left ? (
          <span className="otp-remaining font-mono text-[11px] font-semibold" data-otp-tone={tone}>
            {left.expired ? "expired" : `${left.seconds}s`}
          </span>
        ) : pinnedAt != null ? (
          // Where a live code says how long it has, a pinned one says what it
          // is. Never "expired": that word is a claim about now, and this code
          // was never about now.
          <span className="otp-remaining font-mono text-[11px] font-semibold" data-otp-tone="muted">
            pinned
          </span>
        ) : readout.mode === "hotp" && readout.counter != null ? (
          <span className="font-mono text-[11px] text-[var(--muted-foreground)]">
            counter {readout.counter}
          </span>
        ) : null}
      </div>

      {left ? (
        <>
          <div
            className="otp-track relative h-[4px] overflow-hidden rounded-full"
            role="img"
            aria-label={
              left.expired
                ? `Expired — this code was the one for the step ending ${fmtClock(
                    readout.expiresAt as number
                  )}`
                : `Valid for ${left.seconds} more seconds`
            }
          >
            <span
              className="otp-fill absolute inset-y-0 left-0"
              data-otp-tone={tone}
              data-otp-fill={bucket}
            />
          </div>
          <span className="text-[9.5px] text-[var(--muted-foreground)]">
            {left.expired ? (
              <>
                This was the code for the {readout.period}s step ending{" "}
                <span className="font-mono">{fmtClock(readout.expiresAt as number)}</span>. It is
                still the value this cell produced — run the cell again for the current one.
              </>
            ) : (
              <>
                Valid until <span className="font-mono">{fmtClock(readout.expiresAt as number)}</span>
                {readout.period ? ` · ${readout.period}s step` : ""}
              </>
            )}
          </span>
        </>
      ) : pinnedAt != null ? (
        // No bar above this line, deliberately: there is nothing draining. The
        // second sentence is the useful one — a pinned code is the reproducible
        // case, which is what `at=` is for, and it is the honest replacement
        // for the advice that used to sit here.
        <span className="text-[9.5px] text-[var(--muted-foreground)]">
          The code for the {readout.period ? `${readout.period}s ` : ""}step at{" "}
          <span className="font-mono">{fmtClock(pinnedAt)}</span>. Pinned by{" "}
          <span className="font-mono">at=</span>, so every run of this recipe produces it.
        </span>
      ) : readout.mode === "hotp" ? (
        <span className="text-[9.5px] text-[var(--muted-foreground)]">
          A HOTP code answers to a counter, not a clock — it does not expire, it
          gets spent.
        </span>
      ) : null}
    </div>
  );
}
