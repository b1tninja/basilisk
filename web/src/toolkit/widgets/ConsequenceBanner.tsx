import { useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { GateBanner, GateFact } from "./GateBanner";

/**
 * One fact of a consequence, as the action table declares it.
 *
 * `sub` is a second line under the detail — the fingerprint under the key, the
 * qualifier under the host. Kept separate rather than folded into `detail` so
 * the mono/muted treatment is the banner's decision and not each action's.
 */
export type ConsequenceFact = {
  term: string;
  detail: string;
  sub?: string;
  /** Fingerprints and ids, which have to break and have to be mono. */
  mono?: boolean;
};

export type ConsequenceSpec = {
  /** The sentence in the header — a statement of what is about to happen. */
  title: string;
  facts: ConsequenceFact[];
  /** Verb on the confirm button: "Publish", "Replace". */
  confirmLabel: string;
};

/**
 * The confirmation for an action with consequences (§34c/§34d), in §27's
 * banner grammar and rendered inline in the tile under the action row.
 *
 * Three things are visibly absent compared with the approval banner, and the
 * absences *are* the design (§43b): no session grant, no per-run batch, no
 * request counter. There is no defensible "don't ask again" for publishing —
 * each publish is its own irreversible act, and a five-minute window in which
 * a tile publishes without asking is a bug wearing a checkbox. Nothing loops
 * here, and no run is in progress. Because the shell is otherwise identical,
 * the eye lands where the checkbox was and finds nothing there, which is a
 * legible statement rather than a missing feature.
 *
 * Neither button is `--warn` (§43c). Inside the banner, warn text sits on the
 * warn-8% ground and measures 4.39:1 in light, and it is unnecessary anyway:
 * the banner is already entirely amber-framed. The rule that reconciles this
 * with the outward action's amber outline is that **amber marks the decision
 * point** — on the tile that is the button; in the banner it is the banner,
 * and the buttons are its answer.
 *
 * Unlike `ApprovalBanner`, this one takes focus on open and resolves Escape as
 * cancel (§43d). That is not a divergence in grammar: the approval banner
 * appears because a *run* reached a boundary op and the user may not have been
 * looking, so stealing focus would be an interruption; this one appears
 * because the user just clicked the button directly above it.
 */
export function ConsequenceBanner({
  spec,
  onConfirm,
  onCancel,
  busy = false,
  error,
  className,
}: {
  spec: ConsequenceSpec;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
  /** The thrown message, verbatim (§33f). Never "something went wrong". */
  error?: string | null;
  className?: string;
}) {
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  return (
    <GateBanner
      className={className}
      data-consequence-ask={spec.confirmLabel.toLowerCase()}
      label={spec.title}
      heading={spec.title}
      onEscape={busy ? undefined : onCancel}
      facts={
        <>
          {spec.facts.map((f) => (
            <GateFact
              key={f.term}
              term={f.term}
              detailClassName={f.mono ? "break-all font-mono" : undefined}
            >
              <span className="text-[var(--foreground)]">{f.detail}</span>
              {f.sub ? (
                <div className="break-all font-mono text-[length:10px] text-[var(--muted-foreground)]">
                  {f.sub}
                </div>
              ) : null}
            </GateFact>
          ))}
        </>
      }
      actions={
        <>
          <Button
            ref={cancelRef}
            size="sm"
            variant="ghost"
            disabled={busy}
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button size="sm" variant="secondary" aria-busy={busy || undefined} onClick={onConfirm}>
            {busy ? `${spec.confirmLabel}…` : spec.confirmLabel}
          </Button>
        </>
      }
      footnote={
        error ? (
          // §33f: the thrown message verbatim, and the action stays live. A
          // failed publish is retryable, and swallowing the message to show
          // "something went wrong" is the one outcome worse than the failure.
          <p className="mt-1.5 text-[length:10px] text-[var(--error)]">{error}</p>
        ) : null
      }
    />
  );
}
