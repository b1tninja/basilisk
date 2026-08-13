import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { cn } from "@/lib/cn";

/** A notebook a peer proposed that this browser has not adopted. */
export type ProposedNotebook = {
  /** Sender's fingerprint — the session checked their signature; no label here. */
  from: string;
  title: string;
  source: string;
  ts: number;
};

export type NotebookShareProps = {
  /** Whether an exchange is open at all — decides which sentence is honest. */
  live: boolean;
  /** Whether there is anything here to share. */
  hasNotebook: boolean;
  /** Waiting on a press, or null when nothing is. */
  proposed: ProposedNotebook | null;
  onShare: () => void;
  onAdopt: () => void;
  onDismiss: () => void;
  /** The last attempt's outcome, in the words the layer below used. */
  note?: string | null;
  className?: string;
};

/**
 * Why nothing can be shared — one string, naming the session rather than the
 * button, exactly as `HandoffQueue` does. The notebook is fine; there is simply
 * no channel.
 */
const NO_SESSION =
  "No session is open, so there is nowhere to send this. Open a shared session under Share, and this becomes one press.";

/** How many cells a proposal is, without compiling it to find out. */
function cellCount(source: string) {
  return String(source || "")
    .split(/\n\s*\n+/)
    .map((c) => c.trim())
    .filter(Boolean).length;
}

/**
 * The notebook itself crossing between machines.
 *
 * Everything under `HandoffQueue` presumed both ends were already holding the
 * same text, and nothing ever put it there. An invite carries an audience and no
 * recipe; the session carried a manifest, an attestation, an offer and a result
 * and no notebook. So a joiner arrived empty, derived a manifest from an empty
 * notebook, and refused every offer that reached them — with a sentence telling
 * them to ask for a document no part of the product would send. This is the
 * entry point for the thing that was missing.
 *
 * **The digest gate is untouched.** Both ends still hold the same text and still
 * prove it by digest before a single value is registered. What changed is that
 * one of them may now receive that text, signed by the peer proposing it,
 * instead of being required to retype it.
 *
 * **Adopting is not always a press, and that is the point.** A joiner with an
 * empty notebook takes the first proposal without being asked — requiring a
 * press to *receive* a notebook is what the joiner was stuck behind, and adding
 * one back would be the same uselessness with an extra step. A notebook with
 * your own work in it is never replaced silently: that lands here, named by
 * whoever sent it, and waits.
 */
export function NotebookShare({
  live,
  hasNotebook,
  proposed,
  onShare,
  onAdopt,
  onDismiss,
  note,
  className,
}: NotebookShareProps) {
  return (
    <section
      className={cn("flex flex-col gap-2", className)}
      data-notebook-share={live ? "live" : "idle"}
    >
      <h4 className="text-[11px] font-bold text-[var(--foreground)]">
        The notebook itself
      </h4>

      <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">
        A cell can only cross to a peer who is holding the same notebook — every
        offer is checked against the text on the receiving machine, by digest.
        Sharing signs this notebook with the key the session was opened under and
        puts it in front of the room. Nothing runs there, and nobody&apos;s own
        work is replaced without a press.
      </p>

      <div className="flex flex-wrap gap-1.5">
        <Button
          size="sm"
          variant="secondary"
          disabledReason={
            !live
              ? NO_SESSION
              : hasNotebook
                ? undefined
                : "There is nothing in this notebook yet. Write a cell and this becomes one press."
          }
          onClick={onShare}
        >
          Share this notebook
        </Button>
      </div>

      {proposed ? (
        <div
          className="flex flex-col gap-1 rounded-[6px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-2 py-1.5"
          data-notebook-proposed
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="peer-verdict" data-verdict="warn">
              proposed
            </span>
            <span className="text-[11px] text-[var(--foreground)]">
              {proposed.title}
            </span>
            {/* Whole, for `HandoffQueue`'s reason: no label is known for this
                fingerprint here, and the row that decides whether to take
                somebody's notebook is the last place to print part of who they
                are. */}
            <span className="min-w-0 flex-1 text-[10px] text-[var(--muted-foreground)]">
              from <Fingerprint fpr={proposed.from} />
            </span>
          </div>
          <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
            {cellCount(proposed.source)} cell
            {cellCount(proposed.source) === 1 ? "" : "s"}, signed and checked
            against that peer&apos;s key. It is not the notebook you are holding,
            so nothing has been changed here. Adopting replaces this notebook
            with theirs — your cells are not merged into it and are not kept.
          </span>
          <div className="flex flex-wrap gap-1.5">
            <Button size="sm" variant="secondary" onClick={onAdopt}>
              Adopt their notebook
            </Button>
            <Button size="sm" variant="ghost" onClick={onDismiss}>
              Keep mine
            </Button>
          </div>
          <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
            Keeping yours does not tell them anything — there is no decline on
            the wire. Until one of you is holding the other&apos;s text, every
            cell handed across will be refused as a notebook this peer has not
            seen.
          </span>
        </div>
      ) : null}

      {note ? (
        <p
          className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
          data-notebook-share-note
        >
          {note}
        </p>
      ) : null}
    </section>
  );
}
