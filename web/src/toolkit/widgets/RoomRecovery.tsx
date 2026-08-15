import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { cn } from "@/lib/cn";

/**
 * Recovery, offered where the room is — the second of the two notebooks.
 *
 * `room-ceremony.js` writes the deal and nothing else; this section is the
 * press that writes the reversal, at recovery time, following the deal
 * picker's own precedent: picker first, notebook falls out. The picker here is
 * one question — **who is contributing** — because everything else is read off
 * the shares' own BLIP39 headers by `room-recovery.js`, and the refusals
 * printed below are that module's, computed beside the arithmetic they
 * describe.
 *
 * Rendered by `SessionSheet` under both the start panel and the live panel,
 * deliberately: the recovery notebook is *written* whenever the quorum agrees
 * to it, and only its send cells need a live room — a recoverer who writes it
 * first and starts the session second has done nothing wrong.
 *
 * The paste path is always offered, because the person it exists for is
 * exactly the one this panel cannot describe: a custodian holding words on
 * paper, in a browser with no vault, no session and no notebook. Their
 * recovery has no contributors to pick, so it is one press with no picker.
 */
export type RoomRecoveryProps = {
  /** What this machine's own share says about itself, or "" holding none. */
  facts: string;
  /** `roomRecoveryIssues` — why the notebook cannot be written, as sentences. */
  issues: string[];
  /** The notebook as `serializeRecipe` will hold it, headers and all. */
  text: string;
  /** One line per cell, in cell order — the reading beside the recipe. */
  cells: { why: string }[];
  threshold: number;
  total: number;
  /**
   * Everyone the deal dealt a share to, minus this machine — the pickable
   * contributors. `chosen` is the agreement being built; the fingerprint is
   * whole, always, because a contributor is being *identified* here.
   */
  choices: { fingerprint: string; name?: string; chosen: boolean }[];
  onToggle: (fingerprint: string) => void;
  onWrite: () => void;
  /** The custodian's one-cell paste recovery — no session, no picker. */
  onWriteCustodian: () => void;
  /** What the last press did, or "" — a live region. */
  note?: string;
  className?: string;
};

export function RoomRecovery({
  facts,
  issues,
  text,
  cells,
  threshold,
  total,
  choices,
  onToggle,
  onWrite,
  onWriteCustodian,
  note = "",
  className,
}: RoomRecoveryProps) {
  const [showCells, setShowCells] = useState(false);
  const issuesId = useId();

  return (
    <section className={cn("flex flex-col gap-1.5", className)} data-room-recovery>
      <span className="text-[11px] font-bold text-[var(--foreground)]">
        Recover a dealt secret
      </span>

      {/* What this machine holds, read off the share's own header — the same
          facts the "Check a share…" panel prints from one mnemonic, offline.
          Absent when there is nothing readable here; the refusal below names
          that state instead of a sentence claiming facts nothing carries. */}
      {facts ? (
        <p
          className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
          data-room-recovery-facts
        >
          {facts}
        </p>
      ) : null}

      {choices.length ? (
        <fieldset
          className="m-0 flex flex-col gap-1 border-0 p-0"
          data-room-recovery-contributors
        >
          <legend className="p-0 text-[10px] font-bold text-[var(--muted-foreground)]">
            Who is contributing a share
          </legend>
          {/* One checkbox per holder the deal records. The agreement lists
              exactly the contributors it has — the generated gather takes
              every listed share and no others — so this list is the decision,
              not a filter over one made elsewhere. */}
          <ul className="flex list-none flex-col gap-1 p-0">
            {choices.map((c) => (
              <li
                key={c.fingerprint}
                className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5"
              >
                <label className="flex flex-wrap items-center gap-1.5 text-[10.5px] text-[var(--foreground)]">
                  <input
                    type="checkbox"
                    checked={c.chosen}
                    onChange={() => onToggle(c.fingerprint)}
                    aria-label={`${c.chosen ? "Remove" : "Add"} ${c.name || c.fingerprint} as a contributor`}
                  />
                  <Fingerprint
                    className="text-[10.5px] text-[var(--foreground)]"
                    fpr={c.fingerprint}
                  />
                  {c.name ? (
                    <span className="min-w-0 truncate text-[10.5px] text-[var(--muted-foreground)]">
                      {c.name}
                    </span>
                  ) : null}
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
      ) : null}

      {/* The refusals, drawn as their own list so the button can borrow all
          of them — same arrangement as the ceremony section above and Start
          below, for the same reason: one refusal, on screen once. */}
      {issues.length ? (
        <ul
          id={issuesId}
          className="flex list-none flex-col gap-1 p-0"
          data-room-recovery-issues
          data-disabled-reason
        >
          {issues.map((issue) => (
            <li
              key={issue}
              className="border-l-2 border-[var(--warn)] pl-2 text-[10.5px] leading-snug text-[var(--muted-foreground)]"
            >
              {issue}
            </li>
          ))}
        </ul>
      ) : null}

      {/* The cells before they replace anything — the deal picker's rule,
          held here too: a generated notebook that could not be read before it
          replaced yours would be the one thing in this app taken on trust. */}
      {text ? (
        <div className="flex flex-col gap-1">
          <button
            type="button"
            className="self-start text-[10.5px] text-[var(--brand)] underline"
            aria-expanded={showCells}
            onClick={() => setShowCells((v) => !v)}
          >
            {showCells ? "Hide" : "Show"} the {cells.length} cells this writes
          </button>
          {showCells ? (
            <>
              <ol className="flex list-none flex-col gap-0.5 p-0">
                {cells.map((c, i) => (
                  <li
                    key={i}
                    className="text-[10px] leading-snug text-[var(--muted-foreground)]"
                  >
                    <span className="font-mono">[{i}]</span> {c.why}
                  </li>
                ))}
              </ol>
              <pre
                className="overflow-x-auto rounded-[6px] border border-[var(--border)] bg-[var(--surface)] p-2 font-mono text-[10px] text-[var(--muted-foreground)]"
                data-room-recovery-recipe
              >
                {text}
              </pre>
            </>
          ) : null}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-1.5">
        <Button
          size="sm"
          variant="secondary"
          disabledReason={issues.length ? issues.join(" ") : undefined}
          reasonId={issues.length ? issuesId : undefined}
          onClick={onWrite}
        >
          {issues.length || !threshold
            ? "Write the recovery"
            : `Write the ${threshold}-of-${total} recovery`}
        </Button>
        <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
          Replaces the notebook you have open.
        </span>
      </div>

      {/* The road for the reader the picker cannot serve: a custodian with
          cards and nothing else. One unheaded cell whose `shares` collector
          opens the paste rows — the surface finding 2a said nothing pointed
          at. Always offered, because the state it serves is precisely the one
          where everything above is empty. */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Button size="sm" variant="ghost" onClick={onWriteCustodian} data-room-recovery-custodian>
          Recover from cards instead
        </Button>
        <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
          Holding mnemonics on paper? This writes a one-cell notebook that
          reads them from the Inputs tray — no session needed.
        </span>
      </div>

      {/* Always rendered — a live region created at the moment of its first
          message is a message some screen readers never announce. */}
      <p
        aria-live="polite"
        data-room-recovery-note={note ? "1" : ""}
        className="text-[10.5px] leading-snug text-[var(--brand)]"
      >
        {note}
      </p>
    </section>
  );
}
