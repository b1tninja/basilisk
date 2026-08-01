import { useState } from "react";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";
import {
  filterRecipientRows,
  recipientRows,
} from "../../lib/toolkit/artifact-readouts.js";

/**
 * The recipient-list read-out (§37b, design_handoff_artifact_actions).
 *
 * A `recipients` artifact is the answer to "who is this about to be encrypted
 * to", and it rendered as a JSON array — the one form in which nobody checks a
 * recipient list, which is the only reason to look at one. The five fields are
 * exactly what the engine already serializes; none of them is re-derived.
 *
 * `encryptCapable: false` is drawn as a stated fact rather than a warning
 * tone. It is not an error — a key with no encryption-capable subkey is a
 * perfectly good signing key — but a reader choosing recipients has to see it,
 * because `gpg.encrypt` will skip that row and the skip is easy to miss.
 *
 * No per-row *Import to key cache* button, though §37b sketches one: the
 * pubkey-cache service is not injected into a tile's actions yet, and a button
 * whose handler does not exist is worse than the absence. It is one service
 * away, and the row is where it will go.
 *
 * ## A ceiling, and a filter above a certain length
 *
 * The table rendered `max-height: none` at 16px a row, so a real `hkp.search`
 * — tens of rows — is several hundred pixels of table inside one row of a list
 * that has no reason to expect one. It scrolls now, and past `FILTER_ROWS` it
 * gets a search box.
 *
 * §47c is what permits the box: *could this interaction change what Copy
 * copies?* It cannot — the artifact keeps every row, the raw toggle shows the
 * whole JSON, and Copy copies the body — so it is a view and the tile may have
 * it. Which rows *match* is not a view decision and is not made here:
 * `filterRecipientRows` owns it, because a fingerprint is displayed grouped and
 * pasted from wherever the reader has it, and a comparison written inline would
 * silently match nothing for the one field nobody types by hand.
 *
 * The threshold exists so the common case does not grow a control it does not
 * need. A cache list is two or three rows; a keyserver search is forty.
 */

/**
 * Rows before the table offers a filter.
 *
 * The *ceiling* is deliberately not a constant beside this one. It is
 * `max-h-44` on the scroll box — 176px, about eleven rows at the 16px pitch
 * these rows measure — and a `TABLE_MAX_ROWS = 11` that no code could read
 * would be a number agreeing with a class only by hand. That is the `glyph`
 * defect: declared, validated, and rendered by nothing.
 */
export const FILTER_ROWS = 8;

export function RecipientsCard({
  content,
  className,
}: {
  content: string;
  className?: string;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const [query, setQuery] = useState("");
  const rows = recipientRows(content);
  if (!rows) return null;
  const shown = filterRecipientRows(rows, query);

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-recipients-card>
      {rows.length > FILTER_ROWS ? (
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by name, email or fingerprint"
          aria-label="Filter recipients"
          className="artifact-filter w-full rounded-[4px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] bg-transparent font-mono text-[var(--foreground)] placeholder:text-[var(--muted-foreground)]"
          data-recipients-filter
        />
      ) : null}
      {/* The scroll box, not the table, carries the ceiling: a `max-height` on
          a `<table>` is ignored by the table layout algorithm, which is how a
          cap can read as applied in a stylesheet and render unbounded in a
          browser. */}
      <div className="max-h-44 overflow-y-auto" data-recipients-rows>
        <table className="w-full table-fixed border-collapse text-left">
          <tbody>
            {shown.map((r) => (
              <tr key={r.fingerprint} className="align-baseline">
                <td className="w-[40%] truncate pr-2 font-mono text-[10px] text-[var(--foreground)]">
                  {r.label || r.email || "(no user id)"}
                </td>
                <td
                  className="w-[34%] truncate pr-2 font-mono text-[10px] text-[var(--muted-foreground)]"
                  title={formatFingerprint(r.fingerprint)}
                >
                  {formatFingerprint(r.fingerprint)}
                </td>
                {/* Two lines, not one truncating cell. Measured in the real
                    pane, "approved · cannot encrypt" lost its second half —
                    and the half that gets cut is the one that changes what
                    `gpg.encrypt` will do with this row. */}
                <td className="w-[26%] font-mono text-[9px] text-[var(--muted-foreground)]">
                  <span className="block truncate">{r.approvalState}</span>
                  {r.encryptCapable ? null : (
                    <span className="block truncate text-[var(--warn)]">cannot encrypt</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-col gap-1">
        {/* The total is always stated, and the filtered count only when one is
            in force — so a reader who has typed something can see that the
            rows they cannot see still exist, and `gpg.encrypt` will still walk
            them. A count that silently became the filtered one would make a
            filter look like a deletion. */}
        <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
          {shown.length === rows.length
            ? `${rows.length} recipient${rows.length === 1 ? "" : "s"}`
            : `${shown.length} of ${rows.length} recipients shown — the list still holds all ${rows.length}`}
        </span>
        <button
          type="button"
          className="self-start text-[10px] text-[var(--brand)] underline"
          onClick={() => setShowRaw((v) => !v)}
        >
          {showRaw ? "hide raw" : "raw"}
        </button>
        {showRaw ? (
          <code className="artifact-body block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-[var(--muted-foreground)]">
            {content}
          </code>
        ) : null}
      </div>
    </div>
  );
}
