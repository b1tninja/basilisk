import { useState } from "react";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";
import { recipientRows } from "../../lib/toolkit/artifact-readouts.js";

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
 */
export function RecipientsCard({
  content,
  className,
}: {
  content: string;
  className?: string;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const rows = recipientRows(content);
  if (!rows) return null;

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-recipients-card>
      <table className="w-full table-fixed border-collapse text-left">
        <tbody>
          {rows.map((r) => (
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
      <div className="flex flex-col gap-1">
        <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
          {rows.length} recipient{rows.length === 1 ? "" : "s"}
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
