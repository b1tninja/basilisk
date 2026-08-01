import { useState } from "react";
import { cn } from "@/lib/cn";
import { receiptSummary } from "../../lib/toolkit/artifact-readouts.js";

/**
 * The run-receipt read-out (§37b, design_handoff_artifact_actions).
 *
 * A receipt is a digest table, and it shipped as canonical JSON — correct as a
 * wire format and unreadable as a document. This renders the rows
 * `run.verify` actually walks, in the order it walks them, so a mismatch it
 * reports later ("cell 1 · output 2") names something a reader can find.
 *
 * No "verify this" button, and the absence is the design (§37b): verification
 * means re-running the recipe and comparing, which is `run.verify` — an op,
 * with a receipt as its input. A button here could only re-run *this*
 * notebook, which is not what verifying somebody else's receipt means.
 *
 * Digests are shown truncated with the full value in `title`: twelve hex
 * characters is enough to see that two rows differ, and the full 64 makes
 * every row wrap. The byte length rides in the same `title` rather than
 * beside the digest — measured in the real pane, the two together truncated
 * each other, and a truncated digest that *looks* complete is the one failure
 * mode a digest table must not have.
 */
export function ReceiptCard({
  content,
  className,
}: {
  content: string;
  className?: string;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const summary = receiptSummary(content);
  if (!summary) return null;

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-receipt-card>
      <div className="flex flex-wrap items-baseline gap-x-2">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          {summary.label}
        </span>
        <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
          {summary.createdAt} · ops {summary.registry}
        </span>
      </div>
      <code
        className="artifact-body block truncate font-mono text-[var(--muted-foreground)]"
        title={summary.recipeDigest}
      >
        recipe sha256 {summary.recipeDigest.slice(0, 12)}…
      </code>

      <table className="w-full table-fixed border-collapse text-left">
        <tbody>
          {summary.cells.flatMap((cell) =>
            cell.outputs.map((o, oi) => (
              <tr key={`${cell.index}-${oi}`} className="align-baseline">
                <td className="w-[14%] truncate pr-2 font-mono text-[9px] text-[var(--muted-foreground)]">
                  cell {cell.index}
                </td>
                <td className="w-[36%] truncate pr-2 font-mono text-[10px] text-[var(--foreground)]">
                  {o.label}
                </td>
                <td className="w-[18%] truncate pr-2 font-mono text-[9px] text-[var(--muted-foreground)]">
                  {o.role}
                </td>
                <td
                  className="w-[32%] truncate font-mono text-[9px] text-[var(--muted-foreground)]"
                  title={`${o.digest} · ${o.length} bytes`}
                >
                  {o.digest.slice(0, 12)}…
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
      <div className="flex flex-col gap-1">
        <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
          {summary.cells.length} cell{summary.cells.length === 1 ? "" : "s"} ·{" "}
          {summary.artifacts} artifact{summary.artifacts === 1 ? "" : "s"}
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
