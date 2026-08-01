import { useState } from "react";
import { cn } from "@/lib/cn";
import { packetSummary } from "../../lib/toolkit/artifact-readouts.js";

/**
 * The ciphertext / envelope read-out (§37b, design_handoff_artifact_actions).
 *
 * An armored OpenPGP message rendered as armor is a wall of base64 that tells
 * you nothing about itself. Its *framing* is in the clear, though, and the
 * framing is what a reader wants: how many recipients could open it, whether
 * a passphrase was involved (SKESK) rather than a key (PKESK), whether it was
 * signed, and how big the sealed body is.
 *
 * This is the shape §37a's corollary predicts. "Decrypt with…" was rejected as
 * an action because it computes a new value; "inspect packets" was rejected as
 * an action because it is not a button at all — it is what the tile should
 * already show. Nothing here needs a key, and nothing here is a verdict.
 *
 * The armor is one toggle away, not taken away.
 */
export function PacketMapCard({
  content,
  className,
}: {
  content: string;
  className?: string;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const summary = packetSummary(content);
  if (!summary) return null;

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-packet-map>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {summary.rows.map((row, i) => (
          <span
            key={`${row.tag}-${i}`}
            className="flex items-baseline gap-1 rounded-[3px] bg-[color-mix(in_srgb,var(--caret)_var(--tile-tint),transparent)] px-1.5 py-px"
          >
            <span className="font-mono text-[10px] font-semibold text-[var(--foreground)]">
              {row.name}
            </span>
            <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
              {row.bytes} B
            </span>
          </span>
        ))}
        <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
          {summary.rows.length} packet{summary.rows.length === 1 ? "" : "s"} ·{" "}
          {summary.bytes} B
        </span>
      </div>

      <div className="flex flex-col gap-1">
        <button
          type="button"
          className="self-start text-[10px] text-[var(--brand)] underline"
          onClick={() => setShowRaw((v) => !v)}
        >
          {showRaw ? "hide armor" : "armor"}
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
