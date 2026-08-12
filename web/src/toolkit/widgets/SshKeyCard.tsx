import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { Fingerprint } from "@/components/ui/fingerprint";
import { sshKeySummary } from "../../lib/toolkit/artifact-readouts.js";

type Summary = Awaited<ReturnType<typeof sshKeySummary>>;

/**
 * The SSH key read-out — the same three facts for both halves (§37b).
 *
 * `SshSigCard`'s shape, deliberately: key type and comment on the identity
 * line, the `SHA256:…` fingerprint under it in mono, and the wire form itself
 * one click away. A `.pub` line and an openssh-key-v1 block answer the same
 * three questions, so they get one card rather than two that would drift.
 *
 * **The fingerprint is the point.** It is what `ssh-keygen -lf` prints and
 * what GitHub shows beside a key, so it is the string you compare when you
 * want to know *which* key a tile is holding — a question a base64 line cannot
 * answer by being read.
 *
 * `withRaw` is how this card is safe on a masked tile. Every field above comes
 * off the public blob (§34b), so the kind mounts this as its `publicView` with
 * `withRaw={false}`: the private block itself is the one thing that must not
 * be one click away from a masked tile, and it is not rendered at all rather
 * than rendered behind a toggle that a stray click would open.
 */
export function SshKeyCard({
  content,
  withRaw = true,
  className,
}: {
  content: string;
  withRaw?: boolean;
  className?: string;
}) {
  const [summary, setSummary] = useState<Summary>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let live = true;
    sshKeySummary(content)
      .then((s) => {
        if (live) setSummary(s);
      })
      .catch(() => {
        if (live) setSummary(null);
      });
    return () => {
      live = false;
    };
  }, [content]);

  // A body that did not parse — a passphrase-protected block this build cannot
  // open, or armor that is not a key at all — draws nothing, and the tile
  // renders what it would have rendered anyway (§32d).
  if (!summary) return null;

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-ssh-key-card>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          {summary.keyType}
        </span>
        <span className="text-[10px] text-[var(--muted-foreground)]">
          {summary.form === "private" ? "private key" : "public line"}
          {summary.comment ? ` · ${summary.comment}` : ""}
        </span>
      </div>
      {/* The fingerprint is the point of this card, and it was the one thing on
          it a reader could not take with them. `<Fingerprint>` copies it
          verbatim — no grouping — because it is what `ssh-keygen -lf` prints and
          what an `allowed_signers` line is compared against character for
          character. The keyserver and trust rows refuse, and say that the
          keyserver holds OpenPGP keys. */}
      <Fingerprint
        className="artifact-body text-[var(--muted-foreground)]"
        fpr={summary.fingerprint}
      />
      {withRaw ? (
        <div className="flex flex-col gap-1">
          <button
            type="button"
            /* `artifact-inline-toggle` raises the box to the 22px the action
               row uses. It measured 16px — the smallest hit target on the
               page by 3px — for no reason but that it is a bare word rather
               than a button-shaped control. */
            className="artifact-inline-toggle self-start text-[10px] text-[var(--brand)] underline"
            onClick={() => setShowRaw((v) => !v)}
          >
            {showRaw
              ? "hide key"
              : summary.form === "private"
                ? "show block"
                : "show line"}
          </button>
          {showRaw ? (
            <code className="artifact-body block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-[var(--muted-foreground)]">
              {content}
            </code>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
