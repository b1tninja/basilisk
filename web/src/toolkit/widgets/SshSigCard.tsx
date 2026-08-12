import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { Fingerprint } from "@/components/ui/fingerprint";
import { sshsigSummary } from "../../lib/toolkit/artifact-readouts.js";

type Summary = Awaited<ReturnType<typeof sshsigSummary>>;

/**
 * The sshsig read-out (§37b, design_handoff_artifact_actions).
 *
 * Three facts, decoded by the shipped `lib/ssh/sshsig.js` parser, and nothing
 * else. **Namespace** leads because it is the field that silently decides
 * whether a signature verifies: a `git` signature can never verify as a `file`
 * signature, and the armor gives no hint which one you are holding. The signer
 * is the `SHA256:…` form `ssh-keygen -lf` prints (§28a), so it can be compared
 * against an `allowed_signers` line character for character.
 *
 * There is deliberately **no verify button**. Verification needs a key and the
 * payload, and a tile has neither — the signature block outlived the run that
 * made it and the payload was never on it. That is `ssh.verify`, and §37a is
 * the rule that keeps it an op rather than a button that would have to guess
 * at both of its inputs.
 */
export function SshSigCard({
  content,
  className,
}: {
  content: string;
  className?: string;
}) {
  const [summary, setSummary] = useState<Summary>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let live = true;
    sshsigSummary(content)
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

  if (!summary) return null;

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-sshsig-card>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          namespace {summary.namespace || "(none)"}
        </span>
        <span className="text-[10px] text-[var(--muted-foreground)]">
          {summary.sigType}
          {summary.hashAlg ? ` · ${summary.hashAlg}` : ""}
        </span>
      </div>
      {/* Which key signed it, and now a control that hands the whole digest to
          whoever is checking an `allowed_signers` line against it. */}
      <Fingerprint
        className="artifact-body text-[var(--muted-foreground)]"
        fpr={summary.fingerprint}
      />
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
