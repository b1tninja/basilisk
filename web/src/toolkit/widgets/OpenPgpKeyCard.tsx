import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";

/**
 * The OpenPGP key read-out (§35e, design_handoff_artifact_actions).
 *
 * An armored key is base64 packets — unreadable as text and actively
 * misleading as a "preview", because the first lines look identical for every
 * key ever generated. The one question a reader has of a public key is *whose
 * is this*, and the armor answers it only after parsing.
 *
 * So the card answers it: user id, fingerprint in grouped hex, and the
 * creation and expiry dates. The armor stays available underneath — nothing
 * is taken away, it stops being the only thing offered.
 *
 * The parse is lazy and its failure is ordinary. A malformed or truncated
 * armor renders the raw body with no card rather than an error tile: the
 * value came from a computation that succeeded, and our inability to
 * describe it is not the user's problem to debug (§32f's reasoning, applied
 * one level down).
 */
type Parsed = {
  uid: string;
  fingerprint: string;
  created: string;
  expires: string | null;
  isPrivate: boolean;
};

export function OpenPgpKeyCard({
  content,
  fingerprint,
  publicOnly = false,
  className,
}: {
  content: string;
  /** `traits.fingerprint` — shown immediately, before the parse resolves. */
  fingerprint?: string;
  publicOnly?: boolean;
  className?: string;
}) {
  const [parsed, setParsed] = useState<Parsed | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let live = true;
    const armored = String(content || "");
    if (!armored.includes("BEGIN PGP")) {
      setParsed(null);
      return;
    }
    (async () => {
      try {
        // Lazy: openpgp is a large module and most tiles are not keys.
        const { readKey } = await import("openpgp");
        const key = await readKey({ armoredKey: armored });
        const primary = await key.getPrimaryUser().catch(() => null);
        const exp = await key.getExpirationTime().catch(() => null);
        if (!live) return;
        setParsed({
          uid: primary?.user?.userID?.userID || "",
          fingerprint: key.getFingerprint().toUpperCase(),
          created: key.getCreationTime().toISOString().slice(0, 10),
          expires:
            exp instanceof Date && Number.isFinite(exp.getTime())
              ? exp.toISOString().slice(0, 10)
              : null,
          isPrivate: armored.includes("PRIVATE KEY BLOCK"),
        });
      } catch (_) {
        if (live) setParsed(null);
      }
    })();
    return () => {
      live = false;
    };
  }, [content]);

  const shownFingerprint = formatFingerprint(parsed?.fingerprint || fingerprint || "");

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-openpgp-card>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          {parsed?.uid || "OpenPGP key"}
        </span>
        <span className="text-[10px] text-[var(--muted-foreground)]">
          {parsed?.isPrivate ? "private" : "public"}
        </span>
      </div>

      {shownFingerprint ? (
        <code className="artifact-body block break-all font-mono text-[var(--muted-foreground)]">
          {shownFingerprint}
        </code>
      ) : null}

      {parsed ? (
        <span className="text-[10px] text-[var(--muted-foreground)]">
          created {parsed.created}
          {parsed.expires ? ` · expires ${parsed.expires}` : " · does not expire"}
        </span>
      ) : null}

      {publicOnly ? null : (
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
      )}
    </div>
  );
}
