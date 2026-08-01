import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { formatFingerprint } from "../../lib/utils.js";
import {
  openpgpKeyForm,
  openpgpKeySummary,
} from "../../lib/toolkit/artifact-readouts.js";

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
 * **This file no longer parses anything.** The armor parse was the largest
 * derivation still living inside a widget, and inside one it had no test: the
 * suite is `environment: "node"`, so nothing in it could reach a `useEffect`.
 * It is `openpgpKeySummary` now, and what is left here is layout — which is
 * the whole of the boundary stated in `artifact-readouts.js`'s header.
 *
 * The parse is lazy and its failure is ordinary. A malformed or truncated
 * armor renders the raw body with no card rather than an error tile: the
 * value came from a computation that succeeded, and our inability to
 * describe it is not the user's problem to debug (§32f's reasoning, applied
 * one level down).
 */
type Summary = Awaited<ReturnType<typeof openpgpKeySummary>>;

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
  const [parsed, setParsed] = useState<Summary>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    let live = true;
    openpgpKeySummary(content)
      .then((s) => {
        if (live) setParsed(s);
      })
      .catch(() => {
        if (live) setParsed(null);
      });
    return () => {
      live = false;
    };
  }, [content]);

  /**
   * The half, on the first frame and forever after.
   *
   * Synchronous, total, and the *same* derivation `openpgpKeySummary` reports
   * in `form` — it calls this — so the caption cannot disagree with the card
   * under it, which was the whole of the defect the previous fix worked around
   * by making the caption wait for a parse that may never land.
   */
  const form = openpgpKeyForm(content);

  const shownFingerprint = formatFingerprint(parsed?.fingerprint || fingerprint || "");

  return (
    <div className={cn("flex flex-col gap-1 pl-[1px]", className)} data-openpgp-card>
      <div className="flex items-baseline gap-2">
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          {parsed?.uid || "OpenPGP key"}
        </span>
        {/* Nothing rather than a guess, which is `KeyCard.half`'s rule applied
            one card over — but "nothing" is now only for armor that states
            neither half, not for every frame before a lazy import lands.

            This read `parsed?.isPrivate ? "private" : "public"`, and `parsed`
            is null for the whole of the `openpgp` import and permanently for a
            block that does not parse, so an OpenPGP *private* key captioned
            itself **public**: measured on the catalog's key section, the
            private row read "OpenPGP key · public · 5CDE D055 …" until the
            module landed. The first fix made the caption wait for the parse,
            which stopped it lying and left it silent on exactly the tiles that
            most need it. `openpgpKeyForm` is the derivation instead — the
            armor's own header, which states this for every key OpenPGP emits —
            and `openpgpKeySummary` calls the same function, so this is one
            source with two consumers rather than two sources for one fact. */}
        {form ? (
          <span className="text-[10px] text-[var(--muted-foreground)]" data-openpgp-form={form}>
            {form}
          </span>
        ) : null}
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
