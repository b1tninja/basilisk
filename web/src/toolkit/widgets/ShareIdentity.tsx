import { cn } from "@/lib/cn";
import { shareIdentity } from "../../lib/toolkit/artifact-readouts.js";

/**
 * What a masked share tile can say about itself (§33e/§37b).
 *
 * A share tile is masked, correctly and by default, and until now that meant
 * it said "sensitive — value not shown" and nothing more. So the one question
 * a custodian holding three tiles actually has — *which* share is this, and how
 * many of them recover the secret — could only be answered by revealing a
 * secret in order to read a number that is not one.
 *
 * Both facts are public: they are printed on the card, said aloud in the room,
 * and recorded in the split's own commitments. Neither derives from the masked
 * material, which is precisely what §34b's rule asks of anything drawn on a
 * masked tile — the mask is about where a value lands, not about how nervous
 * the tile is.
 *
 * This is a `publicView` only. The kind declares no `view`, so a *revealed*
 * share still renders through the tile's own text path, keeping its format
 * bar, its Hide button and its auto-hide timer. A widget that redrew the body
 * would have quietly taken all three away — the share's value is its own
 * words, and the tile already renders words well.
 */
export function ShareIdentity({
  artifact,
  className,
}: {
  artifact: {
    shareIndex?: number;
    tags?: string[];
    traits?: { shareOf?: number; threshold?: number };
  };
  className?: string;
}) {
  const id = shareIdentity(artifact);
  if (!id) return null;
  return (
    <span
      className={cn("flex flex-wrap items-baseline gap-x-2", className)}
      data-share-identity
    >
      {id.index ? (
        <span className="font-mono text-[11px] font-semibold text-[var(--foreground)]">
          Share {id.index}
        </span>
      ) : null}
      {id.threshold ? (
        <span className="text-[10px] text-[var(--muted-foreground)]">
          {id.threshold} shares recover the secret
        </span>
      ) : null}
      {id.flavour ? (
        <span className="font-mono text-[9px] text-[var(--muted-foreground)]">
          {id.flavour}
        </span>
      ) : null}
    </span>
  );
}
