import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/cn";
import {
  ArtifactTile,
  canExpand,
  renderKindView,
  type ArtifactFormat,
  type OutputArtifact,
} from "./ArtifactTile";
import { ARTIFACT_KINDS, FALLBACK_KIND } from "../artifact-kinds/registry";
import { resolveArtifactKind } from "../artifact-kinds/resolve";

/**
 * The tile's anatomy, its actions and its mask gate moved to `ArtifactTile`
 * (§33a). These re-exports are not compatibility shims kept out of politeness:
 * `OutputArtifact` is the shape both call sites and the catalog build, and
 * `canExpand` / `formatArtifact` are used to reason about a row from outside
 * one. Re-exporting keeps a single import path for callers while the anatomy
 * lives where it is rendered.
 */
export {
  ARTIFACT_FORMATS,
  formatArtifact,
  canExpand,
  type ArtifactFormat,
  type OutputArtifact,
} from "./ArtifactTile";

type Props = {
  outputs: OutputArtifact[];
  className?: string;
};

/**
 * How long a revealed secret stays visible before re-masking (§32c).
 *
 * There is no honest way to detect screen sharing — the Screen Capture API
 * only tells a page about its *own* capture — so a timeout is the real
 * mitigation rather than a reassuring indicator that cannot be backed up.
 */
export const REVEAL_TIMEOUT_MS = 15000;

/**
 * Cell outputs — a vertical stack of artifact tiles; outputs are usually all
 * wanted at once, so no paging (design v2 §20h, replaces OutputCarousel).
 *
 * What is left here after §33a is exactly what is *list*-scoped: the chrome,
 * the reveal set with its one shared auto-hide timer, the per-label format
 * map, and the Sheet. The timer is the reason the reveal state did not move
 * down into the tile — it re-masks every revealed row at once, and N tiles
 * each holding their own timer would be a different behaviour wearing the
 * same code.
 */
export function OutputList({ outputs, className }: Props) {
  const [expanded, setExpanded] = useState<number | null>(null);
  /**
   * Labels the user has deliberately unmasked, and the alphabet each row is
   * being shown in. Both are view state, held here and never persisted: a
   * reveal lasts as long as you are looking at it, and re-running the cell
   * re-masks. Keyed by label rather than index so a row keeps its state when
   * the list around it changes.
   */
  const [revealed, setRevealed] = useState<Set<string>>(() => new Set());
  const [formats, setFormats] = useState<Record<string, ArtifactFormat>>({});
  /**
   * Bumped by any interaction with a revealed row; the auto-hide timer keys
   * off it, so reading or reformatting a value keeps it open and walking away
   * re-masks it.
   */
  const [revealTouch, setRevealTouch] = useState(0);
  const keepRevealed = () => setRevealTouch((n) => n + 1);

  useEffect(() => {
    if (!revealed.size) return undefined;
    const t = setTimeout(() => setRevealed(new Set()), REVEAL_TIMEOUT_MS);
    return () => clearTimeout(t);
  }, [revealed, revealTouch]);
  const expandedRow = expanded != null ? outputs[expanded] : null;
  // The Sheet shows the same widget the row does, given room — never a second
  // rendering of the same value. Masked here means masked there.
  const expandedKindBody = expandedRow
    ? renderKindView(
        resolveArtifactKind(expandedRow, ARTIFACT_KINDS, FALLBACK_KIND),
        expandedRow,
        !!expandedRow.sensitive && !revealed.has(expandedRow.label)
      )
    : null;
  if (!outputs.length) return null;
  return (
    <div
      className={cn(
        "rounded-[10px] border border-[var(--border)] bg-[var(--surface)] p-1",
        className
      )}
      data-output-list
    >
      {outputs.map((a, i) => (
        <ArtifactTile
          key={`${a.label}-${i}`}
          artifact={a}
          divided={i < outputs.length - 1}
          revealed={revealed.has(a.label)}
          onReveal={() => setRevealed((prev) => new Set(prev).add(a.label))}
          onHide={() =>
            setRevealed((prev) => {
              const next = new Set(prev);
              next.delete(a.label);
              return next;
            })
          }
          onKeepRevealed={keepRevealed}
          format={formats[a.label] || "raw"}
          onFormatChange={(f) => setFormats((prev) => ({ ...prev, [a.label]: f }))}
          onExpand={canExpand(a) ? () => setExpanded(i) : undefined}
        />
      ))}

      {/* An artifact can also open as its own window — the same widget, given
          room to breathe, using the shell's existing Sheet primitive. */}
      <Sheet open={expanded != null} onOpenChange={(o) => !o && setExpanded(null)}>
        <SheetContent side="right" className="w-[min(560px,100vw)] sm:max-w-none">
          <SheetHeader>
            <SheetTitle className="font-mono text-[13px]">
              {expandedRow?.label}
              {expandedRow?.netType ? (
                <span className="ml-2 text-[10px] font-normal uppercase tracking-wider text-[var(--muted-foreground)]">
                  {expandedRow.netType}
                  {expandedRow.netKind ? ` · ${expandedRow.netKind}` : ""}
                </span>
              ) : null}
            </SheetTitle>
          </SheetHeader>
          {expandedRow ? (
            <div className="overflow-y-auto px-4 pb-4">
              {/* Same widget the row uses, given room — never a second
                  rendering of the same value. */}
              {expandedKindBody ? (
                expandedKindBody
              ) : (
                <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--foreground)]">
                  {expandedRow.sensitive && !revealed.has(expandedRow.label)
                    ? "sensitive — value not shown"
                    : expandedRow.content}
                </pre>
              )}
              <Button
                size="sm"
                variant="secondary"
                className="mt-3 h-[24px] rounded-[5px] px-2.5 text-[10.5px]"
                onClick={() => expandedRow.onCopy()}
              >
                Copy raw
              </Button>
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}
