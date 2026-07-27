import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/cn";
import type { ArtifactTile } from "./notebook-types";

type Props = {
  outputs: ArtifactTile[];
  className?: string;
};

function OutputCard({ a, index }: { a: ArtifactTile; index: number }) {
  const title = a.label || a.filename || `Output ${index + 1}`;
  const isShare =
    a.role === "share" ||
    /share/i.test(String(a.label || "")) ||
    /\.txt$/i.test(String(a.filename || ""));
  return (
    <div className="flex h-full min-h-0 flex-col rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold">{title}</span>
        {isShare ? (
          <Badge variant="secondary" className="normal-case tracking-normal">
            share
          </Badge>
        ) : null}
        {a.sensitive ? (
          <Badge variant="warn" className="normal-case tracking-normal">
            sensitive
          </Badge>
        ) : null}
      </div>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all font-mono text-xs leading-relaxed">
        {a.content.slice(0, 4000)}
        {a.content.length > 4000 ? "…" : ""}
      </pre>
    </div>
  );
}

/**
 * One artifact: stacked card. Several (e.g. SSS shares): horizontal snap slider
 * so the notebook keeps vertical real estate.
 */
export function OutputCarousel({ outputs, className }: Props) {
  const scrollerRef = useRef<HTMLDivElement>(null);
  const [index, setIndex] = useState(0);

  const syncIndex = useCallback(() => {
    const el = scrollerRef.current;
    if (!el || !outputs.length) return;
    const w = el.clientWidth || 1;
    const i = Math.round(el.scrollLeft / w);
    setIndex(Math.max(0, Math.min(outputs.length - 1, i)));
  }, [outputs.length]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    el.addEventListener("scroll", syncIndex, { passive: true });
    return () => el.removeEventListener("scroll", syncIndex);
  }, [syncIndex]);

  useEffect(() => {
    setIndex(0);
    const el = scrollerRef.current;
    if (el) el.scrollTo({ left: 0 });
  }, [outputs]);

  const go = (dir: -1 | 1) => {
    const el = scrollerRef.current;
    if (!el) return;
    const next = Math.max(0, Math.min(outputs.length - 1, index + dir));
    el.scrollTo({ left: next * el.clientWidth, behavior: "smooth" });
    setIndex(next);
  };

  if (!outputs.length) return null;

  if (outputs.length === 1) {
    return (
      <div className={cn("border-t border-[var(--border)] pt-3", className)}>
        <OutputCard a={outputs[0]} index={0} />
      </div>
    );
  }

  return (
    <div className={cn("border-t border-[var(--border)] pt-3", className)}>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-xs font-semibold text-[var(--muted-foreground)]">
          Outputs
        </span>
        <Badge variant="secondary" className="normal-case tracking-normal">
          {index + 1} / {outputs.length}
        </Badge>
        <div className="ml-auto flex gap-1">
          <Button
            type="button"
            size="icon"
            variant="outline"
            className="h-7 w-7"
            disabled={index <= 0}
            aria-label="Previous output"
            onClick={(e) => {
              e.stopPropagation();
              go(-1);
            }}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            type="button"
            size="icon"
            variant="outline"
            className="h-7 w-7"
            disabled={index >= outputs.length - 1}
            aria-label="Next output"
            onClick={(e) => {
              e.stopPropagation();
              go(1);
            }}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div
        ref={scrollerRef}
        className="flex max-h-56 snap-x snap-mandatory overflow-x-auto scroll-smooth [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {outputs.map((a, ai) => (
          <div
            key={ai}
            className="w-full shrink-0 snap-center snap-always px-0.5"
            aria-hidden={ai !== index}
          >
            <OutputCard a={a} index={ai} />
          </div>
        ))}
      </div>

      <div className="mt-2 flex justify-center gap-1.5">
        {outputs.map((_, ai) => (
          <button
            key={ai}
            type="button"
            aria-label={`Go to output ${ai + 1}`}
            className={cn(
              "h-1.5 w-1.5 rounded-full transition-colors",
              ai === index
                ? "bg-[var(--brand)]"
                : "bg-[color-mix(in_srgb,var(--border)_80%,var(--text-muted))]"
            )}
            onClick={(e) => {
              e.stopPropagation();
              const el = scrollerRef.current;
              if (!el) return;
              el.scrollTo({ left: ai * el.clientWidth, behavior: "smooth" });
              setIndex(ai);
            }}
          />
        ))}
      </div>
    </div>
  );
}
