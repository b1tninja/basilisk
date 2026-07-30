import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/cn";
import { NetworkArtifact, hasNetworkRenderer } from "./NetworkArtifact";
import { InspectorArtifact, type InspectSnapshot } from "./InspectorArtifact";
import {
  bytesToBase32,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
} from "../../lib/toolkit/encode.js";

/** One cell-output artifact row (design v2 §20h/21b/22b). */
export type OutputArtifact = {
  /** Slot / filename / label shown in mono — e.g. "ciphertext", "signature.asc". */
  label: string;
  /** Value kind badge — "text", "bytes", "key"… uppercased in the row. */
  kind: string;
  sizeBytes: number;
  sensitive?: boolean;
  onCopy: () => void;
  /** True only for key-export rows — the sole publishable output kind (§21b). */
  publishable?: boolean;
  /** Confirm-popover label, e.g. a short fingerprint ("3F2A…C81"). */
  publishConfirmLabel?: string;
  /** Publish action — called only after the confirm popover is accepted. */
  onPublish?: () => void | Promise<void>;
  /** Slot this artifact was already published to — replaces the Publish button. */
  publishedAs?: string;
  /** Directory URL once published — the row's link icon copies this. */
  directoryUrl?: string;
  /** One-shot diagnostic action (§22b) — e.g. stun.check's "Configure TURN". */
  diagnosticAction?: { label: string; onClick: () => void };
  /**
   * One-line content preview, truncated by the caller — shown directly under
   * the row (and as the row's hover title). Omit for sensitive artifacts;
   * the row shows "sensitive — value not shown" instead, matching the Slots
   * tray's convention for secret values.
   */
  preview?: string;
  /**
   * Network/WebRTC artifacts (design v2 §23a/23b/29d/30d) render as a manager
   * widget instead of a JSON preview — the pipeline type picks the renderer.
   */
  netType?: string;
  netKind?: string;
  netData?: unknown;
  /** Structured `inspect` body — renders as a typed inspector, not text. */
  inspectSnapshot?: unknown;
  /** Full serialized content, for types that are text on the wire (SDP). */
  content?: string;
  /**
   * Whether a sensitive value may be unmasked on request. Set by the engine
   * only for tiles a user explicitly asked to see (`out`, `text`, `inspect`);
   * incidental tiles omit it and stay masked, so nothing is exposed implicitly.
   */
  revealable?: boolean;
  /** 22b — wired through to the pair matrix's all-failed CTA. */
  onConfigureTurn?: () => void;
};

type Props = {
  outputs: OutputArtifact[];
  className?: string;
};

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Cell outputs — a vertical stack of artifact rows; outputs are usually all
 * wanted at once, so no paging (design v2 §20h, replaces OutputCarousel).
 * An already-published row shows its @slot instead of Publish, so it can't
 * be republished by accident.
 */
/** Representations an artifact can be re-rendered in, after the fact. */
export const ARTIFACT_FORMATS = ["raw", "hex", "base64", "base64url", "base32"] as const;
export type ArtifactFormat = (typeof ARTIFACT_FORMATS)[number];

/**
 * Re-encode an artifact's content for display.
 *
 * Representation is a *view* concern once the value has been computed — the
 * pipeline already decided the bytes, and looking at them as hex rather than
 * base64 should not require editing and re-running the recipe. `raw` is
 * whatever the step produced; the rest re-encode the UTF-8 bytes of that text.
 *
 * Returns null when the content cannot be reinterpreted, so the caller can
 * fall back to `raw` rather than render an error.
 */
export function formatArtifact(content: string, format: ArtifactFormat): string | null {
  if (format === "raw") return content;
  try {
    const bytes = new TextEncoder().encode(content);
    if (format === "hex") return bytesToHex(bytes);
    if (format === "base64") return bytesToBase64(bytes);
    if (format === "base64url") return bytesToBase64Url(bytes);
    if (format === "base32") return bytesToBase32(bytes);
    return null;
  } catch {
    return null;
  }
}

/** Segmented alphabet picker for one artifact row. */
function FormatBar({
  value,
  onChange,
}: {
  value: ArtifactFormat;
  onChange: (f: ArtifactFormat) => void;
}) {
  return (
    <span role="tablist" aria-label="Display format" className="flex gap-px">
      {ARTIFACT_FORMATS.map((f) => (
        <button
          key={f}
          type="button"
          role="tab"
          aria-selected={f === value}
          className={cn(
            "rounded-[3px] px-1 py-px font-mono text-[9px] transition-colors",
            f === value
              ? "bg-[color-mix(in_srgb,var(--brand)_18%,transparent)] font-semibold text-[var(--brand)]"
              : "text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          )}
          onClick={() => onChange(f)}
        >
          {f}
        </button>
      ))}
    </span>
  );
}

export function OutputList({ outputs, className }: Props) {
  const [confirming, setConfirming] = useState<number | null>(null);
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
  const expandedRow = expanded != null ? outputs[expanded] : null;
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
        <div
          key={`${a.label}-${i}`}
          className={cn(
            "relative flex flex-col gap-1 px-2.5 py-2",
            i < outputs.length - 1 && "border-b border-[color-mix(in_srgb,var(--border)_55%,transparent)]"
          )}
        >
        <div className="flex items-center gap-2.5" title={a.preview}>
          <span
            className={cn(
              "shrink-0 rounded-[3px] px-[5px] py-[2px] text-[9px] font-medium uppercase tracking-wider",
              a.kind === "diag"
                ? "bg-[color-mix(in_srgb,var(--warn)_12%,transparent)] text-[var(--warn)]"
                : a.kind === "key"
                  ? "bg-[color-mix(in_srgb,var(--brand)_12%,transparent)] text-[var(--brand)]"
                  : "bg-[color-mix(in_srgb,var(--caret)_12%,transparent)] text-[var(--caret)]"
            )}
          >
            {a.kind}
          </span>
          <code className="min-w-0 flex-1 truncate font-mono text-[11px] font-medium text-[var(--foreground)]">
            {a.label}
          </code>
          {a.sensitive ? (
            <Badge variant="warn" className="normal-case tracking-normal">
              sensitive
            </Badge>
          ) : null}
          {a.diagnosticAction ? (
            <Button
              size="sm"
              className="h-[22px] shrink-0 rounded-[5px] bg-[var(--warn)] px-2 text-[10px] font-bold text-[#1a1405] hover:opacity-90"
              onClick={(e) => {
                e.stopPropagation();
                a.diagnosticAction?.onClick();
              }}
            >
              {a.diagnosticAction.label}
            </Button>
          ) : null}
          <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
            {fmtSize(a.sizeBytes)}
          </span>
          {hasNetworkRenderer(a.netType) ? (
            <Button
              size="sm"
              variant="secondary"
              className="h-[22px] shrink-0 rounded-[5px] px-2 text-[10px]"
              onClick={(e) => {
                e.stopPropagation();
                setExpanded(i);
              }}
            >
              Expand
            </Button>
          ) : null}
          <Button
            size="sm"
            variant="secondary"
            className="h-[22px] shrink-0 rounded-[5px] px-2 text-[10px]"
            onClick={(e) => {
              e.stopPropagation();
              a.onCopy();
            }}
          >
            Copy
          </Button>
          {a.publishedAs ? (
            <span className="flex shrink-0 items-center gap-1">
              <code className="font-mono text-[10px] text-[var(--brand)]">{a.publishedAs}</code>
              {a.directoryUrl ? (
                <button
                  type="button"
                  className="text-[10px] text-[var(--muted-foreground)] hover:text-[var(--brand)]"
                  aria-label="Copy directory link"
                  title="Copy directory link"
                  onClick={(e) => {
                    e.stopPropagation();
                    void navigator.clipboard.writeText(a.directoryUrl!);
                  }}
                >
                  🔗
                </button>
              ) : null}
            </span>
          ) : a.publishable && a.onPublish ? (
            <>
              <Button
                size="sm"
                className="h-[22px] shrink-0 rounded-[5px] bg-[var(--brand)] px-2 text-[10px] font-bold text-[var(--on-brand)] hover:opacity-90"
                onClick={(e) => {
                  e.stopPropagation();
                  setConfirming(i);
                }}
              >
                Publish
              </Button>
              {confirming === i ? (
                <div
                  className="absolute right-2 top-full z-10 mt-1 w-[280px] rounded-[9px] border border-[var(--border)] bg-[var(--surface)] p-[10px] shadow-[0_10px_24px_rgba(0,0,0,.4)]"
                  onClick={(e) => e.stopPropagation()}
                >
                  <p className="mb-2 text-[11px] leading-[1.5] text-[var(--foreground)]">
                    Publish as{" "}
                    <code className="text-[var(--muted-foreground)]">
                      {a.publishConfirmLabel || a.label}
                    </code>
                    ? Anyone with directory access can fetch it.
                  </p>
                  <div className="flex justify-end gap-1.5">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-[24px] rounded-[5px] px-2.5 text-[10.5px]"
                      onClick={() => setConfirming(null)}
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      className="h-[24px] rounded-[5px] bg-[var(--brand)] px-2.5 text-[10.5px] font-bold text-[var(--on-brand)] hover:opacity-90"
                      onClick={() => {
                        setConfirming(null);
                        void a.onPublish?.();
                      }}
                    >
                      Publish
                    </Button>
                  </div>
                </div>
              ) : null}
            </>
          ) : null}
        </div>
          {a.sensitive && !revealed.has(a.label) ? (
            <span className="flex items-center gap-2 pl-[1px]">
              <span className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
                sensitive — value not shown
              </span>
              {/* Only tiles produced by an explicit `out` / `text` / `inspect`
                  offer this. A value that merely passed through was never
                  asked to be displayed, so there is nothing to reveal. */}
              {a.revealable && a.content ? (
                <button
                  type="button"
                  className="rounded-[4px] border border-[color-mix(in_srgb,var(--warn)_45%,transparent)] px-1.5 py-px text-[10px] font-semibold text-[var(--warn)] hover:bg-[color-mix(in_srgb,var(--warn)_12%,transparent)]"
                  title="Show this value in the clear"
                  onClick={() =>
                    setRevealed((prev) => new Set(prev).add(a.label))
                  }
                >
                  Reveal
                </button>
              ) : null}
            </span>
          ) : hasNetworkRenderer(a.netType) ? (
            <NetworkArtifact
              netType={a.netType!}
              netKind={a.netKind}
              data={a.netData}
              content={a.content}
              onConfigureTurn={a.onConfigureTurn}
            />
          ) : a.inspectSnapshot ? (
            /* `inspect` carries a structured snapshot — render the value as
               what it is, rather than the flattened text dump. */
            <InspectorArtifact
              snapshot={a.inspectSnapshot as InspectSnapshot}
              className="mt-0.5"
            />
          ) : a.content ? (
            <span className="flex flex-col gap-1 pl-[1px]">
              <span className="flex items-center gap-2">
                <FormatBar
                  value={formats[a.label] || "raw"}
                  onChange={(f) =>
                    setFormats((prev) => ({ ...prev, [a.label]: f }))
                  }
                />
                {a.sensitive ? (
                  <button
                    type="button"
                    className="rounded-[4px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] px-1.5 py-px text-[9px] font-semibold text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                    onClick={() =>
                      setRevealed((prev) => {
                        const next = new Set(prev);
                        next.delete(a.label);
                        return next;
                      })
                    }
                  >
                    Hide
                  </button>
                ) : null}
              </span>
              <code
                className={cn(
                  "block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px]",
                  a.sensitive
                    ? "text-[var(--foreground)]"
                    : "text-[var(--muted-foreground)]"
                )}
              >
                {formatArtifact(a.content, formats[a.label] || "raw") ?? a.content}
              </code>
            </span>
          ) : a.preview ? (
            <code className="truncate pl-[1px] font-mono text-[10px] text-[var(--muted-foreground)]">
              {a.preview}
            </code>
          ) : null}
        </div>
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
          {expandedRow && hasNetworkRenderer(expandedRow.netType) ? (
            <div className="overflow-y-auto px-4 pb-4">
              <NetworkArtifact
                netType={expandedRow.netType!}
                netKind={expandedRow.netKind}
                data={expandedRow.netData}
                content={expandedRow.content}
                onConfigureTurn={expandedRow.onConfigureTurn}
              />
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
