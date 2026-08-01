import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { cn } from "@/lib/cn";
import { KindGlyph } from "./kind-glyphs";
import { ArtifactAction } from "./ArtifactAction";
import { actionsFor } from "../../lib/toolkit/artifact-actions.js";
import {
  ARTIFACT_KINDS,
  FALLBACK_KIND,
  type ToolkitArtifactKind,
} from "../artifact-kinds/registry";
import { resolveArtifactKind } from "../artifact-kinds/resolve";
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
  /**
   * What the artifact *is* — the identity the kind registry matches on (§32b).
   *
   * Distinct from `kind` above, which is the badge string. These were missing
   * from this type, so the resolver saw role-less objects and every artifact
   * fell through to the fallback kind in the live UI, while an engine-backed
   * test resolved real artifacts and passed. A mapped-shape gap between the
   * two is invisible to both ends unless something carries it.
   */
  role?: string;
  tags?: string[];
  traits?: Record<string, unknown>;
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
  /**
   * JOSE body from a `jose.*` op — renders as the JWT reader rather than a
   * base64url blob. Carries the op's verification verdict, which the UI
   * cannot re-derive from the token text.
   */
  jose?: unknown;
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

/**
 * Whether a row has enough body to be worth its own window (§32c).
 *
 * Expand was originally network-only, but a keypair inspector body or a large
 * hexdump has exactly the same problem — too much value for a list row. The
 * threshold is deliberately generous: below it, the inline body is already
 * fully readable and a window would be ceremony.
 */
const EXPANDABLE_CONTENT_CHARS = 512;

export function canExpand(a: OutputArtifact): boolean {
  // §32d: expandability is a property of the *kind*, declared in the table,
  // not a third list of body-shape predicates kept in sync by hand. Falling
  // back to the size rule is what an unclaimed artifact gets.
  const kind = resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND);
  if (kind.expandable) return true;
  return (a.content?.length ?? 0) > EXPANDABLE_CONTENT_CHARS;
}

/**
 * How long a revealed secret stays visible before re-masking (§32c).
 *
 * There is no honest way to detect screen sharing — the Screen Capture API
 * only tells a page about its *own* capture — so a timeout is the real
 * mitigation rather than a reassuring indicator that cannot be backed up.
 */
export const REVEAL_TIMEOUT_MS = 15000;

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
              ? "bg-[color-mix(in_srgb,var(--brand)_var(--tile-tint),transparent)] font-semibold text-[var(--brand)]"
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

/**
 * Render a kind's body, degrading rather than blanking a cell (§32d).
 *
 * A view parses data the engine handed it, so a malformed body must fall back
 * to the raw text path — the tile below renders `a.content` when this returns
 * null. Throwing here would convert a computation that succeeded into a
 * user-visible failure, which inverts the severity.
 */
function renderKindView(
  kind: ToolkitArtifactKind,
  artifact: Parameters<ToolkitArtifactKind["view"]>[0]["artifact"],
  masked: boolean
) {
  try {
    // §33e/§35d: while masked, only a kind's declared `publicView` may draw —
    // the body it renders derives solely from public material. Without one,
    // a masked tile shows nothing but the masked line, as before. The full
    // `view` never runs on a masked value; that is the mask, not a styling
    // choice.
    const render = masked ? kind.publicView : kind.view;
    return render ? render({ artifact, masked }) : null;
  } catch {
    return null;
  }
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
      {outputs.map((a, i) => {
        // §32e: one resolver call, computed once. The kind is decided by the
        // artifact's identity; `kindBody` is null when this kind has no body
        // to draw, and the raw path below renders instead.
        const resolvedKind = resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND);
        const kindBody = renderKindView(resolvedKind, a, false);
        return (
        <div
          key={`${a.label}-${i}`}
          data-artifact-kind={resolvedKind.id}
          className={cn(
            "relative flex flex-col gap-1 px-2.5 py-2",
            i < outputs.length - 1 && "border-b border-[color-mix(in_srgb,var(--border)_55%,transparent)]"
          )}
        >
        <div className="flex items-center gap-2.5" title={a.preview}>
          {/* §35 — glyph in front of the existing label. `a.kind` is already
              the lookup key, so no new prop; the same map backs TypeCard and
              the Types shelf so one kind never shows two icons. */}
          <span
            className={cn(
              "inline-flex shrink-0 items-center gap-1 rounded-[3px] px-[5px] py-[2px] text-[9px] font-medium uppercase tracking-wider",
              a.kind === "diag"
                ? "bg-[color-mix(in_srgb,var(--warn)_var(--tile-tint),transparent)] text-[var(--warn)]"
                : a.kind === "key"
                  ? "bg-[color-mix(in_srgb,var(--brand)_var(--tile-tint),transparent)] text-[var(--brand)]"
                  : "bg-[color-mix(in_srgb,var(--caret)_var(--tile-tint),transparent)] text-[var(--caret)]"
            )}
          >
            <KindGlyph kind={a.kind} />
            {a.kind}
          </span>
          <code className="artifact-label min-w-0 flex-1 truncate font-mono font-medium text-[var(--foreground)]">
            {a.label}
          </code>
          {a.sensitive ? (
            <Badge variant="warn" className="normal-case tracking-normal">
              sensitive
            </Badge>
          ) : null}
          <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
            {fmtSize(a.sizeBytes)}
          </span>
        </div>

        {/* §36a — actions on their own line. The identity line above answers
            "what is this"; this one answers "what can I do to it". Eight
            controls sharing one flex row gave a plain text artifact the same
            visual weight as a publishable key with five affordances. */}
        <div className="flex flex-wrap items-center gap-1.5">
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
          {canExpand(a) ? (
            <ArtifactAction label="Expand" tier="inert" onClick={() => setExpanded(i)} />
          ) : null}
          {/* §33c: the kind names its actions, the table defines them once,
              and this row renders them. "Copy" gates the same way on every
              tile because there is only one Copy — the churn this whole
              abstraction exists to stop is each tile growing its own. */}
          {actionsFor(resolvedKind).map((action) => {
            const ctx = {
              artifact: a,
              kind: resolvedKind,
              masked: !!a.sensitive && !revealed.has(a.label),
              services: {
                // The existing handler, not a re-implementation: it fires the
                // shipped clipboard toast and knows this artifact's own
                // serialization. The table makes its *gating* uniform.
                copyArtifact: () => a.onCopy(),
                clipboard: { write: (t: string) => navigator.clipboard.writeText(t) },
              },
            };
            const availability = action.available(ctx);
            const reason =
              availability === true ? undefined : availability.disabled;
            return (
              <ArtifactAction
                key={action.id}
                label={action.label}
                tier={action.tier}
                reason={reason}
                onClick={() => {
                  void Promise.resolve(action.run(ctx)).catch(() => {
                    /* the action's own error surface is the next increment;
                       a rejected copy must not take the tile down. */
                  });
                }}
              />
            );
          })}
          {a.publishedAs ? (
            <span className="flex shrink-0 items-center gap-1">
              <code className="artifact-meta font-mono text-[var(--brand)]">{a.publishedAs}</code>
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
            <span className="flex flex-col gap-1 pl-[1px]">
              {/* §35d: a masked private key is no longer a blank tile — its
                  algorithm, fingerprint and public line are public facts. */}
              {renderKindView(resolvedKind, a, true)}
              <span className="flex items-center gap-2">
              <span className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
                sensitive — value not shown
              </span>
              {/* Only tiles produced by an explicit `out` / `text` / `inspect`
                  offer this. A value that merely passed through was never
                  asked to be displayed, so there is nothing to reveal. */}
              {a.revealable && a.content ? (
                <button
                  type="button"
                  className="rounded-[4px] border border-[color-mix(in_srgb,var(--warn)_45%,transparent)] px-1.5 py-px text-[10px] font-semibold text-[var(--warn)] hover:bg-[color-mix(in_srgb,var(--warn)_var(--tile-tint),transparent)]"
                  title="Show this value in the clear"
                  onClick={() =>
                    setRevealed((prev) => new Set(prev).add(a.label))
                  }
                >
                  Reveal
                </button>
              ) : null}
              </span>
            </span>
          ) : kindBody ? (
            /* §32e: one resolver call where three bespoke predicates used to
               chain. The kind comes from the artifact's identity (role +
               tags), and the view reads the body — so a token whose body
               failed to decode is still a token showing its empty state,
               rather than falling through and rendering as untyped text.
               Reached only past the sensitive gate above, so a freshly signed
               value still masks until it is revealed. */
            kindBody
          ) : a.content ? (
            <span
              className="flex flex-col gap-1 pl-[1px]"
              /* Reading or reformatting a revealed value counts as still
                 looking at it, so the auto-hide timer restarts. */
              onMouseMove={a.sensitive ? keepRevealed : undefined}
              onFocus={a.sensitive ? keepRevealed : undefined}
            >
              <span className="flex items-center gap-2">
                <FormatBar
                  value={formats[a.label] || "raw"}
                  onChange={(f) => {
                    keepRevealed();
                    setFormats((prev) => ({ ...prev, [a.label]: f }));
                  }}
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
                  "artifact-body block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono",
                  a.sensitive
                    ? "text-[var(--foreground)]"
                    : "text-[var(--muted-foreground)]"
                )}
              >
                {formatArtifact(a.content, formats[a.label] || "raw") ?? a.content}
              </code>
            </span>
          ) : a.preview ? (
            <code className="artifact-body truncate pl-[1px] font-mono text-[var(--muted-foreground)]">
              {a.preview}
            </code>
          ) : null}
        </div>
        );
      })}

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
