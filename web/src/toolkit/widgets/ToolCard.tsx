import {
  TOOLBOX_META,
  getShelfMeta,
  type ParamSpec,
  type StepSpec,
} from "../../lib/toolkit/registry.js";
import { specInputNeeds } from "../../lib/toolkit/input-needs.js";
import { decodeTwinToken } from "../../lib/toolkit/step-names.js";
import { docsUrlFor } from "../../lib/toolkit/step-docs.js";
import { cn } from "@/lib/cn";
import { Glyph, glyphIdFor } from "./Glyph";

/**
 * Tool card / ops-drawer view of a registry StepSpec (`getStep` / `listSteps`).
 * Not a parallel param schema — use registry ParamSpec fields as-is.
 */
export type ToolCardOp = StepSpec;

type Props = {
  op: ToolCardOp;
  decode?: boolean;
  /** Compact hover / chip-pop layout. */
  compact?: boolean;
  /** Pinned docs panel — brand border, stays open while editing elsewhere (§19f). */
  pinned?: boolean;
  /** Close button for the pinned panel. */
  onClose?: () => void;
  className?: string;
};

const KIND_LABEL: Record<string, string> = {
  source: "Sources",
  transform: "Transforms",
  sink: "Outputs",
  flow: "Flow control",
};

function paramTypeBits(p: ParamSpec): string {
  const typeBits = [p.type];
  // `type` names the value kind and nothing else now, so the card has to say
  // how the value may arrive. It used to fall out of `type: "slot"` — which is
  // exactly why the value kind of 36 params went unwritten.
  if (p.slot === "required") typeBits.push("$slot");
  else if (p.slot) typeBits.push("literal or $slot");
  if (p.positional) typeBits.push("positional");
  if (p.flag) typeBits.push(p.flag);
  if (p.serialize === "always") typeBits.push("serialize always");
  if (p.enum?.length) typeBits.push(p.enum.join(" · "));
  // `default ""` printed as `default ` with nothing after it — the one default
  // that changes behaviour invisibly, described invisibly. `emptyMeans` is the
  // registry's phrase for what blank actually does, and it is the same string
  // the field's placeholder and hint show.
  else if (p.default === "" && p.emptyMeans) typeBits.push(`empty → ${p.emptyMeans}`);
  else if (p.default !== undefined && p.default !== null && p.default !== "")
    typeBits.push(`default ${String(p.default)}`);
  return typeBits.join(" · ");
}

/**
 * Reference-link footer (§31d) — one quiet line pointing at the spec page the
 * op wraps. Shared so the tool card and the inline param editor cannot drift;
 * renders nothing for ops with no single canonical page (composites like
 * `gpg.encrypt`), which is why it is safe to drop in unconditionally.
 */
export function DocsFooter({ op, className }: { op: { name?: string } | string; className?: string }) {
  const ref = docsUrlFor(op);
  if (!ref) return null;
  return (
    <p className={cn("text-xs", className)}>
      <a
        href={ref.url}
        target="_blank"
        rel="noreferrer noopener"
        className="inline-flex items-center gap-1 text-[var(--brand)] hover:underline"
        title={ref.url}
      >
        <span aria-hidden="true">↗</span>
        {ref.label}
      </a>
    </p>
  );
}

/** Standard tool card — docs, kind, I/O types, params. Redesigned with uniform widget system. */
export function ToolCard({
  op,
  decode = false,
  compact = false,
  pinned = false,
  onClose,
  className,
}: Props) {
  const io = op.effectiveIo
    ? op.effectiveIo(decode ? { decode: true } : {})
    : { input: op.input || "?", output: op.output || "?" };
  const display = op.label || op.name;
  const nameLabel = op.decodeTwin
    ? decodeTwinToken(op, decode)
    : decode
      ? `${display} -d`
      : display;
  const recipeTok = op.decodeTwin
    ? decodeTwinToken(op, decode)
    : `${op.name}${decode ? " -d" : ""}`;
  const tb = op.toolbox || "io";
  const tbMeta = (TOOLBOX_META as Record<string, { badge?: string; label?: string }>)[tb] || {
    badge: tb,
    label: tb,
  };
  const shelf = op.shelf ? getShelfMeta(op.shelf).label : "";
  const kindLabel = KIND_LABEL[op.kind || ""] || op.kind || "op";
  const params = op.params || [];
  const shown = params.slice(0, compact ? 4 : 8);
  const docLead = compact
    ? String(op.doc || "")
        .replace(/\s*Example:[\s\S]*$/i, "")
        .replace(/\s*Also accepts[\s\S]*$/i, "")
        .trim()
    : op.doc;

  return (
    <div
      className={cn(
        "tool-card rounded-lg border bg-[var(--surface)] transition-all",
        pinned ? "border-[var(--brand)]" : "border-[var(--border)]",
        compact && "tool-card-compact",
        className
      )}
      data-dir={decode ? "decode" : "encode"}
      data-pinned={pinned || undefined}
    >
      {/* Header: glyph + title + metadata row */}
      <header className="flex gap-3 border-b border-[var(--border)] p-3.5">
        <Glyph
          id={glyphIdFor(op)}
          size={compact ? 18 : 20}
          className="mt-0.5 text-[var(--foreground)]"
        />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold text-[var(--foreground)] truncate">{nameLabel}</p>
          <p className="text-xs text-[var(--muted-foreground)] font-mono">
            Recipe <code>{recipeTok}</code>
          </p>
        </div>
        {onClose ? (
          <button
            type="button"
            className="h-[18px] w-[18px] shrink-0 self-start text-[11px] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            aria-label="Close docs"
            title="Close docs"
            onClick={onClose}
          >
            ✕
          </button>
        ) : null}
      </header>

      {/* Metadata chips */}
      <div className="flex flex-wrap gap-2 px-3.5 py-2.5 border-b border-[var(--border)]">
        <span
          className={cn(
            "inline-flex text-xs font-bold px-2 py-1 rounded-md",
            `toolbox-badge toolbox-${tb}`,
            "bg-[color-mix(in_srgb,var(--accent)_12%,transparent)] text-[var(--accent)]"
          )}
          title={tbMeta.label}
        >
          {tbMeta.badge}
        </span>
        {shelf ? (
          <span className="inline-flex text-xs font-semibold px-2 py-1 rounded-md bg-[var(--surface-raised)] text-[var(--muted-foreground)]">
            {shelf}
          </span>
        ) : null}
        <span className="inline-flex text-xs font-semibold px-2 py-1 rounded-md bg-[var(--surface-raised)] text-[var(--muted-foreground)]">
          {kindLabel}
        </span>
        {/* §26d: declared on the step, not special-cased by name here, so the
            treatment travels with the registry. `--warn`, not `--error` — an
            error tone on a legitimate, sometimes-necessary op cries wolf. */}
        {(op as { exposure?: string }).exposure === "exports-secret" ? (
          <span
            className="inline-flex rounded-md bg-[color-mix(in_srgb,var(--warn)_14%,transparent)] px-2 py-1 text-xs font-semibold text-[var(--warn)]"
            data-exposure="exports-secret"
            title="Everything downstream of this step can read the key. Prefer agent.sign / agent.decrypt, which keep it in the vault."
          >
            Hands the private key to the pipeline
          </span>
        ) : null}
        {/* Derived, not read: `key` is no longer a step-level field, because
            binding `key=$slot` retires the panel and only the param knows
            that. Same walk the compiler uses, with nothing bound. */}
        {specInputNeeds(op).map((need) => (
          <span key={need} className="text-xs text-[var(--muted-foreground)]">
            Needs {need} input
          </span>
        ))}
        {op.unresolvedRecipients ? (
          <span className="text-xs text-[var(--muted-foreground)]">Needs recipients</span>
        ) : null}
      </div>

      {/* I/O types */}
      <div className="flex items-center justify-between gap-3 px-3.5 py-3 border-b border-[var(--border)] text-xs">
        <div className="flex items-baseline gap-1">
          <span className="font-semibold text-[var(--muted-foreground)]">In</span>
          <span className="font-mono font-bold text-[var(--foreground)]">{io.input}</span>
        </div>
        <span className="text-[var(--muted-foreground)]">→</span>
        <div className="flex items-baseline gap-1">
          <span className="font-semibold text-[var(--muted-foreground)]">Out</span>
          <span className="font-mono font-bold text-[var(--foreground)]">{io.output}</span>
        </div>
      </div>

      {/* Documentation */}
      {docLead ? (
        <p className="px-3.5 py-3 text-xs text-[var(--muted-foreground)] leading-relaxed border-b border-[var(--border)]">
          {docLead}
        </p>
      ) : null}

      {/* Reference footer (§31d) — normative spec for what this step actually
          calls, always the last row before aliases/params, never inline with
          the body copy. Rendered in compact mode too: these cards sit in a
          Radix tooltip whose provider leaves `disableHoverableContent` at its
          default of false, so the pointer can travel into the card and reach
          the link. */}
      <DocsFooter op={op} className="px-3.5 py-2 border-b border-[var(--border)]" />

      {/* Aliases */}
      {!compact && op.aliases?.length ? (
        <p className="px-3.5 py-2 text-xs text-[var(--muted-foreground)] border-b border-[var(--border)]">
          Aliases:{" "}
          {op.aliases.map((a, i) => (
            <span key={a}>
              {i ? ", " : ""}
              <code className="font-mono">{a}</code>
            </span>
          ))}
        </p>
      ) : null}

      {/* Parameters */}
      {shown.length ? (
        <div className="border-b border-[var(--border)]">
          <p className="px-3.5 pt-3 pb-2 text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)] gap-1">
            Parameters
          </p>
          <ul className="space-y-2 px-3.5 pb-3">
            {shown.map((p) => (
              <li key={p.name} className="text-xs">
                <code className="font-bold font-mono text-[var(--foreground)]">{p.name}</code>
                <div className="text-[var(--muted-foreground)]">
                  <span className="font-mono text-xs">{paramTypeBits(p)}</span>
                  {p.doc ? (
                    <p className="mt-0.5 text-[var(--muted-foreground)] italic">
                      {p.doc}
                    </p>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
          {params.length > shown.length ? (
            <p className="px-3.5 pb-3 text-xs text-[var(--muted-foreground)]">
              +{params.length - shown.length} more in Docs
            </p>
          ) : null}
        </div>
      ) : (
        <p className="px-3.5 py-2 text-xs text-[var(--muted-foreground)] border-b border-[var(--border)]">
          No parameters.
        </p>
      )}

      {/* Hint / pinned footer */}
      {pinned ? (
        <p className="px-3.5 py-2 font-mono text-[10px] text-[var(--muted-foreground)]">
          pinned · stays open while you edit params elsewhere
        </p>
      ) : !compact ? (
        <p className="px-3.5 py-2 text-xs text-[var(--muted-foreground)] italic">
          Drag onto a cell, or click to append.
        </p>
      ) : null}
    </div>
  );
}
