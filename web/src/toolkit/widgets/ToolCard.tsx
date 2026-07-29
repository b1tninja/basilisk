import {
  TOOLBOX_META,
  getShelfMeta,
  type ParamSpec,
  type StepSpec,
} from "../../lib/toolkit/registry.js";
import { decodeTwinToken } from "../../lib/toolkit/step-names.js";
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
  blocked?: boolean;
  fit?: boolean;
  hideHint?: boolean;
  /** Compact hover / chip-pop layout. */
  compact?: boolean;
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
  if (p.positional) typeBits.push("positional");
  if (p.flag) typeBits.push(p.flag);
  if (p.serialize === "always") typeBits.push("serialize always");
  if (p.enum?.length) typeBits.push(p.enum.join(" · "));
  else if (p.default !== undefined && p.default !== null)
    typeBits.push(`default ${String(p.default)}`);
  return typeBits.join(" · ");
}

/** Standard tool card — docs, kind, I/O types, params. Redesigned with uniform widget system. */
export function ToolCard({
  op,
  decode = false,
  blocked = false,
  fit = false,
  hideHint = false,
  compact = false,
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
        "tool-card rounded-lg border border-[var(--border)] bg-[var(--surface)] transition-all",
        compact && "tool-card-compact",
        className
      )}
      data-dir={decode ? "decode" : "encode"}
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
        {blocked ? (
          <span className="inline-flex text-xs font-bold px-2 py-1 rounded-md bg-red-200/20 text-red-700 dark:bg-red-950/30 dark:text-red-400">
            FIPS blocked
          </span>
        ) : null}
        {fit ? (
          <span className="inline-flex text-xs font-bold px-2 py-1 rounded-md bg-green-200/20 text-green-700 dark:bg-green-950/30 dark:text-green-400">
            Fits tip
          </span>
        ) : null}
        {op.unresolvedInputs ? (
          <span className="text-xs text-[var(--muted-foreground)]">
            Needs {String(op.unresolvedInputs)} input
          </span>
        ) : null}
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

      {/* Hint */}
      {!hideHint && !compact ? (
        <p className="px-3.5 py-2 text-xs text-[var(--muted-foreground)] italic">
          Drag onto a cell, or click to append.
        </p>
      ) : null}
    </div>
  );
}
