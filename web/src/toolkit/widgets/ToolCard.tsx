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

/** Standard tool card — docs, kind, I/O types, params. */
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
      className={cn("tool-card", compact && "tool-card-compact", className)}
      data-dir={decode ? "decode" : "encode"}
    >
      <header className="tool-card-head">
        <Glyph
          id={glyphIdFor(op)}
          size={compact ? 18 : 22}
          svgClassName="ops-glyph ops-glyph-tile tool-card-glyph"
        />
        <div className="tool-card-titles">
          <p className="tool-card-name">{nameLabel}</p>
          <p className="tool-card-recipe muted fs-xs">
            Recipe <code>{recipeTok}</code>
          </p>
        </div>
      </header>
      <div className="tool-card-meta">
        <span className={`toolbox-badge toolbox-${tb}`} title={tbMeta.label}>
          {tbMeta.badge}
        </span>
        {shelf ? <span className="tool-card-chip">{shelf}</span> : null}
        <span className="tool-card-chip">{kindLabel}</span>
        {blocked ? (
          <span className="tool-card-flag tool-card-flag-warn">FIPS blocked</span>
        ) : null}
        {fit ? <span className="tool-card-flag tool-card-flag-fit">Fits tip</span> : null}
        {op.unresolvedInputs ? (
          <span className="tool-card-flag">Needs {String(op.unresolvedInputs)} input</span>
        ) : null}
        {op.unresolvedRecipients ? (
          <span className="tool-card-flag">Needs recipients</span>
        ) : null}
      </div>
      <div className="tool-card-io" aria-label="Input and output types">
        <div className="tool-card-io-side">
          <span className="tool-card-io-label muted">In</span>
          <span className="tool-card-type" data-io="in">
            {io.input}
          </span>
        </div>
        <span className="tool-card-io-arrow" aria-hidden>
          →
        </span>
        <div className="tool-card-io-side">
          <span className="tool-card-io-label muted">Out</span>
          <span className="tool-card-type" data-io="out">
            {io.output}
          </span>
        </div>
      </div>
      {docLead ? <p className="tool-card-doc">{docLead}</p> : null}
      {!compact && op.aliases?.length ? (
        <p className="tool-card-aliases muted fs-xs">
          Aliases:{" "}
          {op.aliases.map((a, i) => (
            <span key={a}>
              {i ? ", " : ""}
              <code>{a}</code>
            </span>
          ))}
        </p>
      ) : null}
      {shown.length ? (
        <div className="tool-card-params">
          <p className="tool-card-section">Parameters</p>
          <ul className="tool-card-param-list">
            {shown.map((p) => (
              <li key={p.name}>
                <code>{p.name}</code>
                <span className="tool-card-param-type muted">{paramTypeBits(p)}</span>
                {p.doc ? <span className="tool-card-param-doc">{p.doc}</span> : null}
              </li>
            ))}
          </ul>
          {params.length > shown.length ? (
            <p className="muted fs-xs">+{params.length - shown.length} more in Docs</p>
          ) : null}
        </div>
      ) : (
        <p className="tool-card-noparams muted fs-xs">No parameters.</p>
      )}
      {!hideHint && !compact ? (
        <p className="tool-card-hint muted fs-xs">Drag onto a cell, or click to append.</p>
      ) : null}
    </div>
  );
}
