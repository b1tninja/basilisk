import { TOOLBOX_META, SHELF_META, getShelfMeta } from "../lib/toolkit/registry.js";
import { GLYPH_PATHS } from "../lib/toolkit/glyphs.js";
import { cn } from "@/lib/cn";

export type ToolCardOp = {
  name: string;
  toolbox?: string;
  shelf?: string;
  doc?: string;
  kind?: string;
  input?: string;
  output?: string;
  label?: string;
  aliases?: string[];
  params?: Array<{
    name: string;
    type: string;
    doc?: string;
    enum?: string[];
    default?: unknown;
  }>;
  unresolvedInputs?: string | null;
  unresolvedRecipients?: boolean;
  effectiveIo?: (params: Record<string, unknown>) => { input: string; output: string };
};

type Props = {
  op: ToolCardOp;
  decode?: boolean;
  blocked?: boolean;
  fit?: boolean;
  hideHint?: boolean;
  className?: string;
};

const KIND_LABEL: Record<string, string> = {
  source: "Sources",
  transform: "Transforms",
  sink: "Outputs",
  flow: "Flow control",
};

function Glyph({ id }: { id: string }) {
  const inner = GLYPH_PATHS[id];
  if (!inner) return <span className="tool-card-glyph">#</span>;
  return (
    <svg
      className="ops-glyph ops-glyph-tile tool-card-glyph"
      width="22"
      height="22"
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <g dangerouslySetInnerHTML={{ __html: inner }} />
    </svg>
  );
}

function glyphFor(op: ToolCardOp): string {
  if (op.shelf) {
    const fromShelf = (SHELF_META as Record<string, { glyph?: string }>)[op.shelf]?.glyph;
    if (fromShelf) return fromShelf;
    const meta = getShelfMeta(op.shelf);
    if (meta?.glyph) return String(meta.glyph);
  }
  return (TOOLBOX_META as Record<string, { glyph?: string }>)[op.toolbox || ""]?.glyph || "gear";
}

/** Standard tool card — docs, kind, I/O types, params. */
export function ToolCard({
  op,
  decode = false,
  blocked = false,
  fit = false,
  hideHint = false,
  className,
}: Props) {
  const io = op.effectiveIo
    ? op.effectiveIo(decode ? { decode: true } : {})
    : { input: op.input || "?", output: op.output || "?" };
  const display = op.label || op.name;
  const nameLabel = decode ? `${display} -d` : display;
  const recipeTok = `${op.name}${decode ? " -d" : ""}`;
  const tb = op.toolbox || "io";
  const tbMeta = (TOOLBOX_META as Record<string, { badge?: string; label?: string }>)[tb] || {
    badge: tb,
    label: tb,
  };
  const shelf = op.shelf ? getShelfMeta(op.shelf).label : "";
  const kindLabel = KIND_LABEL[op.kind || ""] || op.kind || "op";
  const params = op.params || [];
  const shown = params.slice(0, 8);

  return (
    <div className={cn("tool-card", className)}>
      <header className="tool-card-head">
        <Glyph id={glyphFor(op)} />
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
      {op.doc ? <p className="tool-card-doc">{op.doc}</p> : null}
      {op.aliases?.length ? (
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
            {shown.map((p) => {
              const typeBits = [p.type];
              if (p.enum?.length) typeBits.push(p.enum.join("|"));
              else if (p.default !== undefined && p.default !== null)
                typeBits.push(`default ${String(p.default)}`);
              return (
                <li key={p.name}>
                  <code>{p.name}</code>
                  <span className="tool-card-param-type muted">{typeBits.join(" · ")}</span>
                  {p.doc ? <span className="tool-card-param-doc">{p.doc}</span> : null}
                </li>
              );
            })}
          </ul>
          {params.length > shown.length ? (
            <p className="muted fs-xs">+{params.length - shown.length} more in Docs</p>
          ) : null}
        </div>
      ) : (
        <p className="tool-card-noparams muted fs-xs">No parameters.</p>
      )}
      {!hideHint ? (
        <p className="tool-card-hint muted fs-xs">Drag onto a cell, or click to append.</p>
      ) : null}
    </div>
  );
}
