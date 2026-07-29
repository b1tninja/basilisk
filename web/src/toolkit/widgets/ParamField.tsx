import type { ReactNode } from "react";
import type { ParamSpec } from "../../lib/toolkit/registry.js";
import { cn } from "@/lib/cn";

export type { ParamSpec };

type Visibility = { show: boolean; forced?: unknown; locked?: boolean };

type Props = {
  param: ParamSpec;
  value: unknown;
  visibility?: Visibility;
  onChange: (name: string, value: string | number | boolean) => void;
  /** Extra control slot (e.g. recipient binder for to=). */
  control?: ReactNode;
  className?: string;
};

/** Single builder param — bool / enum / text / locked. Redesigned with uniform widget system. */
export function ParamField({
  param,
  value,
  visibility = { show: true },
  onChange,
  control,
  className,
}: Props) {
  if (!visibility.show) return null;
  const val = visibility.forced != null ? visibility.forced : value ?? param.default ?? "";
  const title = param.doc || undefined;
  const locked = !!visibility.locked;

  if (control) {
    return (
      <div className={cn("param-field", className)} title={title}>
        <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">
          {param.name}
        </label>
        {control}
      </div>
    );
  }

  if (param.type === "bool" || param.type === "flag") {
    const checked = val === true || val === "true";
    return (
      <div className={cn("param-field param-field-bool", className)} title={title}>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => onChange(param.name, e.target.checked)}
            className="w-4 h-4 rounded border-[var(--border)] bg-[var(--surface)] accent-[var(--brand)]"
          />
          <span className="text-sm font-semibold text-[var(--text)]">{param.name}</span>
          {param.flag ? (
            <code className="text-xs text-[var(--text-muted)] font-mono">{param.flag}</code>
          ) : null}
        </label>
      </div>
    );
  }

  if (param.type === "enum") {
    const enumValues = param.enum || [];
    // If <= 3 options, show as segmented buttons; otherwise use select
    if (enumValues.length <= 3) {
      return (
        <div className={cn("param-field", className)} title={title}>
          <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-2">
            {param.name}
            {locked && (
              <span className="ml-2 text-xs font-normal normal-case text-[var(--text-muted)]">
                (locked by format)
              </span>
            )}
          </label>
          <div className="inline-flex rounded-md border border-[var(--border)] overflow-hidden bg-[var(--surface-raised)]">
            {enumValues.map((e) => (
              <button
                key={e}
                disabled={locked}
                onClick={() => onChange(param.name, e)}
                className={cn(
                  "px-3 py-1.5 text-sm font-bold border-l border-[var(--border)] first:border-l-0 transition-colors",
                  String(val) === e
                    ? "bg-[var(--brand)] text-[var(--on-brand)]"
                    : "bg-[var(--surface)] text-[var(--text)] hover:bg-[var(--surface-raised)]"
                )}
              >
                {e}
              </button>
            ))}
          </div>
        </div>
      );
    }

    return (
      <div className={cn("param-field", className)} title={title}>
        <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">
          {param.name}
          {locked && (
            <span className="ml-2 text-xs font-normal normal-case text-[var(--text-muted)]">
              (locked by format)
            </span>
          )}
        </label>
        <select
          className="w-full px-2.5 py-1.5 text-sm border border-[var(--border)] rounded-md bg-[var(--surface)] text-[var(--text)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)] focus:ring-offset-1"
          disabled={locked}
          value={String(val)}
          onChange={(e) => onChange(param.name, e.target.value)}
        >
          {enumValues.map((e) => (
            <option key={e} value={e}>
              {e}
            </option>
          ))}
        </select>
      </div>
    );
  }

  return (
    <div className={cn("param-field", className)} title={title}>
      <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">
        {param.name}
      </label>
      <input
        className="w-full px-2.5 py-1.5 text-sm border border-[var(--border)] rounded-md bg-[var(--surface)] text-[var(--text)] font-mono focus:outline-none focus:ring-2 focus:ring-[var(--brand)] focus:ring-offset-1"
        type={param.type === "int" ? "number" : "text"}
        value={String(val ?? "")}
        onChange={(e) =>
          onChange(
            param.name,
            param.type === "int" ? Number(e.target.value) : e.target.value
          )
        }
      />
    </div>
  );
}

type GroupProps = {
  params: ParamSpec[];
  values: Record<string, unknown>;
  visibilityFor?: (p: ParamSpec) => Visibility;
  onChange: (name: string, value: string | number | boolean) => void;
  className?: string;
};

export function ParamFieldGroup({
  params,
  values,
  visibilityFor,
  onChange,
  className,
}: GroupProps) {
  const visibleParams = params.filter((p) => visibilityFor?.(p)?.show !== false);

  return (
    <div className={cn("flex flex-col gap-4", className)}>
      {visibleParams.map((p) => (
        <ParamField
          key={p.name}
          param={p}
          value={values[p.name]}
          visibility={visibilityFor?.(p)}
          onChange={onChange}
        />
      ))}
    </div>
  );
}
