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

/** Single builder param — bool / enum / text / locked. Views registry ParamSpec. */
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
      <label className={cn("builder-param", className)} title={title}>
        <span className="builder-param-name">{param.name}</span>
        {control}
      </label>
    );
  }

  if (param.type === "bool" || param.type === "flag") {
    const checked = val === true || val === "true";
    return (
      <label className={cn("builder-param builder-param-bool", className)} title={title}>
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(param.name, e.target.checked)}
        />
        <span className="builder-param-name">{param.name}</span>
        {param.flag ? <span className="builder-param-flag">{param.flag}</span> : null}
      </label>
    );
  }

  if (param.type === "enum") {
    return (
      <label className={cn("builder-param", className)} title={title}>
        <span className="builder-param-name">
          <span>{param.name}</span>
          {locked ? (
            <span className="muted fs-xs builder-param-lock-tag">locked by format</span>
          ) : null}
        </span>
        <select
          className="text-input"
          disabled={locked}
          value={String(val)}
          onChange={(e) => onChange(param.name, e.target.value)}
        >
          {(param.enum || []).map((e) => (
            <option key={e} value={e}>
              {e}
            </option>
          ))}
        </select>
      </label>
    );
  }

  return (
    <label className={cn("builder-param", className)} title={title}>
      <span className="builder-param-name">{param.name}</span>
      <input
        className="text-input"
        type={param.type === "int" ? "number" : "text"}
        value={String(val ?? "")}
        onChange={(e) =>
          onChange(
            param.name,
            param.type === "int" ? Number(e.target.value) : e.target.value
          )
        }
      />
    </label>
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
  return (
    <div className={cn("builder-params", className)}>
      {params.map((p) => (
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
