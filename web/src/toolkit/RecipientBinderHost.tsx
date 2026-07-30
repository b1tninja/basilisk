import { useEffect, useRef } from "react";
import { mountRecipientBinder } from "../lib/recipient-picker.js";
import type { ResolvedRecipient } from "./notebook-types";

type Props = {
  slots: number;
  foreach?: boolean;
  onChange: (recs: ResolvedRecipient[]) => void;
};

/** Host the existing vanilla recipient binder inside React (phase-1 bridge). */
export function RecipientBinderHost({ slots, foreach = false, onChange }: Props) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || slots <= 0) return;
    const binder = mountRecipientBinder(el, {
      slots,
      foreach,
      onChange: (
        recs: {
          fingerprint?: string;
          armoredKey?: string;
          label?: string;
          email?: string;
          modernCapable?: boolean;
        }[]
      ) => {
        onChange(
          (recs || [])
            .filter((r) => r?.fingerprint)
            .map((r) => ({
              fingerprint: String(r.fingerprint),
              armoredKey: String(r.armoredKey || ""),
              label: r.label || undefined,
              email: r.email || undefined,
              modernCapable: !!r.modernCapable,
            }))
        );
      },
    });
    return () => {
      try {
        binder.destroy?.();
      } catch {
        /* ignore */
      }
      el.innerHTML = "";
    };
  }, [slots, foreach, onChange]);

  return <div ref={ref} className="cell-bind-messaging cell-runtime-zone" />;
}
