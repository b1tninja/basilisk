import { useEffect, useRef } from "react";
import { mountRecipientBinder } from "../lib/recipient-picker.js";

type Props = {
  slots: number;
  foreach?: boolean;
  onChange: (recs: { fingerprint: string; armoredKey: string }[]) => void;
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
      onChange: (recs: { fingerprint?: string; armoredKey?: string }[]) => {
        onChange(
          (recs || [])
            .filter((r) => r?.fingerprint)
            .map((r) => ({
              fingerprint: String(r.fingerprint),
              armoredKey: String(r.armoredKey || ""),
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
