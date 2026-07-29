/** Shared DnD MIME types for toolkit surfaces. */
export const STEP_MIME = "application/x-basilisk-step";
export const REORDER_MIME = "application/x-basilisk-reorder";
export const CHIP_REORDER_MIME = "application/x-basilisk-chip-reorder";

export function stepDragPayload(name: string, decode = false): string {
  return JSON.stringify({ name, decode: !!decode });
}

/** Parse STEP_MIME (JSON `{name,decode}` or legacy plain step name). */
export function parseStepMime(raw: string): { name: string; decode: boolean } | null {
  const s = String(raw || "").trim();
  if (!s) return null;
  if (s.startsWith("{")) {
    try {
      const o = JSON.parse(s);
      if (o && typeof o.name === "string") {
        return { name: o.name, decode: !!o.decode };
      }
    } catch {
      /* fall through */
    }
  }
  return { name: s, decode: false };
}
