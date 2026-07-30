/**
 * Clipboard source/sink ops (design v2 §32d) — the unbuilt half of "make the
 * signaling channel a first-class choice" (p2p-dkg DESIGN §4; `qr` is the
 * other half and already exists).
 *
 * The two directions carry different weight on purpose. Reading the clipboard
 * is a privacy event — any site could be watching what you last copied — so
 * `clipboard.read` goes through a permission gate the UI registers, asked
 * every run and never remembered, because clipboard contents change silently
 * between runs. Writing is comparatively low-stakes (the user just ran the
 * recipe that produces the value), so `clipboard.write` confirms with a
 * toast-weight event, not a dialog.
 *
 * Main-thread only: `navigator.clipboard` read needs transient user
 * activation, which is why the gate resolves with the text itself — the UI
 * reads the clipboard inside the user's Allow click, while the activation is
 * still live, rather than handing control back here after it has expired.
 * @module lib/toolkit/clipboard-ops
 */

/**
 * @typedef {() => Promise<string | null>} ClipboardReadGate
 *   Resolves with clipboard text (read inside the Allow gesture) or null on
 *   deny/dismiss.
 */

/** @type {ClipboardReadGate | null} */
let readGate = null;

/**
 * Register the UI's permission surface (ToolkitShell does this on mount).
 * Pass null to unregister. Tests register a fake gate.
 * @param {ClipboardReadGate | null} gate
 */
export function setClipboardReadGate(gate) {
  readGate = gate;
}

export async function execClipboardRead() {
  if (!readGate) {
    throw new Error(
      "clipboard.read: no permission surface registered — run inside the toolkit UI"
    );
  }
  const text = await readGate();
  if (text == null) {
    throw new Error("clipboard.read: denied");
  }
  return {
    type: "text",
    // Whatever was copied could be a secret — masked unless the recipe
    // explicitly reveals it downstream, like any other sensitive value.
    data: String(text),
    meta: { sensitive: true, clipboardRead: true },
  };
}

/**
 * Stringify a pipeline value for the clipboard: text-ish values verbatim,
 * bytes as base64 (a clipboard holds text), structured data as JSON.
 * @param {{ type?: string, data?: unknown }} value
 * @returns {string}
 */
export function clipboardTextFor(value) {
  const data = value?.data;
  if (data instanceof Uint8Array) {
    let bin = "";
    for (const b of data) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  if (typeof data === "string") return data;
  return JSON.stringify(data);
}

/**
 * Sink with passthrough, like `out` — the value continues down the pipe.
 * @param {{ type: string, data: unknown, meta?: Record<string, unknown> }} value
 */
export async function execClipboardWrite(value) {
  if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
    throw new Error("clipboard.write: Clipboard API unavailable in this context");
  }
  const text = clipboardTextFor(value);
  await navigator.clipboard.writeText(text);
  if (typeof window !== "undefined") {
    // Toast-weight confirmation ("ok", auto-dismiss) — same weight as the
    // existing Copy buttons, deliberately not matching Read's gating.
    window.dispatchEvent(
      new CustomEvent("basilisk:clipboard-wrote", {
        detail: { chars: text.length },
      })
    );
  }
  return value;
}
