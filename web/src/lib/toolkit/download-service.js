/**
 * Saving an artifact to a file (§34a's inert tier, design_handoff_artifact_actions).
 *
 * The service half of the `download` action. It lives here rather than in
 * `artifact-actions.js` for the reason that file's header gives: services are
 * injected, never imported, so the action table reaches no browser surface of
 * its own and stays unit-testable with a stub. Same shape as
 * `keyring-service.js`.
 *
 * **Blob + object URL, not a `data:` URI.** `toolkit.html`'s policy is
 * `default-src 'none'` with `blob:` in none of its directives, which looks
 * fatal and is not: a `download`-attributed anchor starts a *download*, and no
 * CSP fetch directive governs one. The evidence is not a reading of the spec —
 * `file.save`'s no-File-System-Access fallback in `file-ops.js` has shipped
 * this exact motion under this exact policy. A `data:` URI would have been the
 * fallback and would have been the worse one anyway: it makes a second full
 * copy of a private key as an immutable base64 string that can never be zeroed
 * (see `src/lib/memory-safety.js`).
 *
 * **The object URL is revoked.** A live `blob:` URL to a private-key body is a
 * handle to the secret for the lifetime of the document, readable by anything
 * that can reach the href. Revoked on the next turn rather than synchronously,
 * because revoking inside the same task races the download start in Chromium —
 * the same note, and the same 0ms, `file-ops.js` already carries.
 *
 * **No third notification weight.** It announces on `basilisk:file-saved`, the
 * channel `file.save` already owns, for the reason `file.save` gives: the
 * browser draws its own download UI, so the app's part is a light toast, not a
 * modal telling the user what they just watched happen. What it deliberately
 * does *not* borrow from `file.save` is the save picker — a recipe that wrote
 * `file.save` asked for a destination; a click on a tile asked for a copy of
 * this file, and a "where do you want this" dialog would make the cheap action
 * the expensive one.
 */

/**
 * Whether a download can happen here at all. The tile injects the service only
 * when this is true, so `available()` never has to reason about `document`.
 */
export function downloadAvailable() {
  return (
    typeof document !== "undefined" &&
    typeof URL !== "undefined" &&
    typeof URL.createObjectURL === "function"
  );
}

/**
 * Write one artifact body to the user's downloads.
 *
 * @param {{ name: string, content?: string, mime?: string }} file
 * @returns {Promise<{ name: string, bytes: number }>}
 */
export async function downloadArtifactFile({ name, content, mime }) {
  if (!downloadAvailable()) {
    throw new Error("Downloading needs a browser document — this is the main thread's job.");
  }
  const bytes = new TextEncoder().encode(String(content ?? ""));
  const url = URL.createObjectURL(
    new Blob([bytes], { type: mime || "application/octet-stream" })
  );
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    // In a `finally`: a click that threw still leaves the handle behind, and
    // the secret does not care why the function exited.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  if (typeof window !== "undefined") {
    window.dispatchEvent(
      new CustomEvent("basilisk:file-saved", { detail: { name, bytes: bytes.length } })
    );
  }
  return { name, bytes: bytes.length };
}
