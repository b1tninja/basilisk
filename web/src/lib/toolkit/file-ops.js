/**
 * File I/O ops — `file.read` (source) and `file.save` (passthrough sink).
 *
 * The gap these close: every other source in this toolkit produces something
 * the user typed, generated, or received over a channel. Real work starts from
 * a file on disk, and until now the only way in was pasting text into `input`
 * — which silently mangles anything that is not UTF-8 and caps out at whatever
 * a textarea can hold.
 *
 * **No permission gate, on purpose.** Contrast `clipboard.read`, which asks
 * every run through `setClipboardReadGate`: reading the clipboard is a privacy
 * event because the page chooses *when* to look at content the user never
 * offered. A file picker is the opposite — the browser's own dialog is the
 * consent, the user names the exact file inside it, and nothing is read until
 * they do. Adding a second prompt in front of the browser's would be theatre.
 *
 * Both directions prefer the **File System Access API** (`showOpenFilePicker` /
 * `showSaveFilePicker`) and fall back to an `<input type=file>` / download
 * anchor where it is absent (Firefox, Safari, and any non-secure context).
 * Main-thread only: both APIs need a document and transient user activation,
 * which the Run click supplies.
 *
 * @module lib/toolkit/file-ops
 */

/** Chunk size for streaming a save to disk — 1 MiB, matching the STREAM ops. */
const SAVE_CHUNK = 1 << 20;

/**
 * Whether the File System Access API is usable here. Checked per call rather
 * than cached: the answer is stable per browser, but a cached `false` from an
 * insecure-context test run would be wrong in the app.
 * @param {"open"|"save"} which
 */
function hasFsAccess(which) {
  if (typeof window === "undefined") return false;
  const fn = which === "open" ? window.showOpenFilePicker : window.showSaveFilePicker;
  return typeof fn === "function";
}

/**
 * True when the user dismissed a picker. The spec throws `AbortError`, which
 * is a *choice*, not a failure — the recipe should say "cancelled", not dump a
 * DOMException at the author.
 * @param {unknown} err
 */
function isAbort(err) {
  return (
    !!err &&
    typeof err === "object" &&
    /** @type {{ name?: string }} */ (err).name === "AbortError"
  );
}

/**
 * Read one file through `<input type=file>`. The element is appended so that
 * Safari fires `change`, and removed on settle either way.
 * @param {string} accept
 * @returns {Promise<File|null>}  null when the user cancelled
 */
function pickFileLegacy(accept) {
  return new Promise((resolve, reject) => {
    if (typeof document === "undefined") {
      reject(new Error("file.read: no document — main-thread only"));
      return;
    }
    const el = document.createElement("input");
    el.type = "file";
    if (accept) el.accept = accept;
    // Off-screen rather than display:none — a hidden input is click-inert in
    // some engines. No inline styles anywhere in this repo, so the rule lives
    // in toolkit.css against this data attribute.
    el.dataset.basiliskFilePicker = "";
    let settled = false;
    const done = (/** @type {File|null} */ file) => {
      if (settled) return;
      settled = true;
      el.remove();
      resolve(file);
    };
    el.addEventListener("change", () => done(el.files?.[0] || null), { once: true });
    // `cancel` is the modern signal; browsers without it simply leave the
    // promise pending until the next run replaces it, which is the same
    // behaviour a stuck picker has always had.
    el.addEventListener("cancel", () => done(null), { once: true });
    document.body.appendChild(el);
    el.click();
  });
}

/**
 * MIME → a pipeline-honest type. Text files become `text` so `utf8`-shaped
 * recipes keep working; everything else stays `bytes`, because guessing an
 * encoding for arbitrary octets is how you corrupt a key file.
 * @param {string} mime
 * @param {string} name
 */
export function fileLooksTextual(mime, name) {
  const m = String(mime || "").toLowerCase();
  if (m.startsWith("text/")) return true;
  if (/^application\/(json|xml|x-pem-file|pgp-(keys|signature))$/.test(m)) return true;
  return /\.(txt|json|xml|md|pem|asc|sig|csv|recipe|key|pub)$/i.test(String(name || ""));
}

/**
 * @param {Record<string, unknown>} [params]
 * @returns {Promise<{ type: string, data: unknown, meta: Record<string, unknown> }>}
 */
export async function execFileRead(params = {}) {
  const accept = String(params.accept ?? "").trim();
  const as = String(params.as ?? "auto").toLowerCase();

  /** @type {File|null} */
  let file = null;
  if (hasFsAccess("open")) {
    try {
      const opts = /** @type {Record<string, unknown>} */ ({ multiple: false });
      if (accept) {
        // The picker wants a structured description; a bare extension list is
        // what recipe authors will write, so translate rather than reject.
        opts.types = [{ description: "Selected files", accept: acceptToTypes(accept) }];
      }
      const [handle] = await window.showOpenFilePicker(opts);
      file = await handle.getFile();
    } catch (err) {
      if (isAbort(err)) throw new Error("file.read: cancelled");
      // A picker can also fail for policy reasons (cross-origin iframe). The
      // legacy path often still works there, so fall through instead of dying.
      file = await pickFileLegacy(accept);
    }
  } else {
    file = await pickFileLegacy(accept);
  }
  if (!file) throw new Error("file.read: cancelled");

  const buf = new Uint8Array(await file.arrayBuffer());
  const meta = {
    // A file the user chose could be anything, including a private key — the
    // same default `input` and `clipboard.read` take.
    sensitive: true,
    filename: file.name,
    mime: file.type || "application/octet-stream",
    size: buf.length,
    lastModified: file.lastModified || 0,
    fileRead: true,
  };
  const textual =
    as === "text" || (as === "auto" && fileLooksTextual(file.type, file.name));
  if (as === "bytes" || !textual) {
    return { type: "bytes", data: buf, meta: { ...meta, kind: "opaque" } };
  }
  return {
    type: "text",
    data: new TextDecoder().decode(buf),
    meta: { ...meta, kind: "opaque" },
  };
}

/**
 * `.pem,.asc` / `text/plain` → the picker's `accept` dict.
 * @param {string} accept
 * @returns {Record<string, string[]>}
 */
export function acceptToTypes(accept) {
  /** @type {Record<string, string[]>} */
  const types = {};
  const exts = [];
  for (const token of String(accept).split(/[\s,]+/).filter(Boolean)) {
    if (token.startsWith(".")) exts.push(token.toLowerCase());
    else types[token] = types[token] || [];
  }
  if (exts.length) {
    const mime = Object.keys(types)[0] || "application/octet-stream";
    types[mime] = [...(types[mime] || []), ...exts];
  }
  return Object.keys(types).length ? types : { "application/octet-stream": [".bin"] };
}

/**
 * Bytes for a save, without copying when the value already holds octets.
 * @param {{ type?: string, data?: unknown }} value
 * @returns {Uint8Array}
 */
export function saveBytesFor(value) {
  const data = value?.data;
  if (data instanceof Uint8Array) return data;
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data == null) throw new Error("file.save: nothing on the pipeline to write");
  return new TextEncoder().encode(JSON.stringify(data, null, 2));
}

/**
 * Filename for a save: explicit `name=` wins, then whatever produced the value
 * (a `file.read` upstream, or an op that named its own output like
 * `age.encrypt`), then a generic fallback.
 * @param {{ meta?: Record<string, unknown> }} value
 * @param {Record<string, unknown>} params
 */
export function saveNameFor(value, params) {
  const explicit = String(params?.name ?? "").trim();
  if (explicit) return explicit;
  const fromMeta = String(value?.meta?.filename ?? "").trim();
  if (fromMeta) return fromMeta;
  return value?.type === "text" ? "output.txt" : "output.bin";
}

/**
 * Trigger a download through an anchor. Used when the File System Access API
 * is missing — the user gets their browser's download flow instead of a
 * "where do you want this" dialog, which is the honest degradation.
 * @param {Uint8Array} bytes
 * @param {string} name
 * @param {string} mime
 */
function downloadLegacy(bytes, name, mime) {
  if (typeof document === "undefined") {
    throw new Error("file.save: no document — main-thread only");
  }
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.dataset.basiliskFilePicker = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next turn: revoking synchronously races the download start
  // in Chromium.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * Sink with passthrough, like `out` and `clipboard.write` — the value keeps
 * flowing so `file.save | inspect` and `file.save | out @ct` both work.
 * @param {{ type: string, data: unknown, meta?: Record<string, unknown> }} value
 * @param {Record<string, unknown>} [params]
 */
export async function execFileSave(value, params = {}) {
  if (!value) throw new Error("file.save expects a value");
  const bytes = saveBytesFor(value);
  const name = saveNameFor(value, params);
  const mime =
    String(params.mime ?? "").trim() ||
    String(value.meta?.mime ?? "").trim() ||
    (value.type === "text" ? "text/plain; charset=utf-8" : "application/octet-stream");

  if (hasFsAccess("save")) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: name,
        types: [{ description: name, accept: { [mime.split(";")[0]]: guessExts(name) } }],
      });
      const writable = await handle.createWritable();
      // Written in chunks so a multi-gigabyte STREAM ciphertext does not have
      // to exist as one Blob in memory on the way out.
      for (let off = 0; off < bytes.length; off += SAVE_CHUNK) {
        await writable.write(bytes.subarray(off, Math.min(off + SAVE_CHUNK, bytes.length)));
      }
      await writable.close();
      announceSave(name, bytes.length);
      return value;
    } catch (err) {
      if (isAbort(err)) throw new Error("file.save: cancelled");
      downloadLegacy(bytes, name, mime);
      announceSave(name, bytes.length);
      return value;
    }
  }
  downloadLegacy(bytes, name, mime);
  announceSave(name, bytes.length);
  return value;
}

/**
 * @param {string} name
 * @returns {string[]}
 */
function guessExts(name) {
  const m = /(\.[A-Za-z0-9]+)$/.exec(String(name || ""));
  return m ? [m[1].toLowerCase()] : [".bin"];
}

/**
 * Toast-weight confirmation, the same weight `clipboard.write` uses — the user
 * just drove a save dialog, so a second modal would be noise.
 * @param {string} name
 * @param {number} bytes
 */
function announceSave(name, bytes) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(
    new CustomEvent("basilisk:file-saved", { detail: { name, bytes } })
  );
}
