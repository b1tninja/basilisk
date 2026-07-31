/**
 * `qr.scan` — read a QR code back out of an image.
 *
 * The conjugate of the `qr` sink, and the other half of "make the signaling
 * channel a first-class choice" (p2p-dkg DESIGN §4): `qr` already renders an
 * invite for a phone to photograph, but nothing read one back, so the loop
 * only ever ran one way.
 *
 * Composes with the file ops rather than owning a camera:
 *
 *   file.read | qr.scan | quorum.join
 *
 * A screenshot or a photo is the realistic input — the laptop displays, the
 * phone photographs, the photo comes back as a file. A live camera capture is
 * a separate concern (a `camera.*` source with its own permission surface and
 * preview), deliberately not smuggled in here.
 *
 * Uses the platform `BarcodeDetector`. Where it is missing (Firefox, Safari at
 * time of writing) the op says so plainly and names the alternatives, rather
 * than pulling in a decoder library for a path most users will not take.
 * @module lib/toolkit/qr-scan
 */

/** @returns {boolean} */
export function qrScanSupported() {
  return typeof globalThis.BarcodeDetector === "function";
}

/**
 * Decode an image into something the detector can read.
 *
 * Two routes, and which one is used matters more than it looks:
 *
 * - **Raster bytes** (a photo or screenshot off `file.read`) go straight to
 *   `createImageBitmap(blob)`. That takes the Blob directly, fetches no URL,
 *   and so never touches `img-src`.
 * - **SVG** — which is what `qr` itself emits, so scanning this toolkit's own
 *   output is the first thing anyone tries — has to be rasterized through an
 *   `<img>`, and the URL it is given is load-bearing. The app ships
 *   `img-src 'self' data:`, so a `blob:` URL is **blocked outright** (measured
 *   in the live page: the image never loads), while a `data:` URL is allowed.
 *   `createImageBitmap` is no escape either: engines refuse to decode an SVG
 *   blob. Hence the data URL, percent-encoded rather than base64 so a
 *   non-ASCII payload (an invite line with `·` in it) survives — `btoa`
 *   throws on those.
 *
 * @param {Uint8Array|string} data
 * @param {string} mime
 * @returns {Promise<ImageBitmap|HTMLCanvasElement>}
 */
async function toBitmap(data, mime) {
  const asText =
    typeof data === "string"
      ? data
      : /svg/i.test(mime)
        ? new TextDecoder().decode(data)
        : "";
  const isSvg = /^\s*<(\?xml|svg)\b/i.test(asText.slice(0, 200));

  if (!isSvg) {
    const blob = new Blob([data], { type: mime || "image/png" });
    return createImageBitmap(blob);
  }

  const url = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(asText)}`;
  const img = new Image();
  await new Promise((resolve, reject) => {
    img.onload = () => resolve(undefined);
    img.onerror = () =>
      reject(new Error("qr.scan: could not decode the image"));
    img.src = url;
  });
  // Scaled up so a 3px-per-module QR still presents enough pixels for the
  // detector to lock onto.
  const scale = 4;
  const w = Math.max(1, (img.naturalWidth || img.width || 256) * scale);
  const h = Math.max(1, (img.naturalHeight || img.height || 256) * scale);
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("qr.scan: 2D canvas unavailable");
  // QR decoding needs the quiet zone light; a transparent SVG drawn onto a
  // transparent canvas reads as black-on-black.
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, w, h);
  ctx.drawImage(img, 0, 0, w, h);
  return canvas;
}

/**
 * @param {{ type: string, data: unknown, meta?: Record<string, unknown> }} value
 * @param {Record<string, unknown>} [params]
 */
export async function execQrScan(value, params = {}) {
  if (!qrScanSupported()) {
    throw new Error(
      "qr.scan: this browser has no BarcodeDetector — paste the invite with clipboard.read, or open it in a Chromium-based browser"
    );
  }
  if (!value || (value.type !== "bytes" && value.type !== "text" && value.type !== "artifact")) {
    throw new Error("qr.scan expects an image (use `file.read`) or SVG text");
  }
  const data = /** @type {Uint8Array|string} */ (value.data);
  if (!data || (typeof data !== "string" && !(data instanceof Uint8Array))) {
    throw new Error("qr.scan: no image data on the pipeline value");
  }
  const mime = String(value.meta?.mime || "");
  const source = await toBitmap(data, mime);

  const Detector = /** @type {any} */ (globalThis).BarcodeDetector;
  const detector = new Detector({ formats: ["qr_code"] });
  const found = await detector.detect(source);
  if (!found?.length) {
    throw new Error(
      "qr.scan: no QR code found in the image — check it is in frame, in focus, and not cropped"
    );
  }
  // Multiple codes in one photo is a real case — a sheet of share cards. The
  // shape follows `count` exactly as `rtc.recv` does (§30c): one code stays
  // `text` so the ordinary single-invite scan is unchanged, several become a
  // `bundle` whose parts `foreach` can walk. Bundle parts mirror what
  // `foreach` itself produces, so the existing collection machinery needs no
  // special case for scanned codes.
  const all = String(params?.count || "").toLowerCase() === "all";
  // Whatever was in the code could be an invite or a share — sensitive until
  // the recipe says otherwise.
  const values = found.map((d) => String(d.rawValue ?? ""));
  if (!all) {
    return {
      type: "text",
      data: values[0],
      meta: { sensitive: true, qrScan: true, found: values.length },
    };
  }
  const parts = values.map((v) => ({
    type: "text",
    data: v,
    meta: { sensitive: true, qrScan: true },
  }));
  return {
    type: "bundle",
    data: { parts, count: parts.length },
    meta: { kind: "qr-scan", count: parts.length, sensitive: true },
  };
}
