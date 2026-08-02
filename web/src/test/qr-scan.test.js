/**
 * `qr.scan` — reading an invite back out of a QR image.
 *
 * The decode itself belongs to the platform `BarcodeDetector`, which node has
 * no version of, so what is asserted here is everything around it: the type
 * flow, the count-driven shape, the refusals, and — most importantly — the
 * rasterization route, which is constrained by the app's own CSP in a way no
 * amount of reading the code would reveal.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { getStep } from "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { inferSourceType, formatType, resolveStepType } from "../lib/toolkit/types.js";
import { qrScanSupported } from "../lib/toolkit/qr-scan.js";

const SRC = readFileSync(
  fileURLToPath(new URL("../lib/toolkit/qr-scan.js", import.meta.url)),
  "utf8"
);

afterEach(() => vi.unstubAllGlobals());

describe("registry shape", () => {
  it("is a transform on the io/ports shelf, beside `qr`", () => {
    const s = getStep("qr.scan");
    expect(s?.kind).toBe("transform");
    expect(s?.toolbox).toBe("io");
    expect(s?.shelf).toBe("ports");
  });

  it("follows the count-driven shape quorum.recv established", () => {
    const io = (count) => getStep("qr.scan").effectiveIo({ count });
    expect(io("1").output).toBe("text");
    expect(io(undefined).output).toBe("text");
    expect(io("all").output).toBe("bundle");
  });

  it("agrees between effectiveIo and the type checker", () => {
    // Consulted by different layers — the caret uses one, the type walker the
    // other. Disagreeing would let a cipher op be offered after a scan that
    // really produced a collection.
    const bytes = { base: "bytes", kind: "opaque" };
    for (const count of ["1", "all", undefined]) {
      const io = getStep("qr.scan").effectiveIo({ count });
      const resolved = resolveStepType(getStep("qr.scan"), bytes, { count });
      expect(resolved.ok, String(count)).toBe(true);
      expect(resolved.output.base, String(count)).toBe(io.output);
    }
  });
});

describe("type flow", () => {
  it("accepts an image from file.read and SVG text from `qr`", () => {
    for (const recipe of [
      "file.read | qr.scan | out @invite",
      "input | qr.scan | out @invite",
    ]) {
      expect(compileRecipe(recipe).validation.errors.map((e) => e.message), recipe).toEqual([]);
    }
  });

  it("lets foreach walk a multi-code scan, and not a single one", () => {
    const many = compileRecipe("file.read | qr.scan count=all | foreach\n  - out @code");
    expect(many.validation.errors.map((e) => e.message)).toEqual([]);
    const one = compileRecipe("file.read | qr.scan | foreach\n  - out @code");
    expect(one.validation.ok).toBe(false);
  });

  it("refuses a value that is not an image", () => {
    const r = resolveStepType(getStep("qr.scan"), { base: "keypair" }, {});
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/expects an image/i);
  });
});

describe("unsupported engines fail loudly and usefully", () => {
  it("names the alternatives instead of throwing something opaque", async () => {
    expect(qrScanSupported()).toBe(false); // node has no BarcodeDetector
    const { execQrScan } = await import("../lib/toolkit/qr-scan.js");
    await expect(execQrScan({ type: "text", data: "<svg/>" }, {})).rejects.toThrow(
      /BarcodeDetector.*clipboard\.read|clipboard\.read.*BarcodeDetector/s
    );
  });
});

describe("rasterization route is CSP-shaped, and must stay that way", () => {
  // Measured in the live page: the app ships `img-src 'self' data:`, so an
  // <img> pointed at a blob: URL never loads, and createImageBitmap refuses to
  // decode an SVG blob. A data: URL is the only route that works. This test
  // exists because the failure is silent — the op would simply never find a
  // code — and nothing in node can reproduce it.
  it("uses a data: URL for SVG, never a blob: URL", () => {
    expect(SRC).toContain("data:image/svg+xml");
    expect(SRC).not.toContain("createObjectURL");
  });

  it("percent-encodes rather than base64, so non-ASCII payloads survive", () => {
    // `btoa` throws on a payload containing e.g. "·", which real invite lines
    // carry.
    expect(SRC).toContain("encodeURIComponent");
    expect(SRC).not.toContain("btoa(");
  });

  it("paints a light quiet zone before drawing", () => {
    // A transparent SVG on a transparent canvas reads as black-on-black and
    // decodes as nothing.
    expect(SRC).toMatch(/fillStyle\s*=\s*"#ffffff"/);
  });
});
