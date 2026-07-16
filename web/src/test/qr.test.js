import { describe, expect, it } from "vitest";
import { encodeQrModules, openpgp4fprUri, qrSvg, renderQrSvg } from "../lib/qr.js";

function hasFinderPattern(modules, topLeftX, topLeftY) {
  // 7×7 finder: outer border + solid inner 3×3 (Nayuki / ISO layout)
  for (let dy = 0; dy < 7; dy++) {
    for (let dx = 0; dx < 7; dx++) {
      const dark =
        dx === 0 ||
        dx === 6 ||
        dy === 0 ||
        dy === 6 ||
        (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4);
      expect(modules[topLeftY + dy][topLeftX + dx]).toBe(dark);
    }
  }
}

describe("encodeQrModules", () => {
  it("produces a square matrix with size === 17 + 4*version", () => {
    const modules = encodeQrModules("hello");
    const n = modules.length;
    expect(modules.every((row) => row.length === n)).toBe(true);
    const version = (n - 17) / 4;
    expect(version).toBeGreaterThanOrEqual(1);
    expect(n).toBe(17 + 4 * version);
  });

  it("has finder patterns at three corners", () => {
    const modules = encodeQrModules("test");
    const n = modules.length;
    hasFinderPattern(modules, 0, 0);
    hasFinderPattern(modules, n - 7, 0);
    hasFinderPattern(modules, 0, n - 7);
  });
});

describe("openpgp4fprUri", () => {
  it("normalizes spaces, 0x prefix, and uppercases", () => {
    expect(openpgp4fprUri("0x ab cd ef")).toBe("openpgp4fpr:ABCDEF");
    expect(openpgp4fprUri(" 0123 4567 ")).toBe("openpgp4fpr:01234567");
  });
});

describe("qrSvg", () => {
  it("contains svg root and dark/light rects", () => {
    const svg = qrSvg("hello", { dark: "#111", light: "#eee" });
    expect(svg).toContain("<svg");
    expect(svg).toContain('fill="#111"');
    expect(svg).toContain('fill="#eee"');
    expect(svg).toContain("<rect");
  });

  it("renderQrSvg accepts pre-encoded modules", () => {
    const modules = encodeQrModules("x");
    const svg = renderQrSvg(modules);
    expect(svg).toMatch(/^<svg[\s\S]*<\/svg>$/);
  });
});

describe("openpgp4fpr roundtrip", () => {
  it("encodes openpgp4fpr URI with 40 hex chars", () => {
    const fp = "A1B2C3D4E5F6789012345678901234567890ABCD";
    const uri = openpgp4fprUri(fp);
    expect(uri).toBe(`openpgp4fpr:${fp}`);
    const modules = encodeQrModules(uri);
    expect(modules.length).toBeGreaterThanOrEqual(21);
    expect(qrSvg(uri)).toContain("<svg");
  });
});
