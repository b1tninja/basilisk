/**
 * Clipboard source/sink (§32d) — the unbuilt half of "signaling channel as a
 * first-class choice". Read is gated (a privacy event, asked every run);
 * write is a low-friction passthrough sink like `out`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clipboardTextFor,
  execClipboardRead,
  execClipboardWrite,
  setClipboardReadGate,
} from "../lib/toolkit/clipboard-ops.js";
import { getStep } from "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { POLYMORPHIC_STEPS } from "../lib/toolkit/types.js";

afterEach(() => {
  setClipboardReadGate(null);
  vi.unstubAllGlobals();
});

describe("clipboard.read", () => {
  it("fails closed without a registered permission surface", async () => {
    await expect(execClipboardRead()).rejects.toThrow(/no permission surface/);
  });

  it("returns gated text as sensitive — whatever was copied could be a secret", async () => {
    setClipboardReadGate(async () => "-----BEGIN PGP MESSAGE----- …");
    const v = await execClipboardRead();
    expect(v.type).toBe("text");
    expect(v.data).toContain("PGP MESSAGE");
    expect(v.meta.sensitive).toBe(true);
  });

  it("a deny resolves to an error, not an empty value", async () => {
    setClipboardReadGate(async () => null);
    await expect(execClipboardRead()).rejects.toThrow(/denied/);
  });
});

describe("clipboard.write", () => {
  it("writes and passes the value through unchanged, like out", async () => {
    const written = [];
    vi.stubGlobal("navigator", {
      clipboard: { writeText: async (t) => void written.push(t) },
    });
    const value = { type: "text", data: "invite-blob", meta: { sensitive: false } };
    const back = await execClipboardWrite(value);
    expect(back).toBe(value);
    expect(written).toEqual(["invite-blob"]);
  });

  it("stringifies per type: text verbatim, bytes as base64, structured as JSON", () => {
    expect(clipboardTextFor({ type: "text", data: "abc" })).toBe("abc");
    expect(clipboardTextFor({ type: "bytes", data: new Uint8Array([1, 2, 3]) })).toBe(
      btoa("\x01\x02\x03")
    );
    expect(clipboardTextFor({ type: "endpoint", data: { v: 1 } })).toBe('{"v":1}');
  });
});

describe("registry shape", () => {
  it("registers both ops on the io/ports shelf", () => {
    for (const name of ["clipboard.read", "clipboard.write"]) {
      const s = getStep(name);
      expect(s?.toolbox, name).toBe("io");
      expect(s?.shelf, name).toBe("ports");
    }
    expect(getStep("clipboard.read").kind).toBe("source");
  });

  it("write is a universal passthrough — any is stamped from POLYMORPHIC_STEPS", () => {
    expect(POLYMORPHIC_STEPS.has("clipboard.write")).toBe(true);
    expect(getStep("clipboard.write").input).toBe("any");
  });

  it("compiles in the signaling shapes the design names", () => {
    for (const recipe of [
      "clipboard.read | out $pasted",
      "random 16 | encode base64 | clipboard.write | out $copied",
    ]) {
      expect(compileRecipe(recipe).validation.errors.map((e) => e.message)).toEqual([]);
    }
  });
});
