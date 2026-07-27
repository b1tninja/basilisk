import { describe, expect, it } from "vitest";
import {
  buildInspectSnapshot,
  formatHexdump,
  inspectFromSnapshot,
  inspectValue,
} from "../lib/toolkit/inspect.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("formatHexdump", () => {
  it("renders offset, hex, and ascii", () => {
    const bytes = new TextEncoder().encode("Hello, world!");
    const dump = formatHexdump(bytes);
    expect(dump).toContain("00000000");
    expect(dump).toContain("48 65 6c 6c 6f");
    expect(dump).toContain("|Hello, world!|");
  });
});

describe("inspect / tee", () => {
  it("hexdump alias dumps random bytes as text", async () => {
    const { ast, validation } = compileRecipe("random 16 | hexdump");
    expect(validation.ok).toBe(true);
    expect(ast.steps[1].name).toBe("inspect");
    expect(ast.steps[1].params.format).toBe("hexdump");
    const arts = await runRecipe(ast);
    expect(arts[0].content).toMatch(/type: bytes/);
    expect(arts[0].content).toMatch(/00000000/);
  });

  it("tee passes keypair through and emits inspect artifact", async () => {
    const { ast, validation } = compileRecipe(
      "genkey ec/p256 | peek name=kp | export pkcs8 | pem"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const tee = arts.find((a) => /peek:kp|tee:kp/i.test(a.label) || /kp\.inspect/i.test(a.filename));
    expect(tee).toBeTruthy();
    expect(tee.content).toMatch(/type: keypair/);
    expect(tee.content).toMatch(/private JWK|alg: ec\/p256/i);
    expect(tee.sensitive).toBe(true);
    const pem = arts.find((a) => String(a.content).includes("BEGIN PRIVATE KEY"));
    expect(pem).toBeTruthy();
  }, 30_000);

  it("inspect accepts keypair without export", async () => {
    const { ast, validation } = compileRecipe("genkey ed25519 | inspect jwk");
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts[0].content).toMatch(/OKP|Ed25519|private JWK/i);
  }, 30_000);

  it("inspectValue meta format for text", async () => {
    const dump = await inspectValue(
      { type: "text", data: "abc", meta: { sensitive: false, note: "x" } },
      "meta"
    );
    expect(dump).toMatch(/"note": "x"/);
  });

  it("snapshot lets formats switch without re-running", async () => {
    const bytes = new Uint8Array([0x48, 0x69]); // Hi
    const snap = await buildInspectSnapshot({
      type: "bytes",
      data: bytes,
      meta: { sensitive: false },
    });
    expect(snap?.type).toBe("bytes");
    const hex = inspectFromSnapshot(snap, "hex");
    expect(hex).toMatch(/4869/);
    const dump = inspectFromSnapshot(snap, "hexdump");
    expect(dump).toMatch(/\|Hi\|/);
    const meta = inspectFromSnapshot(snap, "meta");
    expect(meta).toMatch(/"sensitive": false/);
  });

  it("inspect of sensitive bytes omits live snapshot (no secret retention)", async () => {
    const { ast, validation } = compileRecipe("random 8 | inspect hex");
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts[0].role).toBe("inspect");
    expect(arts[0].sensitive).toBe(true);
    expect(arts[0].inspectFormat).toBe("hex");
    // Format switching would re-hold random/key bytes — dropped when sensitive.
    expect(arts[0].inspectSnapshot).toBeUndefined();
  });

  it("non-sensitive inspect snapshot still supports live format switch", async () => {
    const snap = await buildInspectSnapshot({
      type: "text",
      data: "Hi",
      meta: { sensitive: false },
    });
    expect(snap?.type).toBe("text");
    const switched = inspectFromSnapshot(snap, "hex");
    expect(switched).toMatch(/4869/);
  });
});
