import { describe, expect, it } from "vitest";
import { formatHexdump, inspectValue } from "../lib/toolkit/inspect.js";
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
      "genkey ec/p256 | tee name=kp | export pkcs8 | pem"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const tee = arts.find((a) => /tee:kp/i.test(a.label) || /kp\.inspect/i.test(a.filename));
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
});
