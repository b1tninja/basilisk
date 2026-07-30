/**
 * Smoke: toolkit-run handler path used by crypto-worker (digest under FIPS).
 */
import { describe, expect, it } from "vitest";
import { getSuiteStatus, runCryptoSelfTests } from "../lib/crypto-self-test.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { executeToolkitRun } from "../lib/toolkit-run.js";

describe("toolkit-run worker path", () => {
  it("runs random 16 | digest | encode hex with FIPS suites verified", async () => {
    await runCryptoSelfTests();
    const { ast, validation } = compileRecipe("random 16 | digest | encode hex");
    expect(validation.ok).toBe(true);
    const { artifacts } = await executeToolkitRun({
      ast,
      fipsMode: true,
      suiteStatus: getSuiteStatus(),
    });
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].content).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses unverified suite when FIPS on (simulated)", async () => {
    await runCryptoSelfTests();
    const { ast } = compileRecipe("random 16 | digest | encode hex");
    await expect(
      executeToolkitRun({
        ast,
        fipsMode: true,
        suiteStatus: {
          openpgp: "verified",
          webcrypto: "unverified",
          sss: "verified",
        },
      })
    ).rejects.toThrow(/FIPS mode.*webcrypto/i);
  });
});
