/**
 * Exhaustive registry verb / param smoke (Vitest — not CAST).
 */
import "fake-indexeddb/auto";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { readKey } from "openpgp";
import {
  ensureGpgKey,
  installHkpFetchMock,
  listAllVerbSmokeCases,
  listVerbSmokeCases,
  runVerbCase,
  uncoveredEnumParams,
  uncoveredOps,
} from "../lib/toolkit/verb-smoke.js";
import { listSteps } from "../lib/toolkit/registry.js";
import { saveKey } from "../lib/vault.js";
import { sessionClear } from "../lib/vault-session.js";

/** @type {Awaited<ReturnType<typeof listAllVerbSmokeCases>>} */
let cases = [];

async function installMocks() {
  const k = await ensureGpgKey();
  const pub = await readKey({ armoredKey: k.publicKey });
  installHkpFetchMock(
    {
      fingerprint: pub.getFingerprint(),
      armoredPublic: k.publicKey,
      email: "alice@example.com",
    },
    vi.stubGlobal.bind(vi)
  );
}

beforeAll(async () => {
  const k = await ensureGpgKey();
  const pub = await readKey({ armoredKey: k.publicKey });
  const fpr = pub.getFingerprint().toUpperCase();
  await saveKey({
    fingerprint: fpr,
    armoredPrivate: k.privateKey,
    publicArmored: k.publicKey,
    uid: "verb-smoke@example.com",
    email: "verb-smoke@example.com",
    protection: "device",
  });
  cases = await listAllVerbSmokeCases();
}, 60_000);

beforeEach(async () => {
  sessionClear();
  vi.unstubAllGlobals();
  await installMocks();
});

describe("verb smoke coverage gates", () => {
  it("registry has ops to cover", () => {
    expect(listSteps().length).toBeGreaterThanOrEqual(60);
    expect(listVerbSmokeCases().length).toBeGreaterThanOrEqual(60);
  });

  it("every listSteps() op appears in the catalog", () => {
    const gaps = uncoveredOps(cases);
    expect(gaps, `uncovered ops: ${gaps.join(", ")}`).toEqual([]);
  });

  it("every enum / bool param value is exercised", () => {
    const gaps = uncoveredEnumParams(cases);
    expect(gaps, `uncovered params:\n${gaps.join("\n")}`).toEqual([]);
  });
});

describe("verb smoke run", () => {
  // Individual cases registered after beforeAll via a second describe block pattern:
  // Vitest collects tests eagerly, so we expand from the static catalog + dynamic
  // ids, and resolve the live case object at run time.
  const staticIds = listVerbSmokeCases().map((c) => c.id);
  const dynamicIds = ["agent.unlock", "agent.pub"];

  for (const id of [...staticIds, ...dynamicIds]) {
    it(
      id,
      async () => {
        const c = cases.find((x) => x.id === id);
        expect(c, `missing case ${id}`).toBeTruthy();
        if (c.mode === "skip") return;
        await runVerbCase(c);
      },
      120_000
    );
  }
});
