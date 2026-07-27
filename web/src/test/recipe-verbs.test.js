/**
 * Exhaustive registry verb / param smoke (Vitest — not CAST).
 * WebAuthn ceremonies + passkey wrap use installWebAuthnPrfStub (no live authenticator).
 */
import "fake-indexeddb/auto";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { readKey } from "openpgp";
import {
  installHkpFetchMock,
  installWebAuthnPrfStub,
} from "./helpers/toolkit-smoke-stubs.js";
import {
  ensureGpgKey,
  listAllVerbSmokeCases,
  listVerbSmokeCases,
  runVerbCase,
  skippedVerbCases,
  uncoveredEnumParams,
  uncoveredOps,
} from "./helpers/verb-smoke.js";
import { listSteps } from "../lib/toolkit/registry.js";
import { saveKey } from "../lib/vault.js";
import { sessionClear } from "../lib/vault-session.js";

/** @type {Awaited<ReturnType<typeof listAllVerbSmokeCases>>} */
let cases = [];

/** Fixed PRF IKM so create → prf → passkey wrap share one key (CI only). */
const FIXED_IKM = new Uint8Array(32);
for (let i = 0; i < 32; i++) FIXED_IKM[i] = (i * 7 + 3) & 0xff;

async function installMocks() {
  installWebAuthnPrfStub(vi.stubGlobal.bind(vi), FIXED_IKM);
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
  await installMocks();
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

  it("catalog has no skip modes", () => {
    const skipped = skippedVerbCases(cases);
    expect(skipped, `still skipped: ${skipped.join(", ")}`).toEqual([]);
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
  const staticIds = listVerbSmokeCases().map((c) => c.id);
  const dynamicIds = ["agent.unlock", "agent.pub"];

  for (const id of [...staticIds, ...dynamicIds]) {
    it(
      id,
      async () => {
        const c = cases.find((x) => x.id === id);
        expect(c, `missing case ${id}`).toBeTruthy();
        expect(c.mode, `${id} should not be skip`).not.toBe("skip");
        await runVerbCase(c);
      },
      120_000
    );
  }
});
