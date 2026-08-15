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
import { compileRecipe } from "../lib/toolkit/recipe.js";
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

  // A doc that offers two spellings side by side is making a claim the parser
  // has to honour, and twice it did not: `gpg.verify` and webcrypto `verify`
  // both advertised "`soft` / `-q`" while a bare `soft` refused with "no
  // positional parameter" — a remedy printed in the reference and performable
  // nowhere.
  //
  // The gate is deliberately narrow. Quoting a param's bare name is *usually*
  // prose — `otp.code` says it takes `digits` and `period` from the URI, and
  // ten such lines are correct English about a parameter rather than a claim
  // about syntax. What made the two bugs bugs is the alternation: `A`/`B` says
  // "either of these works", and that is checkable. So only tokens inside a
  // slash-separated run of backticked spellings are compiled, which fires on
  // the defect and stays silent on the prose. Widening this to every quoted
  // name would need an allowlist for those ten, and an allowlist is where a
  // gate goes to rot.
  it("every alternative spelling a doc offers actually parses", () => {
    // `A`/`B` or `A` / `B`, two or more — the shape of an either-or claim.
    const alternation = /`[^`]+`(?:\s*\/\s*`[^`]+`)+/g;
    const failures = [];
    for (const step of listSteps()) {
      const docs = [step.doc, ...(step.params || []).map((p) => p.doc)];
      const spellings = new Set();
      for (const p of step.params || []) {
        if (p.name) spellings.add(p.name);
        if (p.flag) spellings.add(p.flag);
      }
      for (const doc of docs) {
        for (const group of String(doc || "").match(alternation) || []) {
          for (const quoted of group.match(/`[^`]+`/g) || []) {
            const token = quoted.slice(1, -1).trim();
            // Only tokens that claim to be a spelling of *this* step's params.
            if (!spellings.has(token) && !/^-/.test(token)) continue;
            const { validation } = compileRecipe(`${step.name} ${token}`);
            // A step that cannot open a chain still reports a chain-start
            // error here, which is not what this asks about. The parse error
            // is: the token had nowhere to go.
            const rejected = (validation.errors || []).find((e) =>
              /no positional parameter/.test(e.message)
            );
            if (rejected) {
              failures.push(`${step.name} offers \`${token}\` — ${rejected.message}`);
            }
          }
        }
      }
    }
    expect(failures, `unparseable spellings:\n${failures.join("\n")}`).toEqual([]);
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
