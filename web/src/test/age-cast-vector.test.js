/**
 * CAST-15 — what the age suite actually proves, and that it can fail.
 *
 * `age` was the one honest gap in `toolboxToSuite`: a toolbox that does real
 * cryptography, has a vector to run and a result to gate on, and named no suite
 * only because its math lives in the third-party `age-encryption` package. The
 * cheap close was to map it to `webcrypto`; that would have had the self-test
 * vouch for primitives it never ran, which is the false claim
 * `crypto-self-test.js` exists to prevent. The expensive close — the one taken
 * — is a CAST of its own.
 *
 * ## Why these vectors and not a round-trip
 *
 * age's ciphertext is randomized: a fresh ephemeral X25519 share and a fresh
 * file key per file, so there is no fixed ciphertext an *encrypt* can be
 * compared against. A round-trip is therefore the only available shape for the
 * encrypt direction — and on its own it is nearly worthless, because it passes
 * against any implementation that agrees with itself. An age library that used
 * the wrong HKDF info string would round-trip perfectly and interoperate with
 * nothing.
 *
 * So the weight of CAST-15 is on two vectors this repository did not produce:
 *
 *   1. `armor_x25519` from the age testkit — age-encryption.org/testkit,
 *      published as C2SP CCTV, https://github.com/C2SP/CCTV/tree/main/age.
 *      A fixed identity, a fixed armored file, and the SHA-256 of the plaintext
 *      it must decrypt to. Bytes produced by `age` itself.
 *   2. The X25519 key-encoding example in the age specification,
 *      https://github.com/C2SP/C2SP/blob/main/age.md — an identity and the
 *      recipient it must derive to.
 *
 * ## Why a source sweep sits beside the behavioural tests
 *
 * The behavioural half runs the POST and reads the result. That proves the CAST
 * passes; it cannot prove the CAST *checked the published answer* rather than
 * an answer computed next to it. A vector recomputed from the library at test
 * time is the exact failure this file is defending against, so the constants are
 * also matched against their published values as literal text.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SELF_TEST_LABELS,
  getSuiteStatus,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import {
  assertRecipeAllowedUnderFips,
  suitesUsedByAst,
  toolboxToSuite,
  toolboxVerification,
} from "../lib/toolkit/suite-gate.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

const SELF_TEST_SRC = readFileSync(
  fileURLToPath(new URL("../lib/crypto-self-test.js", import.meta.url)),
  "utf8"
);

/** The published testkit values, written out here a second time on purpose. */
const TESTKIT = {
  identity:
    "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0",
  payload: "013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab",
};

/** The published spec example, likewise. */
const SPEC = {
  identity:
    "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX",
  recipient: "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj",
};

const astOf = (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.ok, `recipe did not compile: ${src}`).toBe(true);
  return ast;
};

describe("CAST-15 holds a published vector, not a locally computed one", () => {
  it("carries the age testkit identity and payload digest verbatim", () => {
    expect(SELF_TEST_SRC).toContain(TESTKIT.identity);
    expect(SELF_TEST_SRC).toContain(TESTKIT.payload);
  });

  it("carries the age spec's identity/recipient pair verbatim", () => {
    expect(SELF_TEST_SRC).toContain(SPEC.identity);
    expect(SELF_TEST_SRC).toContain(SPEC.recipient);
  });

  it("says where both came from, close enough to read beside them", () => {
    // A hard-coded 64-hex string with no provenance is indistinguishable from
    // an invented one, and this repository's rule is that a vector names its
    // source. Both URLs must survive in the file.
    expect(SELF_TEST_SRC).toContain("age-encryption.org/testkit");
    expect(SELF_TEST_SRC).toContain("github.com/C2SP/CCTV");
    expect(SELF_TEST_SRC).toContain("github.com/C2SP/C2SP/blob/main/age.md");
  });

  it("compares against the constant rather than against a fresh encryption", () => {
    // The failure mode this file exists for: a "KAT" whose expected value is
    // recomputed at run time passes unconditionally. The decrypt check must
    // read the frozen digest.
    expect(SELF_TEST_SRC).toMatch(/payloadHex !== AGE_TESTKIT_PAYLOAD_SHA256/);
    expect(SELF_TEST_SRC).toMatch(/derived !== AGE_SPEC_RECIPIENT/);
  });

  it("labels the check with its CAST number", () => {
    expect(SELF_TEST_LABELS.ageKat).toMatch(/CAST-15/);
  });
});

describe("the age suite reports and gates", () => {
  it("verifies the age suite after the POST", async () => {
    const result = await runCryptoSelfTests();
    expect(result.results.ageKat, result.error || "CAST-15 did not pass").toBe(true);
    expect(getSuiteStatus().age).toBe("verified");
  });

  it("maps the age toolbox to the age suite and not a borrowed one", () => {
    expect(toolboxToSuite("age")).toBe("age");
  });

  it("reports the age suite for a recipe made of age ops", () => {
    // The gate finds suites through `suitesUsedByAst`. Before CAST-15 this
    // returned [] for an all-age recipe, which is why FIPS mode could not see
    // the toolbox at all.
    expect(suitesUsedByAst(astOf("age.keygen | age.recipient"))).toEqual(["age"]);
  });

  it("lets an age recipe run under FIPS once CAST-15 has passed", async () => {
    await runCryptoSelfTests();
    expect(() =>
      assertRecipeAllowedUnderFips(
        astOf("age.keygen | age.recipient"),
        getSuiteStatus(),
        true
      )
    ).not.toThrow();
  });

  it("refuses an age recipe under FIPS when the age suite is unverified", () => {
    // The half that makes the mapping worth anything. Note the status map is
    // otherwise all-green: the refusal must come from `age`, not from
    // collateral damage.
    const status = {
      openpgp: "verified",
      webcrypto: "verified",
      sss: "verified",
      age: "unverified",
    };
    expect(() =>
      assertRecipeAllowedUnderFips(astOf("age.keygen | age.recipient"), status, true)
    ).toThrow(/unverified age ops/);
  });

  it("still runs a webcrypto recipe with only age unverified (control)", () => {
    // Without this, a gate that refused everything would look like a working
    // age gate.
    const status = {
      openpgp: "verified",
      webcrypto: "verified",
      sss: "verified",
      age: "unverified",
    };
    expect(() =>
      assertRecipeAllowedUnderFips(astOf("random 16 | digest | encode hex"), status, true)
    ).not.toThrow();
  });

  it("treats a status map with no age key as unverified, not as a pass", () => {
    // `SuiteStatusMap` leaves `age` optional so callers written before the
    // suite existed still typecheck — `engine.js`'s `unverifiedSuiteStatus()`
    // among them. That is only safe if the missing key reads as "not
    // verified", so it is pinned here rather than assumed.
    const legacy = { openpgp: "verified", webcrypto: "verified", sss: "verified" };
    expect(toolboxVerification("age", legacy)).toBe("unverified");
    expect(() =>
      assertRecipeAllowedUnderFips(astOf("age.keygen | age.recipient"), legacy, true)
    ).toThrow(/unverified age ops/);
  });
});

describe("assertSuiteReady is gone", () => {
  it("is no longer exported by the self-test module", () => {
    // It was exported "for hard gates" and no hard gate called it; the gate
    // that shipped is `assertRecipeAllowedUnderFips`. A per-suite entry point
    // kept alive by its own test is a protection nobody can cite.
    expect(SELF_TEST_SRC).not.toMatch(/export async function assertSuiteReady/);
    expect(SELF_TEST_SRC).not.toMatch(/\bassertSuiteReady\b/);
  });
});
