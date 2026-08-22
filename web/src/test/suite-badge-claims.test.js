/**
 * The toolkit's loudest status line counts self-tests, and only self-tests.
 *
 * The pill above the notebook read **"4 suites ready"**. Three of the four
 * came from `getSuiteStatus()` after `runCryptoSelfTests()` — known-answer
 * vectors against OpenPGP, WebCrypto and SSS. The fourth was WebAuthn, and
 * behind it was `typeof window.PublicKeyCredential !== "undefined"` returning
 * the string `"verified"`. A browser feature check was wearing a self-test's
 * word, so it shared the self-test's count, the self-test's ✓, and a heading
 * that said "Crypto self-test (POST)".
 *
 * Two facts make that a claim nobody can cash:
 *
 * 1. **Nothing was tested.** A passkey's private half lives inside an
 *    authenticator this page cannot address. There is no known answer to
 *    check, which is why no CAST vector covers WebAuthn and why it must never
 *    be counted with the suites that have one.
 * 2. **FIPS mode cannot reach it.** `toolboxToSuite("webauthn")` returns
 *    `null`, so `suitesUsedBySteps` never yields a WebAuthn suite and
 *    `assertRecipeAllowedUnderFips` has nothing to refuse. The shell drew a
 *    banner reading "FIPS mode: blocked — webauthn unverified" over recipes
 *    the gate would have run without complaint — a refusal that does not
 *    happen, on a browser feature that cannot be self-tested.
 *
 * The behavioural half of this file pins (2) against the gate itself, with a
 * WebCrypto control that must keep throwing: a "FIPS ignores WebAuthn" test
 * that passes because the gate ignores *everything* would be worth nothing.
 * The source half pins what the shell may say, because the count and the
 * words are rendered from React state that `environment: "node"` cannot
 * mount — the rendered strings are measured on the shipped bundle in
 * `e2e/suite-badge-claims.e2e.js`, and these are the cheap tripwires under
 * the same claims.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertRecipeAllowedUnderFips,
  suitesUsedBySteps,
  toolboxToSuite,
} from "../lib/toolkit/suite-gate.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

/**
 * The shell with its comments taken out.
 *
 * Every pin below is about what the file *does*, and this file's own subject
 * is a sentence that must not be rendered any more — which the comment
 * explaining why quotes verbatim. Matching raw source would score that
 * explanation as the defect, and the fix for a red test would be to delete
 * the reason. The `[^:]` guard keeps `https://` out of the line-comment rule.
 */
const codeOnly = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");

const SHELL = codeOnly(read("../toolkit/ToolkitShell.tsx"));

/** Every suite unverified — the state most likely to make a gate throw. */
const NOTHING_VERIFIED = { openpgp: "unverified", webcrypto: "unverified", sss: "unverified" };

const astOf = (...names) => ({ chains: [{ steps: names.map((name) => ({ name })) }] });

describe("FIPS mode does not gate WebAuthn, and the UI must not imply it does", () => {
  it("maps the webauthn toolbox to no suite", () => {
    expect(toolboxToSuite("webauthn")).toBeNull();
  });

  it("reports no suite for a recipe made entirely of webauthn ops", () => {
    const steps = ["webauthn.caps", "webauthn.create", "webauthn.get", "webauthn.prf"].map(
      (name) => ({ name })
    );
    expect(suitesUsedBySteps(steps)).toEqual([]);
  });

  it("lets a webauthn recipe run under FIPS with every suite unverified", () => {
    expect(() =>
      assertRecipeAllowedUnderFips(astOf("webauthn.create", "webauthn.get"), NOTHING_VERIFIED, true)
    ).not.toThrow();
  });

  it("still refuses an unverified webcrypto recipe (control)", () => {
    // The control for the assertion above. Without it, deleting the body of
    // `assertRecipeAllowedUnderFips` would turn this file green.
    expect(() => assertRecipeAllowedUnderFips(astOf("digest"), NOTHING_VERIFIED, true)).toThrow(
      /FIPS mode: recipe uses unverified webcrypto ops/
    );
  });

  it("keeps the shell's FIPS banner off the webauthn probe", () => {
    // The deleted arm said "blocked" about a run that would proceed. Nothing
    // in the banner's computation may consult the WebAuthn probe again.
    const banner = SHELL.slice(
      SHELL.indexOf("const fipsBlockedMessage"),
      SHELL.indexOf("}, [fipsMode, nb.compiled.ast, suiteStatus]);")
    );
    expect(banner).not.toMatch(/webauthn/i);
    expect(SHELL).not.toMatch(/FIPS mode: blocked/);
  });
});

describe("the shell separates a verified suite from an available capability", () => {
  it("gives the WebAuthn probe its own two words", () => {
    // "present"/"absent", never the self-test's vocabulary: sharing the word
    // is what let a `typeof` check be counted as a qualified algorithm.
    expect(SHELL).toMatch(/function webauthnApiPresence\(\): WebAuthnPresence/);
    expect(SHELL).toMatch(/\? "present"\s*\n?\s*: "absent";/);
    expect(SHELL).not.toMatch(/webauthnCapabilityStatus/);
  });

  it("keeps webauthn out of the badge-label map the count is taken from", () => {
    const labels = SHELL.slice(
      SHELL.indexOf("const SUITE_BADGE_LABEL"),
      SHELL.indexOf("const LAYOUT_KEY")
    );
    expect(labels).toMatch(/webcrypto: "WebCrypto"/);
    expect(labels).not.toMatch(/webauthn/i);
  });

  it("keeps webauthn out of the suite-status state the count is taken from", () => {
    const state = SHELL.slice(
      SHELL.indexOf("const [suiteStatus, setSuiteStatus]"),
      SHELL.indexOf("const [fipsMode, setFipsModeState]")
    );
    expect(state).toMatch(/useState<CastSuiteStatus>/);
    expect(state).not.toMatch(/webauthn: "unverified"/);
  });

  it("counts the pill from the CAST rows alone", () => {
    // `castSuiteRows` is the three self-tested suites; `suiteDetail` is those
    // plus the capability row. The label may only be built from the former.
    expect(SHELL).toMatch(/\$\{verified\} suites verified/);
    expect(SHELL).toMatch(/\$\{verified\} of \$\{castSuiteRows\.length\} suites verified/);
    expect(SHELL).not.toMatch(/suites ready/);
  });
});
