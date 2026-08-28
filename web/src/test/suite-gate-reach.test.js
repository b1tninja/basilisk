/**
 * Every toolbox that does crypto names a suite, or says why it cannot.
 *
 * FIPS mode refuses a run that reaches an unverified suite, and it finds the
 * suites through `toolboxToSuite`. A toolbox that performs real cryptography
 * and maps to `null` is therefore invisible to the gate: `suitesUsedBySteps`
 * reports nothing for it, and nothing the gate does can reach it.
 *
 * That is not hypothetical. `jose` reached SubtleCrypto twelve times through
 * `webcrypto-ops.js` and touched OpenPGP not at all; `otp`'s counter is
 * `crypto.subtle.sign("HMAC")` in `lib/otp/hotp.js`. Both mapped to `null`, so
 * with the switch on and `webcrypto` unverified a JWT or a TOTP ran happily
 * while an `aes-gcm` cell beside it was refused — the same suite, the same
 * primitives, one gated and one not, because of which toolbox the op sits in.
 *
 * ## Why this is a source sweep
 *
 * The question is "does this toolbox's code reach a cryptographic primitive",
 * which is a fact about the code. A behavioural test would only cover the
 * toolboxes it happened to drive, and the defect is precisely a toolbox nobody
 * thought to drive.
 *
 * The exemptions are the interesting half and each says something different: a
 * toolbox can be unmapped because it is polymorphic and either answer would be
 * false on one branch (`agent`), because the primitives are real but nothing
 * qualifies them yet (`quorum`), or because there is no vector to run at all
 * (`webauthn`). Those are three different facts and collapsing them into "not
 * gated" is how the real gaps hid among them.
 *
 * `age` used to be a fourth kind — "its math is a third-party package no CAST
 * qualifies" — and that is the one an exemption cannot stay true about, because
 * it describes a missing test rather than an impossible one. CAST-15 now runs
 * the age project's own published testkit vector, so `age` names the `age`
 * suite and has come off this list. That is what the list shrinking looks like.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { listSteps } from "../lib/toolkit/registry.js";
import { toolboxToSuite } from "../lib/toolkit/suite-gate.js";

const LIB = fileURLToPath(new URL("../lib/toolkit/", import.meta.url));

/**
 * Toolboxes that reach a primitive and still name no suite, each with the
 * reason it cannot name one. **May only shrink.**
 *
 * An entry here is a claim that no honest suite exists for that toolbox — not
 * that gating it would be inconvenient.
 */
const UNGATEABLE = {
  agent:
    "polymorphic: `agent.sign` emits an OpenPGP signature for a PGP key and an sshsig for an SSH key, so either suite is false on one branch",
  quorum:
    "the session's ECDH/HKDF/AES-GCM live in `lib/notebook/crypto.js` and are not CAST-gated today, which `docs/CRYPTOGRAPHY.md` states outright",
  webauthn:
    "a passkey's keypair lives inside an authenticator this page cannot address, so there is no vector to run and no result to gate on",
};

/** The file with its comments removed — prose naming a primitive is not a use. */
function codeOf(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
}

/** Does this toolbox's ops file reach a cryptographic primitive in code? */
function reachesCrypto(toolbox) {
  for (const name of [`${toolbox}-ops.js`, `${toolbox}.js`]) {
    let text;
    try {
      text = codeOf(readFileSync(LIB + name, "utf8"));
    } catch {
      continue;
    }
    if (/crypto\.subtle|webcrypto-ops|@noble|from "openpgp"|age-encryption/.test(text)) return true;
  }
  return false;
}

/** Every toolbox the registry declares, with its suite. */
function toolboxes() {
  const seen = new Map();
  for (const step of listSteps()) {
    const tb = String(step.toolbox || "");
    if (tb) seen.set(tb, toolboxToSuite(tb));
  }
  return seen;
}

describe("the suite gate reaches every toolbox that does crypto", () => {
  it("finds the toolboxes it is measuring", () => {
    // An empty sweep passes every assertion below it.
    const all = toolboxes();
    expect(all.size, "the registry declares no toolboxes at all").toBeGreaterThan(8);
    expect(all.get("webcrypto"), "the suite map stopped answering").toBe("webcrypto");
  });

  it("gates every toolbox whose code reaches a primitive, or records why not", () => {
    const ungated = [];
    for (const [tb, suite] of toolboxes()) {
      if (suite) continue;
      if (tb in UNGATEABLE) continue;
      if (reachesCrypto(tb)) ungated.push(tb);
    }
    expect(
      ungated,
      `these toolboxes reach a cryptographic primitive and name no suite, so FIPS mode cannot see them: ${ungated.join(", ")}`
    ).toEqual([]);
  });

  it("keeps the exemption list honest — nothing on it is gated now", () => {
    // An exemption for a toolbox that *does* name a suite is a comment
    // asserting something untrue about the map beside it.
    const map = toolboxes();
    for (const tb of Object.keys(UNGATEABLE)) {
      expect(map.has(tb), `${tb} is not a toolbox any more, so its exemption is stale`).toBe(true);
      expect(
        map.get(tb),
        `${tb} names a suite now, so take it off the list`
      ).toBeNull();
    }
  });

  it("holds the two that were missing, by name", () => {
    // Named rather than swept, because "every crypto toolbox is gated" is also
    // satisfied by deleting the toolboxes — and these two are the reason this
    // file exists.
    expect(toolboxToSuite("jose"), "jose stopped being gated").toBe("webcrypto");
    expect(toolboxToSuite("otp"), "otp stopped being gated").toBe("webcrypto");
  });

  it("gates age on its own suite, and never on a borrowed one", () => {
    // The exemption that came off the list. `age` must name a suite — that is
    // the gap closing — and it must not name `webcrypto`, because the CAST that
    // qualifies it ran age's vectors and not SubtleCrypto's. Mapping it to
    // `webcrypto` would turn one green self-test into a claim about two
    // different bodies of code, which is the failure this whole file guards.
    expect(toolboxToSuite("age"), "age lost its suite again").toBe("age");
  });
});
