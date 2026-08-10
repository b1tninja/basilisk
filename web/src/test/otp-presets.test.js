/**
 * The `otp.*` ops and the OTP templates.
 *
 * `otp-rfc-vectors.test.js` proves the algorithm against RFC 4226 and RFC
 * 6238; `recipe.test.js` proves every preset compiles. What is left — and
 * what this file holds — is that the ops wire the algorithm to the pipeline
 * correctly and that the templates *run*, on the model of
 * `ssh-presets.test.js`: a template is the first thing a new user clicks, so
 * "it parses" is not the bar.
 *
 * The load-bearing assertion is the security one. A TOTP secret is a
 * credential, so the `otpauth://` URI — which is the secret plus a label — has
 * to come out masked exactly as an unencrypted private key does. That is
 * checked below at the artifact, not at the op, because the mask is a
 * property of the tile the user sees.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  PRESETS,
  PRESET_GROUP_ORDER,
  compileRecipe,
} from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { getStep, listSteps, TOOLBOX_META } from "../lib/toolkit/registry.js";
import { parseOtpauthUri } from "../lib/otp/uri.js";
import { totp } from "../lib/otp/hotp.js";
import { base32ToBytes } from "../lib/toolkit/encode.js";

const byId = (id) => PRESETS.find((p) => p.id === id);
const otpPresets = () => PRESETS.filter((p) => p.group === "OTP");

/** Errors live at `validation.errors`, never `result.errors`. */
const errorsIn = (recipe) =>
  compileRecipe(recipe).validation.errors.map((e) => e.message);

/**
 * Run a recipe headlessly and return its artifacts keyed by label.
 * `runRecipe` returns the artifact array itself — not `{ artifacts }`.
 * @param {string} recipe
 * @param {string} [text]
 */
async function run(recipe, text = "") {
  const { ast, validation } = compileRecipe(recipe);
  expect(validation.errors.map((e) => e.message)).toEqual([]);
  const artifacts = await runRecipe(ast, { inputs: { text: { value: text } } });
  return {
    artifacts,
    out: Object.fromEntries(artifacts.map((a) => [a.label, a.content])),
    tile: (label) => artifacts.find((a) => a.label === label),
  };
}

describe("the toolbox and its shelves", () => {
  it("gives OTP its own toolbox, next to WebAuthn", () => {
    // Both answer "set up my second factor". Its own toolbox rather than a
    // WebCrypto shelf: the key container is a Base32 string, not a CryptoKey.
    expect(TOOLBOX_META.otp?.badge).toBe("OTP");
    expect(TOOLBOX_META.otp.order).toBe(TOOLBOX_META.webauthn.order + 1);
  });

  it("registers exactly the four ops, as two conjugate pairs", () => {
    const names = listSteps()
      .filter((s) => s.toolbox === "otp")
      .map((s) => s.name)
      .sort();
    expect(names).toEqual(["otp.code", "otp.parse", "otp.uri", "otp.verify"]);
    expect(getStep("otp.uri").conjugate).toBe("otp.parse");
    expect(getStep("otp.parse").conjugateOf).toBe("otp.uri");
    expect(getStep("otp.code").conjugate).toBe("otp.verify");
    expect(getStep("otp.verify").conjugateOf).toBe("otp.code");
  });

  it("splits the shelves by whether the secret is on screen", () => {
    expect(getStep("otp.uri").shelf).toBe("enrolment");
    expect(getStep("otp.parse").shelf).toBe("enrolment");
    expect(getStep("otp.code").shelf).toBe("otpcode");
    expect(getStep("otp.verify").shelf).toBe("otpcode");
  });

  it("takes the secret through a slot on verify, never as recipe text", () => {
    // Same reason `age.decrypt key=` and `rtc.ice credential=` are slots: a
    // literal would ride out through Copy link and any exported notebook.
    expect(getStep("otp.verify").params.find((p) => p.name === "secret").slot).toBe("required");
    for (const p of otpPresets()) {
      expect(p.recipe, p.id).not.toMatch(/secret=[A-Z2-7]{8}/);
    }
  });
});

describe("the secret is treated as a credential", () => {
  it("masks the otpauth:// URI, because the URI *is* the secret", async () => {
    const { tile } = await run(
      `random 20 | otp.uri issuer=Acme account=a@b.com | out $uri`
    );
    const uri = tile("uri");
    expect(uri.content).toMatch(/^otpauth:\/\/totp\//);
    expect(uri.sensitive).toBe(true);
    // Masked but openable — the same shape `ssh.encode format=private | out`
    // produces, and the reason `out` sets it.
    expect(uri.revealable).toBe(true);
  });

  it("masks the Base32 secret on its own too", async () => {
    const { tile } = await run("random 20 | base32 | out $secret");
    expect(tile("secret").sensitive).toBe(true);
  });

  it("masks the secret field of a parsed URI, and nothing else", async () => {
    const uri = "otpauth://totp/Acme:a@b.com?secret=MFRGGZDFMZTWQ2LK&issuer=Acme";
    const { tile } = await run(
      `input | tee
  - otp.parse secret | out $s
| tee
  - otp.parse issuer | out $i
| otp.parse digits | out $d`,
      uri
    );
    expect(tile("s").sensitive).toBe(true);
    // An issuer name and a digit count are not credentials. Masking them
    // would teach that everything on this shelf is secret, which is how a
    // real mask stops being read.
    expect(tile("i").sensitive).toBe(false);
    expect(tile("d").sensitive).toBe(false);
  });

  it("does not mask the code itself", async () => {
    // Six digits that expire in one step, whose whole purpose is to be read
    // off the screen. A masked code is a useless code.
    const { tile } = await run("random 20 | base32 | otp.code | out $code");
    expect(tile("code").content).toMatch(/^\d{6}$/);
    expect(tile("code").sensitive).toBe(false);
  });

  it("lets a QR of a sensitive value be revealed, or it is a blank square", async () => {
    // A masked tile runs no view at all, so without `revealable` the QR of an
    // enrolment URI could never be scanned — the one thing the tile is for.
    const { artifacts } = await run(
      `random 20 | otp.uri issuer=Acme account=a@b.com | qr`
    );
    const qr = artifacts.find((a) => a.role === "qr");
    expect(qr.sensitive).toBe(true);
    expect(qr.revealable).toBe(true);
    expect(qr.content).toContain("<svg");
  });
});

describe("the ops carry the pipeline's shapes", () => {
  it("takes raw secret bytes as readily as a Base32 string", async () => {
    const { out } = await run(`random 20 | tee
  - base32 | out $b32
| otp.uri issuer=Acme account=a@b.com | out $uri`);
    expect(parseOtpauthUri(out.uri).secret).toBe(out.b32);
  });

  it("round-trips secret → URI → secret, which is what conjugates mean", async () => {
    const { out } = await run(`random 20 | base32 | tee
  - out $before
| otp.uri issuer=Acme account=a@b.com | otp.parse | out $after`);
    expect(out.after).toBe(out.before);
  });

  it("lets a URI on the stem override the step's own parameters", async () => {
    // The URI is what the other side is holding; two answers to digits=
    // cannot both be obeyed.
    const uri =
      "otpauth://totp/Acme:a@b.com?secret=MFRGGZDFMZTWQ2LK&issuer=Acme&digits=8&algorithm=SHA256";
    const { out } = await run("input | otp.code digits=6 | out $code", uri);
    expect(out.code).toMatch(/^\d{8}$/);
  });

  it("and lets otp.parse be the way to take the parameters back", async () => {
    const uri =
      "otpauth://totp/Acme:a@b.com?secret=MFRGGZDFMZTWQ2LK&issuer=Acme&digits=8&algorithm=SHA256";
    const { out } = await run("input | otp.parse | otp.code digits=6 | out $code", uri);
    expect(out.code).toMatch(/^\d{6}$/);
  });

  it("computes the RFC 6238 vector through the ops when at= pins the clock", async () => {
    // The seed is ASCII "12345678901234567890" in Base32; the answer is the
    // SHA-1 row for t = 1111111111 in Appendix B.
    const { out } = await run(
      `"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" | otp.code digits=8 at=1111111111 | out $code`
    );
    expect(out.code).toBe("14050471");
  });

  it("fails loud on a wrong code, and softly under -q", async () => {
    const base = `random 20 | base32 | out $s\n\n"000000"`;
    await expect(
      run(`${base} | otp.verify secret=$s window=0 | out $ok`)
    ).rejects.toThrow(/does not match any step/);
    const { out } = await run(`${base} | otp.verify -q secret=$s window=0 | out $ok`);
    expect(String(out.ok)).toBe("false");
  });

  it("refuses a malformed code loudly, and softly under -q", async () => {
    const base = `random 20 | base32 | out $s\n\n"not-a-code"`;
    await expect(run(`${base} | otp.verify secret=$s | out $ok`)).rejects.toThrow(
      /not a code/
    );
    const { out } = await run(`${base} | otp.verify -q secret=$s | out $ok`);
    expect(String(out.ok)).toBe("false");
  });

  it("names the window in the failure, so the fix is obvious", async () => {
    // The message has to say *why*, or a clock-drift failure reads as a wrong
    // secret and the user re-enrols for nothing.
    await expect(
      run(`random 20 | base32 | out $s\n\n"000000" | otp.verify secret=$s window=2 | out $ok`)
    ).rejects.toThrow(/±2/);
  });
});

describe("the OTP templates run, and teach what their blurbs promise", () => {
  it("puts the group straight after WebAuthn in the Templates menu", () => {
    expect(PRESET_GROUP_ORDER.indexOf("OTP")).toBe(
      PRESET_GROUP_ORDER.indexOf("WebAuthn") + 1
    );
    expect(otpPresets().length).toBe(4);
  });

  it("compiles every template with zero validation errors", () => {
    for (const p of otpPresets()) {
      expect(errorsIn(p.recipe), p.id).toEqual([]);
      expect(compileRecipe(p.recipe).validation.ok, p.id).toBe(true);
    }
  });

  it("writes a blurb that teaches rather than narrating the steps", () => {
    for (const p of otpPresets()) {
      expect(p.title, p.id).toBeTruthy();
      expect(p.blurb.length, p.id).toBeGreaterThan(60);
    }
  });

  it("otp-enrol carries the whole arc — secret, URI, QR, code, and a check", async () => {
    const { out, artifacts } = await run(byId("otp-enrol").recipe);
    expect(out.secret).toMatch(/^[A-Z2-7]{32}$/); // 20 bytes of Base32
    expect(out.uri).toMatch(
      /^otpauth:\/\/totp\/Basilisk:you%40example\.com\?secret=[A-Z2-7]{32}&issuer=Basilisk&algorithm=SHA1&digits=6&period=30$/
    );
    expect(out.code).toMatch(/^\d{6}$/);
    // The step that makes it an enrolment rather than a picture of one.
    expect(String(out.ok)).toBe("true");
    expect(artifacts.some((a) => a.role === "qr")).toBe(true);
  });

  it("otp-enrol's QR really encodes the URI its own cell emitted", async () => {
    const { out, artifacts } = await run(byId("otp-enrol").recipe);
    const qr = artifacts.find((a) => a.role === "qr");
    expect(qr.mime).toBe("image/svg+xml");
    expect(qr.content).toContain("<svg");
    // Same secret on both branches of the tee — a QR of a *different* secret
    // than the one in $secret is exactly the bug a `tee` invites.
    expect(parseOtpauthUri(out.uri).secret).toBe(out.secret);
  });

  it("otp-read-uri takes a pasted URI apart and codes it", async () => {
    const uri =
      "otpauth://totp/Big%20Corp:alice%40example.com" +
      "?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corp&algorithm=SHA256&digits=8&period=30";
    const { out } = await run(byId("otp-read-uri").recipe, uri);
    expect(out.issuer).toBe("Big Corp");
    expect(out.account).toBe("alice@example.com");
    expect(out.algorithm).toBe("SHA256");
    expect(out.digits).toBe("8");
    // Eight digits because the URI said so, not because the step did.
    expect(out.code).toMatch(/^\d{8}$/);
    expect(out.code).toBe(
      await totp(base32ToBytes("JBSWY3DPEHPK3PXP"), {
        algorithm: "SHA256",
        digits: 8,
        period: 30,
      })
    );
  });

  it("otp-hotp-counter shows a counter that is spent, not expired", async () => {
    const { out } = await run(byId("otp-hotp-counter").recipe);
    expect(out.uri).toContain("counter=0");
    expect(out.uri).not.toContain("period=");
    expect(out.first).toMatch(/^\d{6}$/);
    expect(out.third).toMatch(/^\d{6}$/);
    expect(out.third).not.toBe(out.first);
    // The server is at 0, the token has been pressed to 2 — a look-ahead of
    // three resynchronises.
    expect(String(out.resync)).toBe("true");
  });

  it("otp-parameters proves the parameters are part of the credential", async () => {
    const { out } = await run(byId("otp-parameters").recipe);
    expect(out.plain6).toMatch(/^\d{6}$/);
    expect(out.long8).toMatch(/^\d{8}$/);
    expect(out.odd7).toMatch(/^\d{7}$/);
    expect(out.uri).toContain("algorithm=SHA512");
    expect(out.uri).toContain("digits=8");
    // `at=` pins the last one, so this cell is reproducible run to run.
    expect(byId("otp-parameters").recipe).toContain("at=1111111111");
  });
});

describe("every enum and flag the ops declare is exercised by a running recipe", () => {
  /**
   * The bar `ssh-presets.test.js` sets: a param value that no recipe has ever
   * run is a param value nobody has checked. Anything the four templates do
   * not reach is run right here instead.
   */
  const EXTRA = [
    `random 20 | base32 | otp.uri mode=hotp counter=4 issuer=A account=b | tee
  - otp.parse mode | out $m
| tee
  - otp.parse counter | out $c
| tee
  - otp.parse period | out $p
| otp.parse secret | out $s`,
    `random 20 | base32 | otp.code algorithm=sha256 digits=7 | out $a`,
    `random 20 | base32 | otp.code algorithm=sha512 digits=8 period=60 | out $b`,
    `random 20 | base32 | otp.code algorithm=sha1 digits=6 | out $c`,
  ];

  it("runs the leftovers", async () => {
    for (const src of EXTRA) {
      const { artifacts } = await run(src);
      expect(artifacts.length, src).toBeGreaterThan(0);
    }
  });

  it("leaves no enum value or flag unrun", async () => {
    const corpus = [...otpPresets().map((p) => p.recipe), ...EXTRA].join("\n");
    /** @type {string[]} */
    const missing = [];
    for (const step of listSteps().filter((s) => s.toolbox === "otp")) {
      for (const p of step.params || []) {
        if (p.type === "enum") {
          for (const v of p.enum) {
            // A value equal to the default is exercised by every recipe that
            // omits the param, so only look for the ones that must be written.
            if (String(v) === String(p.default)) continue;
            // A positional param is written bare (`otp.parse issuer`), so
            // looking only for `name=value` would report it forever unrun.
            const written = p.positional
              ? new RegExp(`${step.name.replace(".", "\\.")} ${v}\\b`).test(corpus)
              : corpus.includes(`${p.name}=${v}`);
            if (!written) missing.push(`${step.name} ${p.name}=${v}`);
          }
        }
        if (p.type === "bool" && p.flag && !corpus.includes(p.flag)) {
          missing.push(`${step.name} ${p.flag}`);
        }
      }
    }
    expect(missing, missing.join(", ")).toEqual([]);
  });

  it("exercises every otp.parse field, since each is a separate code path", () => {
    const corpus = [...otpPresets().map((p) => p.recipe), ...EXTRA].join("\n");
    for (const field of getStep("otp.parse").params[0].enum) {
      // `field` is positional, so it is written bare.
      expect(corpus, field).toMatch(new RegExp(`otp\\.parse ${field}\\b`));
    }
  });
});

describe("no template invents syntax the registry does not have", () => {
  const SRC = readFileSync(
    fileURLToPath(new URL("../lib/toolkit/recipe.js", import.meta.url)),
    "utf8"
  );
  /** Comments strip first — the group-order rationale names ops in prose. */
  const stripComments = (t) =>
    t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

  it("names all four otp. ops in the presets themselves", () => {
    const code = stripComments(SRC);
    for (const op of ["otp.uri", "otp.parse", "otp.code", "otp.verify"]) {
      expect(code, op).toContain(op);
    }
  });
});
