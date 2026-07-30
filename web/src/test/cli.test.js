/**
 * Vitest: the headless CLI (`web/cli/`).
 *
 * Two layers on purpose.
 *
 * Most cases drive `main(argv, io)` in-process — fast, and it can assert on
 * exact stdout. But Vitest resolves Vite's `?raw` asset imports for free,
 * which is precisely the thing plain Node cannot do; a suite that only ever
 * ran in-process would have been green while `node cli/basilisk.js` died on
 * `Unknown file extension ".txt"`. So the round trip is *also* run as a real
 * child process, which is the only test here that proves the shipped binary
 * works.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, describe, expect, it } from "vitest";
import { rmSync } from "node:fs";
import { EXIT, main } from "../../cli/main.js";
import { parseSharesFile } from "../../cli/bindings.js";
import { listSteps } from "../lib/toolkit/registry.js";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI_BIN = resolve(here, "../../cli/basilisk.js");

const workdirs = [];
function workdir() {
  const dir = mkdtempSync(join(tmpdir(), "basilisk-cli-"));
  workdirs.push(dir);
  return dir;
}
afterAll(() => {
  // These recipes emit real shares and private keys; do not leave them in tmp.
  for (const dir of workdirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

/**
 * @param {string} dir
 * @param {string} name
 * @param {string} content
 */
function file(dir, name, content) {
  const path = join(dir, name);
  writeFileSync(path, content, "utf8");
  return path;
}

/** Capture a run of the CLI in-process. */
async function cli(argv, ctx = {}) {
  /** @type {string[]} */
  const out = [];
  /** @type {string[]} */
  const err = [];
  const code = await main(argv, {
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    env: ctx.env || {},
    stdin: ctx.stdin,
  });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

const SPLIT_RECOVER = `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share

shares | blip39.decode | sss.combine | base64 | out @secret
`;

describe("basilisk run", () => {
  it("runs split → recover in one session, slots crossing cells", async () => {
    const dir = workdir();
    const recipe = file(dir, "split-recover.txt", SPLIT_RECOVER);
    const outDir = join(dir, "artifacts");

    const { code, out } = await cli(["run", recipe, "--out-dir", outDir, "--json"]);
    expect(code).toBe(EXIT.ok);

    const artifacts = JSON.parse(out);
    const shares = artifacts.filter((a) => a.role === "share");
    expect(shares).toHaveLength(3);

    // The recover cell never saw a paste panel: it consumed the indexed share
    // slots the split cell's foreach registered, exactly as the notebook does.
    const secret = artifacts.find((a) => /secret/i.test(a.label || ""));
    expect(secret, "recovered @secret artifact").toBeTruthy();
    const raw = Buffer.from(String(secret.content).trim(), "base64");
    expect(raw.length).toBe(32);

    // --out-dir writes one file per artifact, named by the artifact.
    const written = readdirSync(outDir).sort();
    expect(written).toContain("secret.txt");
    expect(written.filter((f) => f.startsWith("share-"))).toHaveLength(3);
    expect(readFileSync(join(outDir, "secret.txt"), "utf8")).toBe(secret.content);
  });

  it("recovers from a --shares file with threshold-many mnemonics", async () => {
    const dir = workdir();
    const split = file(dir, "split.txt", SPLIT_RECOVER.split("\n\n")[0]);
    const splitRun = await cli(["run", split, "--json"]);
    expect(splitRun.code).toBe(EXIT.ok);
    const mnemonics = JSON.parse(splitRun.out)
      .filter((a) => a.role === "share")
      .map((a) => a.content);
    expect(mnemonics).toHaveLength(3);

    // A fresh process would have no slots; the shares file is the whole input.
    // Two of three: the recipe's threshold, not all of them.
    const sharesFile = file(
      dir,
      "shares.txt",
      `# recovered from cold storage\n${mnemonics[0]}\n\n${mnemonics[2]}\n`
    );
    const recover = file(dir, "recover.txt", "shares | blip39.decode | sss.combine | base64 | out @secret\n");

    const { code, out } = await cli(["run", recover, "--shares", sharesFile, "--json"]);
    expect(code).toBe(EXIT.ok);
    const secret = JSON.parse(out).find((a) => /secret/i.test(a.label || ""));
    expect(Buffer.from(String(secret.content).trim(), "base64").length).toBe(32);
  });

  it("feeds the `input` op from --input and from stdin identically", async () => {
    const dir = workdir();
    const recipe = file(dir, "hash.txt", "input | utf8 | digest | encode hex | out @hash\n");
    // SHA-256("hello world"), so a wrong binding cannot pass by accident.
    const expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    const flag = await cli(["run", recipe, "--input", "hello world"]);
    expect(flag.code).toBe(EXIT.ok);
    expect(flag.out).toContain(expected);

    const piped = await cli(["run", recipe, "--stdin"], { stdin: "hello world" });
    expect(piped.code).toBe(EXIT.ok);
    expect(piped.out).toContain(expected);
  });

  it("decrypts with --ciphertext, --private-key and --passphrase-env", async () => {
    const { createMessage, encrypt, generateKey, readKey } = await import("openpgp");
    const passphrase = "correct horse battery staple";
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "CLI", email: "cli@example.org" }],
      passphrase,
      format: "armored",
    });
    const armoredCiphertext = await encrypt({
      message: await createMessage({ text: "ciphertext binding works" }),
      encryptionKeys: await readKey({ armoredKey: publicKey }),
    });

    const dir = workdir();
    const recipe = file(dir, "decrypt.txt", "gpg.decrypt | out @plain\n");
    const ct = file(dir, "message.asc", String(armoredCiphertext));
    const key = file(dir, "secret.asc", privateKey);

    const { code, out } = await cli(
      [
        "run",
        recipe,
        "--ciphertext",
        ct,
        "--private-key",
        key,
        "--passphrase-env",
        "BASILISK_TEST_PW",
      ],
      { env: { BASILISK_TEST_PW: passphrase } }
    );
    expect(code).toBe(EXIT.ok);
    expect(out).toContain("ciphertext binding works");
  });

  it("refuses --passphrase-env when the variable is unset, and has no --passphrase", async () => {
    const dir = workdir();
    const recipe = file(dir, "decrypt.txt", "gpg.decrypt | out @plain\n");
    const unset = await cli(["run", recipe, "--passphrase-env", "BASILISK_NOT_SET"], {
      env: {},
    });
    expect(unset.code).toBe(EXIT.runtime);
    expect(unset.err).toMatch(/unset or empty/);

    // A bare --passphrase would land in shell history and `ps`; it is not a flag.
    const bare = await cli(["run", recipe, "--passphrase", "hunter2"]);
    expect(bare.code).toBe(EXIT.usage);
    expect(bare.err).toMatch(/unknown option --passphrase/);
  });
});

describe("browser-only ops", () => {
  it("names the step and the missing surface for a webrtc op (pre-flight)", async () => {
    const dir = workdir();
    // Cell 1 is perfectly runnable; the point is that it does NOT run — the
    // pre-flight refuses before doing crypto work rather than half-executing.
    const recipe = file(
      dir,
      "rtc.txt",
      "random 8 | encode hex | out @nonce\n\nrtc.certificate | out @cert\n"
    );
    const { code, out, err } = await cli(["run", recipe]);
    expect(code).toBe(EXIT.browserOnly);
    expect(err).toContain('browser-only op: "rtc.certificate"');
    expect(err).toContain("cell 2, step 1");
    expect(err).toContain("WebRTC (RTCPeerConnection)");
    expect(out).toBe("");
  });

  it("classifies a clipboard op at dispatch, from the op's own failure", async () => {
    const dir = workdir();
    const recipe = file(dir, "clip.txt", '"hello" | clipboard.write | out @copied\n');
    const { code, err } = await cli(["run", recipe]);
    expect(code).toBe(EXIT.browserOnly);
    expect(err).toContain('browser-only op: "clipboard.write"');
    expect(err).toContain("cell 1, step 2");
    expect(err).toContain("Clipboard API");
    // Never a bare stack or an undefined-property crash.
    expect(err).not.toMatch(/undefined|at Object\.|TypeError/);
  });

  it("does not blanket-block a toolbox: webauthn.attest is a headless parser", async () => {
    const dir = workdir();
    // Garbage input, but the failure must be about the *bytes*, not about a
    // browser surface — `webauthn.attest` decodes pasted data and needs none.
    const recipe = file(dir, "attest.txt", "input | webauthn.attest | out @report\n");
    const { code, err } = await cli(["run", recipe, "--input", "not-an-attestation"]);
    expect(code).toBe(EXIT.runtime);
    expect(err).not.toContain("browser-only op");
  });
});

describe("basilisk check", () => {
  it("exits non-zero on an invalid recipe, with the message the UI shows", async () => {
    const dir = workdir();
    const recipe = file(dir, "bad.txt", "genkey ec/p256 | frobnicate | out @x\n");
    const { code, err } = await cli(["check", recipe]);
    expect(code).toBe(EXIT.invalidRecipe);
    // The validator's own string, unchanged — same text as the cell banner.
    expect(err).toContain('Unknown step "frobnicate"');
  });

  it("reports a forward slot reference rather than failing at run time", async () => {
    const dir = workdir();
    const recipe = file(dir, "forward.txt", "@later | out @x\n\ngenkey ec/p256 | out @later\n");
    const { code, out } = await cli(["check", recipe, "--json"]);
    expect(code).toBe(EXIT.invalidRecipe);
    const report = JSON.parse(out);
    expect(report.ok).toBe(false);
    expect(report.errors.join("\n")).toMatch(/later/);
  });

  it("accepts a valid multi-cell recipe and counts the cells", async () => {
    const dir = workdir();
    const recipe = file(dir, "ok.txt", SPLIT_RECOVER);
    const { code, out } = await cli(["check", recipe]);
    expect(code).toBe(EXIT.ok);
    expect(out).toMatch(/^ok — 2 cells/);
  });

  it("--json carries errors, warnings and the runtime inputs a run would need", async () => {
    const dir = workdir();
    const recipe = file(dir, "needs.txt", "input | utf8 | digest | out @d\n");
    const { code, out } = await cli(["check", recipe, "--json"]);
    expect(code).toBe(EXIT.ok);
    const report = JSON.parse(out);
    expect(report.ok).toBe(true);
    expect(report.errors).toEqual([]);
    expect(report.inputNeeds).toContain("text");
  });

  it("check never executes the recipe — a browser-only op still validates", async () => {
    const dir = workdir();
    const recipe = file(dir, "rtc.txt", "rtc.certificate | out @cert\n");
    const { code } = await cli(["check", recipe]);
    expect(code).toBe(EXIT.ok);
  });
});

describe("basilisk list-ops", () => {
  it("emits every registered op, generated from listSteps()", async () => {
    const { code, out } = await cli(["list-ops", "--json"]);
    expect(code).toBe(EXIT.ok);
    const listed = JSON.parse(out);
    const registered = listSteps();
    expect(listed).toHaveLength(registered.length);
    expect(listed.map((s) => s.name).sort()).toEqual(
      registered.map((s) => s.name).sort()
    );
    for (const op of listed) {
      expect(op.toolbox, `${op.name} toolbox`).toBeTruthy();
      expect(op.doc, `${op.name} doc`).toBeTruthy();
    }
  });

  it("the column view lists the same ops, one line each", async () => {
    const { code, out } = await cli(["list-ops"]);
    expect(code).toBe(EXIT.ok);
    const lines = out.split("\n").filter(Boolean);
    expect(lines).toHaveLength(listSteps().length);
    for (const step of listSteps()) {
      expect(
        lines.some((l) => l.startsWith(`${step.name} `) || l.startsWith(`${step.name}  `)),
        `${step.name} missing from column view`
      ).toBe(true);
    }
  });

  it("filters by toolbox", async () => {
    const { code, out } = await cli(["list-ops", "--json", "--toolbox", "webrtc"]);
    expect(code).toBe(EXIT.ok);
    const listed = JSON.parse(out);
    expect(listed.length).toBeGreaterThan(0);
    expect(listed.every((s) => s.toolbox === "webrtc")).toBe(true);
  });
});

describe("shares file parsing", () => {
  it("is one mnemonic per line, ignoring blanks and comments", () => {
    expect(parseSharesFile("# note\nalpha beta\n\n  gamma   delta \n")).toEqual([
      "alpha beta",
      "gamma delta",
    ]);
  });
});

describe("the shipped binary", () => {
  // The only test that runs `node cli/basilisk.js` for real. Vitest supplies
  // Vite's `?raw` transform; plain Node does not, and `blip39` needs the
  // SLIP-0039 wordlist through exactly that import. This is what proves the
  // loader hooks in cli/basilisk.js are wired.
  it("runs the split → recover round trip as a child process", async () => {
    const dir = workdir();
    const recipe = file(dir, "split-recover.txt", SPLIT_RECOVER);
    const { stdout } = await execFileAsync(
      process.execPath,
      [CLI_BIN, "run", recipe, "--json"],
      { cwd: dirname(CLI_BIN) }
    );
    const artifacts = JSON.parse(stdout);
    expect(artifacts.filter((a) => a.role === "share")).toHaveLength(3);
    const secret = artifacts.find((a) => /secret/i.test(a.label || ""));
    expect(Buffer.from(String(secret.content).trim(), "base64").length).toBe(32);
  }, 60000);

  it("exits 4 with the browser-only message, not a stack trace", async () => {
    const dir = workdir();
    const recipe = file(dir, "rtc.txt", "rtc.certificate | out @cert\n");
    await expect(
      execFileAsync(process.execPath, [CLI_BIN, "run", recipe], { cwd: dirname(CLI_BIN) })
    ).rejects.toMatchObject({
      code: EXIT.browserOnly,
      stderr: expect.stringContaining('browser-only op: "rtc.certificate"'),
    });
  }, 60000);
});
