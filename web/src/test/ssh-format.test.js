/**
 * SSH encodings against real `ssh-keygen` output (§29g).
 *
 * Interop is asserted the way age-ops.test.js asserts it: against checked-in
 * fixtures another implementation produced, byte for byte — not by round-
 * tripping through our own code, which would happily agree with its own
 * bugs. The fixtures' provenance is in fixtures/ssh/README.md.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildPublicBlob,
  parsePublicBlob,
  parsePublicLine,
  formatPublicLine,
} from "../lib/ssh/wire.js";
import {
  DEFAULT_KDF_ROUNDS,
  ENCRYPTED_KEY_MESSAGE,
  WRONG_PASSPHRASE_MESSAGE,
  encodeOpensshPrivateKey,
  parseOpensshPrivateKey,
} from "../lib/ssh/openssh-key-v1.js";
import { sshFingerprint } from "../lib/ssh/fingerprint.js";
import { parseSshsig, sshsigSign, sshsigVerify } from "../lib/ssh/sshsig.js";
import { STEPS } from "../lib/toolkit/registry.js";
import {
  SSH_DECODE_KIND_CONFLICT,
  inferParamDrivenType,
  matchOverload,
  typeOf,
} from "../lib/toolkit/types.js";
import {
  SSH_DECODE_FORMAT_MISMATCH,
  execSshDecode,
  execSshEncode,
} from "../lib/toolkit/ssh-ops.js";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url)), "utf8");
const fixtureBytes = (name) =>
  new Uint8Array(
    readFileSync(fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url)))
  );

const KEYS = ["id_ed25519", "id_ecdsa256", "id_ecdsa384", "id_ecdsa521", "id_rsa"];
const PAYLOAD = fixtureBytes("payload.txt");

/** The raw container bytes inside OPENSSH PRIVATE KEY armor. */
const unarmorBytes = (pem) =>
  Buffer.from(
    pem.match(/-----BEGIN OPENSSH PRIVATE KEY-----\n([\s\S]*?)-----END/)[1].replace(/\s+/g, ""),
    "base64"
  );

/**
 * Replace a length-prefixed string inside a container, fixing its prefix.
 * Only used to reach error branches that need a field no fixture carries.
 */
function patchString(bytes, from, to) {
  const at = bytes.indexOf(Buffer.from(from, "latin1"));
  if (at < 4) throw new Error(`patchString: "${from}" not found`);
  const head = bytes.subarray(0, at - 4);
  const tail = bytes.subarray(at + from.length);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(to.length);
  return Buffer.concat([head, len, Buffer.from(to, "latin1"), tail]);
}

const reArmor = (bytes) =>
  `-----BEGIN OPENSSH PRIVATE KEY-----\n${(bytes.toString("base64").match(/.{1,70}/g) || []).join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;

describe("public lines (RFC 4253)", () => {
  for (const name of KEYS) {
    it(`round-trips ${name}.pub byte-exact`, () => {
      const line = fixture(`${name}.pub`).trim();
      const parsed = parsePublicLine(line);
      expect(parsed.comment).toBe("fixture@basilisk");
      // Rebuild from typed fields, not from the stored blob — the rebuild is
      // what ssh.encode will do, so the rebuild is what must be byte-exact.
      const rebuilt = buildPublicBlob(parsed);
      expect(formatPublicLine(rebuilt, parsed.comment)).toBe(line);
    });
  }

  it("names the field when a blob is truncated", () => {
    const blob = buildPublicBlob(parsePublicLine(fixture("id_ed25519.pub")));
    // 15 bytes covers the length-prefixed "ssh-ed25519"; 20 cuts the key field.
    expect(() => parsePublicBlob(blob.subarray(0, 20))).toThrow(/ed25519 public key/);
    expect(() => parsePublicBlob(blob.subarray(0, 2))).toThrow(/public key algorithm/);
  });

  it("rejects a type/blob mismatch on a public line", () => {
    const line = fixture("id_ed25519.pub").trim().replace(/^ssh-ed25519/, "ssh-rsa");
    expect(() => parsePublicLine(line)).toThrow(/does not match blob type/);
  });
});

describe("openssh-key-v1 container", () => {
  for (const name of KEYS) {
    it(`decodes ${name} to material matching its public line`, async () => {
      const key = await parseOpensshPrivateKey(fixture(name));
      expect(key.comment).toBe("fixture@basilisk");
      expect(key.encrypted).toBe(false);
      const pubLine = parsePublicLine(fixture(`${name}.pub`));
      // The container's embedded public blob and the .pub file must agree.
      expect(Buffer.from(key.publicBlob).toString("base64")).toBe(
        Buffer.from(pubLine.blob).toString("base64")
      );
    });

    it(`re-encodes ${name} to a container that parses to the same material`, async () => {
      const key = await parseOpensshPrivateKey(fixture(name));
      const again = await parseOpensshPrivateKey(await encodeOpensshPrivateKey(key));
      expect(again.type).toBe(key.type);
      expect(again.comment).toBe(key.comment);
      expect(Buffer.from(again.publicBlob).toString("base64")).toBe(
        Buffer.from(key.publicBlob).toString("base64")
      );
    });
  }
});

/**
 * Passphrase-protected containers (§29f).
 *
 * Every encrypted fixture here is `ssh-keygen -p` applied to the *plaintext*
 * fixture beside it, so the bar is not "our decryptor agrees with our
 * encryptor" — it is "the private scalar we recover is byte-identical to the
 * one in the file ssh-keygen encrypted", which only a correct `bcrypt_pbkdf`
 * and a correct aes256-ctr can produce. The rounds counts differ on purpose
 * (1, 4, 16, 24): the KDF's round loop and its output interleave are separate
 * mistakes, and a single rounds count can hide either.
 */
describe("openssh-key-v1, passphrase-protected", () => {
  const PASSPHRASE = "correct horse";
  /** encrypted fixture → the plaintext fixture it was made from, and its rounds */
  const ENCRYPTED = [
    ["id_ed25519_enc1", "id_ed25519", 1],
    ["id_ecdsa256_enc", "id_ecdsa256", 4],
    ["id_rsa_enc", "id_rsa", 16],
  ];

  it.each(ENCRYPTED)(
    "%s decrypts to exactly the material in %s (ssh-keygen wrote both)",
    async (encName, plainName, rounds) => {
      const opened = await parseOpensshPrivateKey(fixture(encName), { passphrase: PASSPHRASE });
      const plain = await parseOpensshPrivateKey(fixture(plainName));
      expect(opened.encrypted).toBe(true);
      expect(opened.kdfRounds).toBe(rounds);
      // Every field, not just the public blob — the public half survives a
      // wrong key derivation intact (it is outside the encrypted section),
      // so comparing only it would pass on a broken KDF.
      const strip = ({ encrypted, kdfRounds, ...rest }) => rest;
      expect(strip(opened)).toEqual(strip(plain));
    }
  );

  it("decrypts the 24-round fixture to the public key ssh-keygen recorded", async () => {
    // id_ed25519_enc is its own key (not a copy of id_ed25519), so its .pub
    // is the independent witness here.
    const key = await parseOpensshPrivateKey(fixture("id_ed25519_enc"), {
      passphrase: PASSPHRASE,
    });
    expect(key.kdfRounds).toBe(24);
    expect(key.comment).toBe("fixture@basilisk");
    const witness = parsePublicLine(fixture("id_ed25519_enc.pub"));
    expect(Buffer.from(key.publicBlob).toString("base64")).toBe(
      Buffer.from(witness.blob).toString("base64")
    );
    // The seed the container held must generate that public key — which the
    // parser checks by comparing the private field's redundant public half.
    expect(Buffer.from(key.pub).toString("base64")).toBe(
      Buffer.from(witness.pub).toString("base64")
    );
    // The seed's public half is re-derived and checked inside the parser, so
    // reaching here at all means the 32 secret bytes are the right ones.
    expect(key.priv).toHaveLength(32);
  });

  it("names the passphrase it needs rather than failing as corruption", async () => {
    await expect(parseOpensshPrivateKey(fixture("id_ed25519_enc"))).rejects.toThrow(
      ENCRYPTED_KEY_MESSAGE
    );
  });

  it("tells a wrong passphrase apart from a corrupt file", async () => {
    // Both surface at the checkint pair; conflating them sends someone who
    // simply mistyped off to hunt for file damage.
    await expect(
      parseOpensshPrivateKey(fixture("id_ed25519_enc"), { passphrase: "wrong horse" })
    ).rejects.toThrow(WRONG_PASSPHRASE_MESSAGE);
  });

  it("names an unsupported cipher instead of failing on a length", async () => {
    // aes256-gcm is legal in this container and carries an auth tag we do not
    // parse. Swap the cipher name in a real fixture to reach the branch.
    const swapped = reArmor(
      patchString(unarmorBytes(fixture("id_ed25519_enc")), "aes256-ctr", "aes256-gcm@openssh.com")
    );
    await expect(
      parseOpensshPrivateKey(swapped, { passphrase: PASSPHRASE })
    ).rejects.toThrow(/unsupported cipher "aes256-gcm@openssh\.com"/);
  });

  it("round-trips through our own encryptor at the ssh-keygen default", async () => {
    const plain = await parseOpensshPrivateKey(fixture("id_ed25519"));
    const pem = await encodeOpensshPrivateKey(plain, { passphrase: "our passphrase" });
    // The header must be the pair ssh-keygen writes, or the file is ours alone.
    const header = unarmorBytes(pem);
    expect(Buffer.from(header).toString("latin1")).toContain("aes256-ctr");
    expect(Buffer.from(header).toString("latin1")).toContain("bcrypt");
    const again = await parseOpensshPrivateKey(pem, { passphrase: "our passphrase" });
    expect(again.kdfRounds).toBe(DEFAULT_KDF_ROUNDS);
    expect(Buffer.from(again.priv).toString("hex")).toBe(
      Buffer.from(plain.priv).toString("hex")
    );
  });

  it("treats an empty passphrase as no encryption, never as encryption with nothing", async () => {
    const plain = await parseOpensshPrivateKey(fixture("id_ed25519"));
    const pem = await encodeOpensshPrivateKey(plain, { passphrase: "" });
    expect(Buffer.from(unarmorBytes(pem)).toString("latin1")).not.toContain("bcrypt");
    expect((await parseOpensshPrivateKey(pem)).encrypted).toBe(false);
  });
});

/**
 * The other direction: containers **we** encrypted (§29f).
 *
 * The block above proves the reader — those fixtures came out of `ssh-keygen`.
 * Nothing proved the writer, and a round trip through our own encryptor and our
 * own decryptor cannot: two mistakes that cancel look exactly like none.
 *
 * So `ours_*_enc` are checked in as *frozen output*. Each was produced by
 * `encodeOpensshPrivateKey` from the plaintext fixture beside it, and each was
 * then handed to `ssh-keygen -y -P "correct horse"`, which printed the matching
 * public key — see `make-ours-enc.mjs`, which is the script that wrote them and
 * ran that check, and README.md, which records the transcript.
 *
 * What is machine-checked *here* is narrower and worth stating plainly: these
 * exact bytes decrypt to exactly the key that went in. That is a regression
 * gate on the writer — change the salt layout, the counter width, the padding
 * or the kdfoptions nesting and these files stop opening — but it is not the
 * interop assertion itself. The interop assertion is reproducible by running
 * the script on any machine with `ssh-keygen`, and is asserted live below when
 * one is present.
 */
describe("openssh-key-v1 we encrypted, frozen and re-read", () => {
  const PASSPHRASE = "correct horse";
  const OURS = [
    ["ours_ed25519_enc", "id_ed25519"],
    ["ours_ecdsa256_enc", "id_ecdsa256"],
    ["ours_rsa_enc", "id_rsa"],
  ];

  it.each(OURS)("%s opens to exactly the material in %s", async (encName, plainName) => {
    const opened = await parseOpensshPrivateKey(fixture(encName), { passphrase: PASSPHRASE });
    const plain = await parseOpensshPrivateKey(fixture(plainName));
    expect(opened.encrypted).toBe(true);
    // Written at the ssh-keygen default, not at whatever was cheapest to test:
    // a container we wrote at 16 rounds would open fine and be quietly weaker
    // than the one `ssh-keygen -p` beside it produces.
    expect(opened.kdfRounds).toBe(DEFAULT_KDF_ROUNDS);
    const strip = ({ encrypted, kdfRounds, ...rest }) => rest;
    expect(strip(opened)).toEqual(strip(plain));
  });

  it.each(OURS)("%s names aes256-ctr + bcrypt in the clear, as ssh-keygen does", (encName) => {
    const head = Buffer.from(unarmorBytes(fixture(encName))).toString("latin1").slice(0, 64);
    expect(head).toContain("aes256-ctr");
    expect(head).toContain("bcrypt");
  });

  it.each(OURS)(
    "%s carries the public blob of %s outside the encrypted section",
    async (encName, plainName) => {
      // This is the field `ssh-keygen -y` prints, so agreeing here is the part
      // of that check the suite can make without a local ssh-keygen.
      const opened = await parseOpensshPrivateKey(fixture(encName), { passphrase: PASSPHRASE });
      const witness = parsePublicLine(fixture(`${plainName}.pub`));
      expect(Buffer.from(opened.publicBlob).toString("base64")).toBe(
        Buffer.from(witness.blob).toString("base64")
      );
    }
  );

  const fixturePath = (name) =>
    fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url));

  /** `ssh-keygen -y -P` against a fixture — the exact call the test makes. */
  const derivePublic = (encName) =>
    spawnSync("ssh-keygen", ["-y", "-P", PASSPHRASE, "-f", fixturePath(encName)], {
      encoding: "utf8",
    });

  /**
   * And when there *is* a local `ssh-keygen`, stop taking the README's word
   * for it.
   *
   * The guard asks the question the test needs answered — "will ssh-keygen
   * read this file?" — by making the call and looking, rather than asking the
   * weaker "is there an ssh-keygen?" and hoping. Two ways the answer is no
   * and neither is news about our encoding:
   *
   *  - no binary, which is the whole reason the fixtures are checked in;
   *  - a binary that refuses the file before reading a byte of it, because
   *    the checkout's ACL is wider than `ssh-keygen` will tolerate
   *    (`UNPROTECTED PRIVATE KEY FILE`). That is what a fresh clone looks
   *    like on Windows, and it is why this used to fail on one machine and
   *    pass on the next within the hour.
   *
   * Not fixed by chmod-ing the fixtures: a mode bit on a checked-in file is
   * something the repository would then be asserting, on a platform where git
   * does not carry it faithfully, to satisfy a tool that is optional here.
   *
   * Any *other* nonzero exit falls through to the test and fails there —
   * "ssh-keygen rejected our container" is exactly the news this unit exists
   * to deliver, and a guard that swallowed it would be worse than no guard.
   */
  const willRead = (probe) => {
    if (probe.error) return false;
    if (probe.status === 0) return true;
    return !/UNPROTECTED PRIVATE KEY FILE|bad permissions|are too open/i.test(
      String(probe.stderr || "")
    );
  };

  const sshKeygenReadsFixtures = willRead(derivePublic(OURS[0][0]));

  // The guard's own branches, since the environment only ever exercises one of
  // them and the interesting one is the branch that must *not* swallow a real
  // refusal. Strings are OpenSSH's, from sshkey_perm_ok.
  it("skips on an absent or permission-refusing ssh-keygen, and only then", () => {
    expect(willRead({ error: new Error("ENOENT") })).toBe(false);
    expect(willRead({ status: 0, stderr: "" })).toBe(true);
    expect(
      willRead({
        status: 1,
        stderr:
          "@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @\n" +
          "Permissions for 'ours_ed25519_enc' are too open.\n" +
          'Load key "ours_ed25519_enc": bad permissions',
      })
    ).toBe(false);
    // An actual interop failure still runs the test, so it can fail there.
    expect(willRead({ status: 1, stderr: 'Load key "x": error in libcrypto' })).toBe(true);
    expect(willRead({ status: 1, stderr: 'Load key "x": incorrect passphrase' })).toBe(true);
  });

  it.runIf(sshKeygenReadsFixtures).each(OURS)(
    "%s is opened by the real ssh-keygen -y -P, deriving the public key of %s",
    (encName, plainName) => {
      const derived = derivePublic(encName);
      expect(derived.status, `ssh-keygen refused ${encName}: ${derived.stderr}`).toBe(0);
      // `-y` prints `type base64` with no comment; the fixture .pub has one.
      const pair = (s) => String(s).trim().split(/\s+/).slice(0, 2).join(" ");
      expect(pair(derived.stdout)).toBe(pair(fixture(`${plainName}.pub`)));
    }
  );
});

describe("fingerprints", () => {
  const lines = fixture("fingerprints.txt").trim().split("\n");
  for (let i = 0; i < KEYS.length; i++) {
    it(`matches ssh-keygen -lf for ${KEYS[i]}`, async () => {
      const expected = lines[i].split(/\s+/)[1];
      expect(expected).toMatch(/^SHA256:/);
      const { blob } = parsePublicLine(fixture(`${KEYS[i]}.pub`));
      expect(await sshFingerprint(blob)).toBe(expected);
    });
  }
});

describe("sshsig", () => {
  for (const name of ["id_ed25519", "id_ecdsa256", "id_rsa"]) {
    it(`verifies ssh-keygen -Y sign output from ${name}`, async () => {
      const sig = fixture(`payload.${name}.file.sshsig`);
      const { blob } = parsePublicLine(fixture(`${name}.pub`));
      await expect(
        sshsigVerify(PAYLOAD, sig, { namespace: "file", publicBlob: blob })
      ).resolves.toBe(true);
    });
  }

  it("verifies under the git namespace when asked for git", async () => {
    const sig = fixture("payload.id_ed25519.git.sshsig");
    await expect(sshsigVerify(PAYLOAD, sig, { namespace: "git" })).resolves.toBe(true);
  });

  it("refuses a namespace mismatch with the §31c message, verbatim", async () => {
    const sig = fixture("payload.id_ed25519.git.sshsig");
    await expect(sshsigVerify(PAYLOAD, sig, { namespace: "file" })).rejects.toThrow(
      'ssh.verify: signature was made under namespace "git", but namespace="file" was requested — a signature never transfers between namespaces.'
    );
  });

  it("refuses a tampered payload", async () => {
    const sig = fixture("payload.id_ed25519.file.sshsig");
    const tampered = new Uint8Array(PAYLOAD);
    tampered[0] ^= 1;
    await expect(sshsigVerify(tampered, sig, { namespace: "file" })).rejects.toThrow(
      /does not verify/
    );
  });

  it("refuses a signature pinned to a different key", async () => {
    const sig = fixture("payload.id_ed25519.file.sshsig");
    const { blob } = parsePublicLine(fixture("id_rsa.pub"));
    await expect(
      sshsigVerify(PAYLOAD, sig, { namespace: "file", publicBlob: blob })
    ).rejects.toThrow(/different key/);
  });

  it("signs ed25519 byte-identically to ssh-keygen (RFC 8032 is deterministic)", async () => {
    const key = await parseOpensshPrivateKey(fixture("id_ed25519"));
    const ours = await sshsigSign(PAYLOAD, key, { namespace: "file" });
    expect(ours).toBe(fixture("payload.id_ed25519.file.sshsig"));
  });

  it("round-trips a fresh ECDSA and RSA signature through its own verify", async () => {
    for (const name of ["id_ecdsa256", "id_ecdsa384", "id_ecdsa521", "id_rsa"]) {
      const key = await parseOpensshPrivateKey(fixture(name));
      const sig = await sshsigSign(PAYLOAD, key, { namespace: "file", hash: "sha256" });
      expect(parseSshsig(sig).hashAlg).toBe("sha256");
      await expect(
        sshsigVerify(PAYLOAD, sig, { namespace: "file", publicBlob: key.publicBlob })
      ).resolves.toBe(true);
    }
  });

  it("signs with a key that arrived passphrase-protected, matching the plaintext signature", async () => {
    // End-to-end proof that the decrypted scalar is the right one: an
    // ed25519 sshsig is deterministic (RFC 8032), so the signature made from
    // the encrypted fixture must be the exact bytes ssh-keygen produced from
    // the plaintext one. A near-miss key would verify against nothing.
    const opened = await parseOpensshPrivateKey(fixture("id_ed25519_enc1"), {
      passphrase: "correct horse",
    });
    const ours = await sshsigSign(PAYLOAD, opened, { namespace: "file" });
    expect(ours).toBe(fixture("payload.id_ed25519.file.sshsig"));
  });
});

/**
 * `ssh.decode` opens a protected key when a passphrase reaches it *somehow*.
 *
 * The two tests below write `inputs.gpg.passphrase` **by hand**, and that is
 * the only way they can: `buildBindings` composes `inputs.gpg` from
 * `armoredMessages` alone and never constructs `inputs.agent`, so no notebook
 * run populates either field. They are kept because the codec path they cover
 * is real and `panelPassphrase` is deliberately retained as the fallback for
 * when a panel field is finally wired (`agent.save protection=passphrase`
 * shares the same gap and would light up with it).
 *
 * The name of this block used to claim the panel was how a user did this. It
 * is not, and the reachable route — `passphrase=$slot` — is covered by the
 * block that follows. A test whose title names a mechanism that does not
 * exist is how the next reader learns something false.
 */
describe("ssh.decode opens a protected key when a passphrase reaches it", () => {
  const recipe = "input | ssh.decode format=private | ssh.fingerprint | out $fp";

  it("decodes when the passphrase is present", async () => {
    const { ast, validation } = compileRecipe(recipe);
    expect(validation.errors).toEqual([]);
    const artifacts = await runRecipe(ast, {
      inputs: { text: { value: fixture("id_ed25519_enc1") }, gpg: { passphrase: "correct horse" } },
    });
    const fp = artifacts.find((a) => a.label === "fp" || /^SHA256:/.test(String(a.content)));
    expect(String(fp.content).trim()).toBe(
      fixture("fingerprints.txt").trim().split("\n")[0].split(/\s+/)[1]
    );
  });

  it("names the missing passphrase when it is absent", async () => {
    const { ast } = compileRecipe(recipe);
    await expect(
      runRecipe(ast, { inputs: { text: { value: fixture("id_ed25519_enc1") } } })
    ).rejects.toThrow(ENCRYPTED_KEY_MESSAGE);
  });

  /**
   * …and the refusal has to name a control that exists.
   *
   * `buildBindings` composes `inputs.gpg` from `armoredMessages` alone and
   * never constructs `inputs.agent` at all, so the panel channel the two
   * tests above exercise is reachable only from a test that writes the
   * binding by hand. The message used to say "Inputs → passphrase" about a
   * field no page renders. `passphrase=$slot` is the path a user can
   * actually take, so that is what the sentence names and what these pin.
   */
  it("takes the passphrase from a named slot", async () => {
    // Written the way the recipe language actually works: the slot is
    // registered by an earlier cell, and the compiler checks that it was —
    // which is the machinery `passphrase=` gets for free by being a `slot`
    // param rather than a string one.
    const { ast, validation } = compileRecipe(
      `"correct horse" | out $pw\n\ninput | ssh.decode format=private passphrase=$pw | ssh.fingerprint | out $fp`
    );
    expect(validation.errors).toEqual([]);
    const artifacts = await runRecipe(ast, {
      inputs: { text: { value: fixture("id_ed25519_enc1") } },
    });
    const fp = artifacts.find((a) => a.label === "fp");
    expect(String(fp.content).trim()).toBe(
      fixture("fingerprints.txt").trim().split("\n")[0].split(/\s+/)[1]
    );
  });

  it("points the refusal at the slot, not at a panel field that does not exist", () => {
    expect(ENCRYPTED_KEY_MESSAGE).toMatch(/passphrase=\$pw/);
    expect(ENCRYPTED_KEY_MESSAGE).not.toMatch(/Inputs → passphrase/);
  });

  it("names an unregistered slot at compile time, before the run", () => {
    const { validation } = compileRecipe(
      "input | ssh.decode format=private passphrase=$pw | ssh.fingerprint | out $fp"
    );
    expect(validation.errors.map((e) => e.message).join("\n")).toMatch(
      /passphrase=\$pw: unknown slot/
    );
  });
});

/**
 * `ssh.encode format=private passphrase=$slot` (§29f).
 *
 * The asymmetry with `ssh.decode` above is the whole design and is asserted
 * here rather than only written down: decoding may read the Inputs panel,
 * because a passphrase there decides whether a run starts. Encoding may not,
 * because there it decides what the file *is* — and a recipe whose output is a
 * protected key on one machine and a bare one on the next, with nothing in its
 * text to say which, is not a recipe. So the secret is named, as an `$slot`.
 */
describe("ssh.encode passphrase=", () => {
  const PASSPHRASE = "correct horse";

  /** One text slot named $pw, the way a notebook cell would register it. */
  const withPw = (pw = PASSPHRASE) => ({
    resolveSlot: (ref) => (ref === "$pw" ? { type: "text", data: pw } : null),
  });

  /** A live keypair value, since execSshEncode reads CryptoKey handles. */
  const keypair = async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    return { type: "keypair", data: pair };
  };

  it("encrypts the block, at the rounds ssh-keygen writes today", async () => {
    const out = await execSshEncode(
      await keypair(),
      { format: "private", passphrase: "$pw" },
      withPw()
    );
    expect(out.meta.kind).toBe("ssh-private");
    expect(out.meta.encrypted).toBe(true);
    const opened = await parseOpensshPrivateKey(out.data, { passphrase: PASSPHRASE });
    expect(opened.encrypted).toBe(true);
    expect(opened.kdfRounds).toBe(DEFAULT_KDF_ROUNDS);
  });

  it("leaves the block bare when no passphrase is named, exactly as before", async () => {
    const out = await execSshEncode(await keypair(), { format: "private" }, withPw());
    expect(out.meta.encrypted).toBe(false);
    expect((await parseOpensshPrivateKey(out.data)).encrypted).toBe(false);
  });

  it("never reads the Inputs panel — a panel passphrase alone changes nothing", async () => {
    // The regression this guards is silent: an export that quietly became
    // encrypted (or stopped being) because of state the recipe cannot see.
    const out = await execSshEncode(
      await keypair(),
      { format: "private" },
      { inputs: { gpg: { passphrase: PASSPHRASE } }, ...withPw() }
    );
    expect((await parseOpensshPrivateKey(out.data)).encrypted).toBe(false);
  });

  it("refuses a literal, which would be a passphrase living in recipe text", async () => {
    await expect(
      execSshEncode(await keypair(), { format: "private", passphrase: PASSPHRASE }, withPw())
    ).rejects.toThrow(/takes an \$slot/);
  });

  it("stops warning about an unencrypted export once one is encrypted", () => {
    // The §29f warning was written when `format=private` could only ever emit
    // a bare block, and was not gated when `passphrase=` made that false. A
    // warning that is wrong precisely where the user did the careful thing is
    // worse than no warning: it teaches that the warnings are noise.
    const warn = (src) => compileRecipe(src).validation.warnings || [];
    const bare = warn("genkey ed25519 | ssh.encode format=private | out $k");
    expect(bare.some((w) => /emits an unencrypted private key/.test(w.message))).toBe(true);

    const protectedOut = warn(
      "genkey ed25519 | ssh.encode format=private passphrase=$pw | out $k"
    );
    expect(protectedOut.some((w) => /emits an unencrypted private key/.test(w.message))).toBe(
      false
    );
  });

  it("refuses an empty slot rather than quietly exporting the key bare", async () => {
    await expect(
      execSshEncode(await keypair(), { format: "private", passphrase: "$pw" }, withPw(""))
    ).rejects.toThrow(/empty passphrase is not encryption/);
  });

  it("refuses passphrase= on the public half instead of ignoring it", async () => {
    await expect(
      execSshEncode(await keypair(), { format: "public", passphrase: "$pw" }, withPw())
    ).rejects.toThrow(/only applies to format=private/);
  });

  it("names the secret in the recipe, and never serializes it", () => {
    const src = `"${PASSPHRASE}" | out $pw

genkey ed25519 | ssh.encode format=private passphrase=$pw | out $k`;
    const { ast, validation } = compileRecipe(src);
    expect(validation.errors).toEqual([]);
    // The `$ref` survives a share link — that is what makes the recipe honest
    // about what it emits — while `p.secret` keeps a literal from ever doing so.
    expect(serializeRecipe({ chains: ast.chains })).toContain("passphrase=$pw");
  });

  it("will not even parse a literal, so one cannot reach the recipe text", () => {
    // `p.secret` drops a literal at *serialization*; making the param `slot`
    // stops it a step earlier, at the parser, where the user still gets told.
    const { validation } = compileRecipe(
      `genkey ed25519 | ssh.encode format=private passphrase="hunter2" | out $k`
    );
    expect(validation.errors.map((e) => e.message).join("\n")).toMatch(
      /ssh\.encode passphrase=.*require \$/i
    );
  });

  it("round-trips end to end through the engine", async () => {
    const { ast, validation } = compileRecipe(`"${PASSPHRASE}" | out $pw

genkey ed25519 | out $id

in $id | ssh.encode format=private passphrase=$pw | out $enc

in $enc | ssh.decode format=private | ssh.fingerprint | out $fp

in $id | ssh.fingerprint | out $fp2`);
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, {
      // ssh.decode's channel, unchanged: the panel opens a protected file.
      inputs: { gpg: { passphrase: PASSPHRASE } },
    });
    const at = (n) => arts.find((a) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n));
    expect(String(at("enc").content)).toContain("BEGIN OPENSSH PRIVATE KEY");
    expect(Buffer.from(unarmorBytes(String(at("enc").content))).toString("latin1")).toContain(
      "aes256-ctr"
    );
    expect(String(at("fp").content)).toMatch(/^SHA256:/);
    expect(String(at("fp").content)).toBe(String(at("fp2").content));
  });

  it("refuses to reopen with the wrong passphrase, so the block really is sealed", async () => {
    const out = await execSshEncode(
      await keypair(),
      { format: "private", passphrase: "$pw" },
      withPw()
    );
    await expect(
      parseOpensshPrivateKey(out.data, { passphrase: "wrong horse" })
    ).rejects.toThrow(WRONG_PASSPHRASE_MESSAGE);
  });
});

/**
 * The type table must agree with what `execSshEncode` actually stamps.
 *
 * `ssh.encode format=private` returns `meta.kind: "ssh-private"` and always
 * has. The overload table said "ssh-public" for every input, so the compiler
 * believed an openssh-key-v1 block was a public line: `| ssh.decode` then took
 * the `ssh-public → key` branch and typed a keypair as a public key, and
 * `ssh.decode`'s own `ssh-private → keypair` overload could never be reached
 * from the op that produces the thing it names.
 */
describe("ssh.encode declares the half it actually emits", () => {
  const outOf = (params) => {
    const spec = STEPS.find((s) => s.name === "ssh.encode");
    return matchOverload(spec.overloads, { base: "keypair" }, params)?.output;
  };

  it("types format=private as ssh-private", () => {
    expect(outOf({ format: "private" })?.kind).toBe("ssh-private");
  });

  it("still types the default as ssh-public", () => {
    expect(outOf({})?.kind).toBe("ssh-public");
    expect(outOf({ format: "public" })?.kind).toBe("ssh-public");
  });

  it("matches what the runtime stamps, so the two cannot drift", async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const value = { type: "keypair", data: pair, meta: {} };
    for (const params of [{ format: "private" }, {}]) {
      const ran = await execSshEncode(value, params);
      expect(ran.meta.kind).toBe(outOf(params)?.kind);
    }
  });

  it("makes ssh.decode's keypair branch reachable, by the word the recipe writes", () => {
    const dec = STEPS.find((s) => s.name === "ssh.decode");
    const out = (params) =>
      matchOverload(dec.overloads, { base: "text", kind: "ssh-private" }, params)?.output;
    expect(out({ format: "private" })?.base).toBe("keypair");
    expect(outOf({ format: "private" })?.kind).toBe("ssh-private");
  });
});

/**
 * `ssh.decode`'s output type is the recipe's word, never the file's content.
 *
 * The measured defect: `input | ssh.decode | export pkcs8 | encode hex`
 * compiled with zero errors, and a real `ssh-ed25519` public line ran through
 * it to SPKI DER (`302a300506032b6570…`) under a recipe that said `pkcs8`. The
 * fallback overload declared `keypair` because the input's `kind` is known
 * only when the text came from `ssh.encode`, while `execSshDecode` picked
 * `key` or `keypair` by looking for `BEGIN OPENSSH PRIVATE KEY` — so the two
 * disagreed for every pasted key, and the disagreement was silent.
 *
 * `format=` is now the single answer both sides read.
 */
describe("ssh.decode types from format=, and the file may only agree", () => {
  const publicLine = fixture("id_ed25519.pub");
  const block = fixture("id_ed25519");

  it("declares a public key for the default, and refuses the pkcs8 export that used to lie", () => {
    const { validation } = compileRecipe("input | ssh.decode | export pkcs8 | encode hex | out $k");
    expect(validation.errors.map((e) => e.message).join("\n")).toMatch(
      /"export pkcs8" needs a private key — tip is key\/public/
    );
  });

  it("declares a keypair for format=private, and exports real pkcs8", async () => {
    const { ast, validation } = compileRecipe(
      "input | ssh.decode format=private | export pkcs8 | encode hex | out $k"
    );
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, { inputs: { text: { value: block } } });
    // PKCS#8 PrivateKeyInfo for Ed25519 — SEQUENCE, version 0, OID 1.3.101.112.
    expect(String(arts.at(-1).content)).toMatch(/^302e020100300506032b657004220420/);
  });

  it("still fingerprints a public line under the default", async () => {
    const { ast, validation } = compileRecipe("input | ssh.decode | ssh.fingerprint | out $fp");
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, { inputs: { text: { value: publicLine } } });
    expect(String(arts.at(-1).content).trim()).toBe(
      fixture("fingerprints.txt").trim().split("\n")[0].split(/\s+/)[1]
    );
  });

  it("refuses a private block handed to the public reading, naming the word that fixes it", async () => {
    const { ast, validation } = compileRecipe("input | ssh.decode | ssh.fingerprint | out $fp");
    expect(validation.errors).toEqual([]);
    await expect(runRecipe(ast, { inputs: { text: { value: block } } })).rejects.toThrow(
      SSH_DECODE_FORMAT_MISMATCH.public
    );
  });

  it("refuses a public line handed to format=private", async () => {
    const { ast, validation } = compileRecipe(
      "input | ssh.decode format=private | ssh.fingerprint | out $fp"
    );
    expect(validation.errors).toEqual([]);
    await expect(runRecipe(ast, { inputs: { text: { value: publicLine } } })).rejects.toThrow(
      SSH_DECODE_FORMAT_MISMATCH.private
    );
  });

  /**
   * And where the compiler *can* tell — text stamped by `ssh.encode` — it
   * says so before the run rather than letting the refusal above happen.
   */
  it("catches a format= that contradicts a known kind, at compile time", () => {
    const priv = compileRecipe(
      `genkey ed25519 | ssh.encode format=private | out $pem\n\nin $pem | ssh.decode | out $k`
    );
    expect(priv.validation.errors.map((e) => e.message)).toContain(
      SSH_DECODE_KIND_CONFLICT.private
    );
    const pub = compileRecipe(
      `genkey ed25519 | ssh.encode | out $pub\n\nin $pub | ssh.decode format=private | out $k`
    );
    expect(pub.validation.errors.map((e) => e.message)).toContain(SSH_DECODE_KIND_CONFLICT.public);
  });

  /**
   * The tip `format=private` declares carries no `alg` — the wire format names
   * the key type, and only at run time. `export scalar` used to fill that gap
   * with `ec/p256` and so declare `length: 32`, while a P-521 SSH key hands
   * back 66 bytes. An unknown algorithm now declares neither.
   */
  it("declares no scalar length for a key whose algorithm it cannot know", async () => {
    const declared = (current) =>
      inferParamDrivenType("export", current, { format: "scalar" }).output;
    expect(declared(typeOf("keypair"))).toEqual({
      base: "bytes",
      kind: "scalar",
      which: "private",
    });
    expect(declared(typeOf("keypair", { alg: "ec/p521" })).length).toBe(66);

    const { ast, validation } = compileRecipe(
      `genkey ec/p521 | ssh.encode format=private | out $pem\n\nin $pem | ssh.decode format=private | export scalar | encode hex | out $s`
    );
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, {});
    // 66, which is what the old declaration of 32 would have been wrong about.
    expect(String(arts.at(-1).content).length / 2).toBe(66);
  }, 30_000);

  it("agrees with the runtime on both readings, so the two cannot drift", async () => {
    const dec = STEPS.find((s) => s.name === "ssh.decode");
    for (const [params, text] of [
      [{}, publicLine],
      [{ format: "public" }, publicLine],
      [{ format: "private" }, block],
    ]) {
      const declared = matchOverload(dec.overloads, { base: "text" }, params)?.output;
      const ran = await execSshDecode({ type: "text", data: text }, params);
      expect(ran.type, JSON.stringify(params)).toBe(declared.base);
      if (declared.which) expect(ran.meta.which).toBe(declared.which);
      expect(dec.effectiveIo(params).output).toBe(declared.base);
    }
  });
});

/**
 * The same claim, asserted where it is actually consumed (§32c).
 *
 * The overload tests above pin the *table*. This pins the **artifact**, which
 * is a different thing and is where the bug was reported: `attachPipeMeta`
 * projects `value.meta.type` into both `pipeType` and `tags`, so a wrong
 * overload silently becomes a wrong tag on a real tile.
 *
 * It matters because `artifact-kinds/registry.tsx` matches kinds on role +
 * tags. Nothing claims `ssh-public` today, so no tile is wrong yet — but the
 * obvious next unit is a kind for SSH public lines (the download feature wanted
 * a `.pub` extension and could not have one for exactly this reason), and such
 * a kind would have claimed the private block too and labelled a private key
 * "SSH public key".
 */
describe("the two ssh.encode formats never share a tag", () => {
  const artifactsOf = async (src) => {
    const { ast, validation } = compileRecipe(src);
    expect(validation.errors, `fixture should compile: ${src}`).toEqual([]);
    return runRecipe(ast, {});
  };

  it("tags a private block ssh-private, not ssh-public", async () => {
    const [art] = await artifactsOf(
      "genkey ed25519 | ssh.encode format=private | out $priv"
    );
    expect(art.content).toContain("BEGIN OPENSSH PRIVATE KEY");
    expect(art.tags).toContain("ssh-private");
    expect(art.tags).not.toContain("ssh-public");
    expect(art.pipeType).toMatchObject({ base: "text", kind: "ssh-private" });
    // Unchanged by the fix, and worth pinning: the mask never depended on the
    // tag being right, which is why this shipped without a visibly broken tile.
    expect(art.sensitive).toBe(true);
    // The role was `secret` when this was written — the sensitivity ternary's
    // answer, not an identity. It is now the type's own word, because the
    // ternary gave the *same* block `secret` here and `text` on a dangling
    // tip, and an artifact kind matches `role` exactly. Pinned here rather
    // than only in the kind table, for the reason this whole file exists:
    // this is where the artifact is, and the table is downstream of it.
    expect(art.role).toBe("ssh-private");
  });

  it("tags a public line ssh-public, not ssh-private", async () => {
    const [art] = await artifactsOf("genkey ed25519 | ssh.encode | out $pub");
    expect(art.content).toMatch(/^ssh-ed25519 /);
    expect(art.tags).toContain("ssh-public");
    expect(art.tags).not.toContain("ssh-private");
    expect(art.pipeType).toMatchObject({ base: "text", kind: "ssh-public" });
    expect(art.sensitive).toBe(false);
  });

  it("shares no tag between the two, whatever else they carry", async () => {
    // Asserted as set disjointness rather than as two literals: a tag added to
    // both halves later would pass the tests above and still reintroduce the
    // defect, because one kind matching both is the whole failure mode.
    const [priv] = await artifactsOf("genkey ed25519 | ssh.encode format=private | out $a");
    const [pub] = await artifactsOf("genkey ed25519 | ssh.encode | out $b");
    const shared = (priv.tags || []).filter((t) => (pub.tags || []).includes(t));
    expect(shared, `private and public share tags: ${shared.join(", ")}`).toEqual([]);
  });
});
