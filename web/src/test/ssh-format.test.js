/**
 * SSH encodings against real `ssh-keygen` output (§29g).
 *
 * Interop is asserted the way age-ops.test.js asserts it: against checked-in
 * fixtures another implementation produced, byte for byte — not by round-
 * tripping through our own code, which would happily agree with its own
 * bugs. The fixtures' provenance is in fixtures/ssh/README.md.
 */
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
import { matchOverload } from "../lib/toolkit/types.js";
import { execSshEncode } from "../lib/toolkit/ssh-ops.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
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

describe("ssh.decode opens a protected key with the Inputs-panel passphrase", () => {
  // The passphrase channel is the one the gpg ops already read; a second one
  // would mean the panel worked for some ops and not others.
  const recipe = "input | ssh.decode | ssh.fingerprint | out @fp";

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

  it("makes ssh.decode's ssh-private branch reachable", () => {
    const dec = STEPS.find((s) => s.name === "ssh.decode");
    const priv = matchOverload(dec.overloads, { base: "text", kind: "ssh-private" }, {})?.output;
    expect(priv?.base).toBe("keypair");
    expect(outOf({ format: "private" })?.kind).toBe("ssh-private");
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
      "genkey ed25519 | ssh.encode format=private | out @priv"
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
    const [art] = await artifactsOf("genkey ed25519 | ssh.encode | out @pub");
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
    const [priv] = await artifactsOf("genkey ed25519 | ssh.encode format=private | out @a");
    const [pub] = await artifactsOf("genkey ed25519 | ssh.encode | out @b");
    const shared = (priv.tags || []).filter((t) => (pub.tags || []).includes(t));
    expect(shared, `private and public share tags: ${shared.join(", ")}`).toEqual([]);
  });
});
