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
  ENCRYPTED_KEY_MESSAGE,
  encodeOpensshPrivateKey,
  parseOpensshPrivateKey,
} from "../lib/ssh/openssh-key-v1.js";
import { sshFingerprint } from "../lib/ssh/fingerprint.js";
import { parseSshsig, sshsigSign, sshsigVerify } from "../lib/ssh/sshsig.js";

const fixture = (name) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url)), "utf8");
const fixtureBytes = (name) =>
  new Uint8Array(
    readFileSync(fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url)))
  );

const KEYS = ["id_ed25519", "id_ecdsa256", "id_ecdsa384", "id_ecdsa521", "id_rsa"];
const PAYLOAD = fixtureBytes("payload.txt");

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
    it(`decodes ${name} to material matching its public line`, () => {
      const key = parseOpensshPrivateKey(fixture(name));
      expect(key.comment).toBe("fixture@basilisk");
      const pubLine = parsePublicLine(fixture(`${name}.pub`));
      // The container's embedded public blob and the .pub file must agree.
      expect(Buffer.from(key.publicBlob).toString("base64")).toBe(
        Buffer.from(pubLine.blob).toString("base64")
      );
    });

    it(`re-encodes ${name} to a container that parses to the same material`, () => {
      const key = parseOpensshPrivateKey(fixture(name));
      const again = parseOpensshPrivateKey(encodeOpensshPrivateKey(key));
      expect(again.type).toBe(key.type);
      expect(again.comment).toBe(key.comment);
      expect(Buffer.from(again.publicBlob).toString("base64")).toBe(
        Buffer.from(key.publicBlob).toString("base64")
      );
    });
  }

  it("refuses a passphrase-protected file with the §29f message, verbatim", () => {
    // The wording is the feature (share-check.js precedent): it names the
    // KDF we lack and the exact command that removes it.
    expect(() => parseOpensshPrivateKey(fixture("id_ed25519_enc"))).toThrow(
      ENCRYPTED_KEY_MESSAGE
    );
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
    const key = parseOpensshPrivateKey(fixture("id_ed25519"));
    const ours = await sshsigSign(PAYLOAD, key, { namespace: "file" });
    expect(ours).toBe(fixture("payload.id_ed25519.file.sshsig"));
  });

  it("round-trips a fresh ECDSA and RSA signature through its own verify", async () => {
    for (const name of ["id_ecdsa256", "id_ecdsa384", "id_ecdsa521", "id_rsa"]) {
      const key = parseOpensshPrivateKey(fixture(name));
      const sig = await sshsigSign(PAYLOAD, key, { namespace: "file", hash: "sha256" });
      expect(parseSshsig(sig).hashAlg).toBe("sha256");
      await expect(
        sshsigVerify(PAYLOAD, sig, { namespace: "file", publicBlob: key.publicBlob })
      ).resolves.toBe(true);
    }
  });
});
