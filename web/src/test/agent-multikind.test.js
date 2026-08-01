/**
 * agent.save / agent.unlock / agent.pub / agent.list across kinds (§28).
 *
 * Device protection only — passkey needs a real authenticator ceremony and
 * has its own stubbed coverage. What matters here is the shape of what goes
 * in and comes out: a WebCrypto keypair goes in, a kind-shaped record lands
 * in the vault, and unlock hands back live CryptoKeys that sign.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import {
  execAgentList,
  execAgentPub,
  execAgentSave,
  execAgentUnlock,
} from "../lib/toolkit/agent-ops.js";
import { NON_PGP_PASSPHRASE_MESSAGE } from "../lib/toolkit/agent-ops.js";
import {
  ENCRYPTED_KEY_MESSAGE,
  parseOpensshPrivateKey,
} from "../lib/ssh/openssh-key-v1.js";
import { listKeys, saveKey, unlockKey } from "../lib/vault.js";
import { sessionClear } from "../lib/vault-session.js";

beforeEach(async () => {
  sessionClear();
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

async function genEd25519() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { type: "keypair", data: pair, meta: { alg: "ed25519" } };
}

describe("agent.save on a keypair", () => {
  it("saves ed25519 as kind ssh with a SHA256: id and a public line", async () => {
    const saved = await execAgentSave(await genEd25519(), {
      protection: "device",
      email: "fixture@basilisk",
    });
    expect(saved.meta.vaultSaved).toBe(true);
    expect(saved.meta.vaultKind).toBe("ssh");
    expect(saved.meta.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    expect(saved.meta.publicLine).toMatch(/^ssh-ed25519 AAAA.* fixture@basilisk$/);

    const list = JSON.parse((await execAgentList()).data);
    expect(list).toHaveLength(1);
    expect(list[0].kind).toBe("ssh");
    expect(list[0].publicLine).toBe(saved.meta.publicLine);
  });

  it("saves x25519 as kind raw with an spki: id", async () => {
    const pair = await crypto.subtle.generateKey("X25519", true, [
      "deriveBits",
      "deriveKey",
    ]);
    const saved = await execAgentSave(
      { type: "keypair", data: pair, meta: { alg: "x25519" } },
      { protection: "device" }
    );
    expect(saved.meta.vaultKind).toBe("raw");
    expect(saved.meta.fingerprint).toMatch(/^spki:SHA256:/);
    const list = JSON.parse((await execAgentList()).data);
    expect(list[0].kind).toBe("raw");
    expect(list[0].publicLine).toBeUndefined();
  });

  it("saves an ssh-kind key at passphrase protection, in an encrypted container", async () => {
    // §28b used to refuse this outright. It works now because openssh-key-v1
    // has a passphrase form (bcrypt_pbkdf + aes256-ctr) and we can write it —
    // and the check that matters is that the *stored payload* is actually
    // encrypted, not merely that a row appeared with the label on it.
    const saved = await execAgentSave(
      await genEd25519(),
      { protection: "passphrase", email: "fixture@basilisk" },
      { inputs: { gpg: { passphrase: "correct horse" } } }
    );
    expect(saved.meta.vaultKind).toBe("ssh");

    const [record] = await listKeys();
    expect(record.protection).toBe("passphrase");
    const stored = await unlockKey(record.fingerprint, {});
    expect(stored).toContain("BEGIN OPENSSH PRIVATE KEY");
    await expect(parseOpensshPrivateKey(stored)).rejects.toThrow(ENCRYPTED_KEY_MESSAGE);
    const opened = await parseOpensshPrivateKey(stored, { passphrase: "correct horse" });
    expect(opened.encrypted).toBe(true);
    expect(opened.type).toBe("ssh-ed25519");
  });

  it("refuses passphrase protection where no container can hold one (kind raw)", async () => {
    // x25519 stores as a bare JWK, which has no passphrase form — the §28b
    // refusal survives for exactly the kinds that still cannot honour it.
    const pair = await crypto.subtle.generateKey("X25519", true, ["deriveBits", "deriveKey"]);
    await expect(
      execAgentSave(
        { type: "keypair", data: pair, meta: { alg: "x25519" } },
        { protection: "passphrase" },
        { inputs: { gpg: { passphrase: "correct horse" } } }
      )
    ).rejects.toThrow(NON_PGP_PASSPHRASE_MESSAGE);
  });

  it("still asks for the passphrase it needs before touching the vault", async () => {
    await expect(
      execAgentSave(await genEd25519(), { protection: "passphrase" })
    ).rejects.toThrow(/needs a key passphrase/);
    expect(await listKeys()).toHaveLength(0);
  });

  it("round-trips a passphrase-protected ssh key through agent.unlock", async () => {
    const bindings = { inputs: { gpg: { passphrase: "correct horse" } } };
    const saved = await execAgentSave(
      await genEd25519(),
      { protection: "passphrase" },
      bindings
    );
    const unlocked = await execAgentUnlock({ fpr: saved.meta.fingerprint }, bindings);
    expect(unlocked.type).toBe("keypair");
    expect(unlocked.data.privateKey.algorithm.name).toBe("Ed25519");
    // The key that comes back must be the key that went in.
    const back = await crypto.subtle.exportKey("jwk", unlocked.data.publicKey);
    const orig = await crypto.subtle.exportKey("jwk", saved.data.publicKey);
    expect(back.x).toBe(orig.x);
  });

  it("still replaces a passkey record, because the recipe said so out loud", async () => {
    // The vault refuses a weakening re-save by default (§34d), but
    // `agent.save protection=device` is an explicit instruction with the
    // fingerprint in front of it — the multi-kind path must keep replacing.
    const pair = await genEd25519();
    const first = await execAgentSave(pair, { protection: "device" });
    const id = first.meta.fingerprint;

    // Upgrade it behind agent.save's back, the way enrolling a passkey would.
    await saveKey({
      fingerprint: id,
      armoredPrivate: "-----BEGIN OPENSSH PRIVATE KEY-----\nZg==\n-----END OPENSSH PRIVATE KEY-----\n",
      uid: "seeded",
      email: "",
      protection: "passkey",
      prfIkm: crypto.getRandomValues(new Uint8Array(32)),
      kind: "ssh",
      alg: "ed25519",
    });
    expect((await listKeys())[0].protection).toBe("passkey");

    const again = await execAgentSave(pair, { protection: "device" });
    expect(again.meta.fingerprint).toBe(id);
    const list = await listKeys();
    expect(list).toHaveLength(1);
    expect(list[0].protection).toBe("device");
  });

  it("refuses symmetric keys rather than half-storing them", async () => {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    await expect(
      execAgentSave({ type: "key", data: key, meta: { alg: "aes/256" } }, {})
    ).rejects.toThrow(/no public half to list/);
  });
});

describe("agent.unlock across kinds", () => {
  it("materializes an ssh key back into CryptoKeys that sign", async () => {
    const saved = await execAgentSave(await genEd25519(), { protection: "device" });
    const id = saved.meta.fingerprint;
    const unlocked = await execAgentUnlock({ fpr: id });
    expect(unlocked.type).toBe("keypair");
    expect(unlocked.meta.vaultKind).toBe("ssh");
    expect(unlocked.meta.sensitive).toBe(true);
    const sig = await crypto.subtle.sign(
      "Ed25519",
      unlocked.data.privateKey,
      new Uint8Array([1, 2, 3])
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      unlocked.data.publicKey,
      sig,
      new Uint8Array([1, 2, 3])
    );
    expect(ok).toBe(true);
  });

  it("materializes a raw x25519 keypair for ECDH", async () => {
    const pair = await crypto.subtle.generateKey("X25519", true, [
      "deriveBits",
      "deriveKey",
    ]);
    const saved = await execAgentSave(
      { type: "keypair", data: pair, meta: { alg: "x25519" } },
      { protection: "device" }
    );
    const unlocked = await execAgentUnlock({ fpr: saved.meta.fingerprint });
    expect(unlocked.type).toBe("keypair");
    expect(unlocked.data.privateKey.algorithm.name).toBe("X25519");
  });
});

describe("agent.pub across kinds", () => {
  it("emits the stored public line for an ssh key", async () => {
    const saved = await execAgentSave(await genEd25519(), {
      protection: "device",
      email: "pub@basilisk",
    });
    const pub = await execAgentPub({ fpr: saved.meta.fingerprint });
    expect(pub.type).toBe("text");
    expect(pub.meta.kind).toBe("ssh-public");
    expect(pub.data).toBe(saved.meta.publicLine);
  });
});
