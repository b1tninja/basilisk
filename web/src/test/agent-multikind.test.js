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

  it("refuses passphrase protection for non-pgp kinds with the §28b message", async () => {
    await expect(
      execAgentSave(await genEd25519(), { protection: "passphrase" })
    ).rejects.toThrow(NON_PGP_PASSPHRASE_MESSAGE);
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
