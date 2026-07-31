/**
 * The multi-kind vault (§28, design_handoff_agent_ssh).
 *
 * The vault's wrap layer never cared what it wrapped; what changes is the
 * id shape and the metadata. The dangerous edge is the id: ssh ids are
 * base64 after `SHA256:`, where the legacy hex normalization would quietly
 * destroy them (`SHA256:Ur1h…` → `A256`), and then every lookup misses —
 * so that is the first thing pinned here.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { listKeys, saveKey, unlockKey } from "../lib/vault.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { normalizeVaultFingerprint, sessionClear } from "../lib/vault-session.js";
import { NON_PGP_PASSPHRASE_MESSAGE } from "../lib/toolkit/agent-ops.js";

const SSH_ID = "SHA256:BV9AB0OE5ffriBtNWFcPq6qLkdtnnn2LXlERMTNNuGc";
const RAW_ID = "spki:SHA256:BV9AB0OE5ffriBtNWFcPq6qLkdtnnn2LXlERMTNNuGc";
const PGP_FPR = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SSH_PAYLOAD = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n";

beforeEach(async () => {
  sessionClear();
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

describe("kind-shaped ids survive normalization", () => {
  it("passes SHA256: and spki:SHA256: ids through verbatim", () => {
    expect(normalizeVaultFingerprint(SSH_ID)).toBe(SSH_ID);
    expect(normalizeVaultFingerprint(RAW_ID)).toBe(RAW_ID);
  });

  it("still hex-normalizes pgp fingerprints", () => {
    expect(normalizeVaultFingerprint("aabb ccdd " + "e".repeat(32))).toBe(
      "AABBCCDD" + "E".repeat(32)
    );
  });

  it("does not mistake near-misses for kind-shaped ids", () => {
    // Wrong length or illegal characters fall back to hex normalization
    // rather than passing a malformed id straight into the store.
    expect(normalizeVaultFingerprint("SHA256:short")).toBe("A256");
  });
});

describe("saving non-pgp kinds", () => {
  it("round-trips an ssh record with kind, publicLine and alg", async () => {
    await saveKey({
      fingerprint: SSH_ID,
      armoredPrivate: SSH_PAYLOAD,
      uid: "fixture@basilisk (ed25519)",
      email: "",
      protection: "device",
      kind: "ssh",
      publicLine: "ssh-ed25519 AAAA fixture@basilisk",
      alg: "ed25519",
    });
    const [meta] = await listKeys();
    expect(meta.kind).toBe("ssh");
    expect(meta.publicLine).toBe("ssh-ed25519 AAAA fixture@basilisk");
    expect(meta.alg).toBe("ed25519");
    expect(await unlockKey(SSH_ID, {})).toBe(SSH_PAYLOAD);
  });

  it("unlockVaultForUse reports the kind so callers can materialize", async () => {
    await saveKey({
      fingerprint: SSH_ID,
      armoredPrivate: SSH_PAYLOAD,
      uid: "fixture",
      email: "",
      protection: "device",
      kind: "ssh",
      alg: "ed25519",
    });
    const result = await unlockVaultForUse(SSH_ID, { skipSession: true });
    expect(result.kind).toBe("ssh");
    expect(result.armored).toBe(SSH_PAYLOAD);
  });

  it("legacy records without kind list as pgp, untouched", async () => {
    await saveKey({
      fingerprint: PGP_FPR,
      armoredPrivate: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nZg==\n-----END PGP PRIVATE KEY BLOCK-----",
      uid: "legacy",
      email: "",
      protection: "device",
    });
    const [meta] = await listKeys();
    expect(meta.kind).toBeUndefined();
    expect(meta.fingerprint).toBe(PGP_FPR);
  });

  it("refuses a malformed non-pgp id instead of storing it", async () => {
    await expect(
      saveKey({
        fingerprint: "not-a-fingerprint",
        armoredPrivate: SSH_PAYLOAD,
        uid: "x",
        email: "",
        protection: "device",
        kind: "ssh",
      })
    ).rejects.toThrow(/Invalid ssh key id/);
  });
});

describe("the §28b passphrase constraint", () => {
  it("states the exact refusal, and names the alternatives", () => {
    // The wording is the feature: no silent downgrade, and the user learns
    // which protections do work.
    expect(NON_PGP_PASSPHRASE_MESSAGE).toBe(
      "Passphrase protection for SSH keys needs an encryption this browser build does not ship yet — use passkey or device protection."
    );
  });
});
