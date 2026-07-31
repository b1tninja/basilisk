/**
 * The approval gate (§27) — the thing standing between "agent" and
 * "rubber stamp".
 *
 * These tests are adversarial on purpose. The threat is a malicious recipe,
 * so the properties worth pinning are the ones an attacker would want to
 * break: that nothing in a recipe can pre-grant approval, that a batch
 * cannot be minted before the user has seen a real payload and a real
 * count, that grants do not leak across keys or across sign-vs-decrypt,
 * and that a denial says what did *not* happen.
 */
import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  beginApprovalRun,
  clearApprovalGrants,
  digestForApproval,
  hasApprovalGate,
  listApprovalGrants,
  requireApproval,
  revokeApprovalGrants,
  setApprovalGate,
} from "../lib/toolkit/approval-gate.js";
import { execAgentSave, execAgentSign } from "../lib/toolkit/agent-ops.js";
import { sessionClear } from "../lib/vault-session.js";
import { parsePublicLine } from "../lib/ssh/wire.js";
import { sshsigVerify } from "../lib/ssh/sshsig.js";

const baseRequest = (over = {}) => ({
  use: "sign",
  stepName: "agent.sign",
  stepText: "agent.sign SHA256:abc namespace=git",
  keyId: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  keyLabel: "fixture@basilisk",
  keyKind: "ssh",
  keyProtection: "device",
  payloadBytes: 12,
  payloadSha256: "1a2b3c4d5e6f7a8b",
  payloadPreview: "hello",
  runTotal: null,
  ...over,
});

beforeEach(async () => {
  clearApprovalGrants();
  beginApprovalRun();
  sessionClear();
  setApprovalGate(null);
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

afterEach(() => {
  setApprovalGate(null);
  clearApprovalGrants();
  vi.useRealTimers();
});

describe("no surface, no signature", () => {
  it("refuses and names the flag that would consent (§27f)", async () => {
    expect(hasApprovalGate()).toBe(false);
    await expect(requireApproval(baseRequest())).rejects.toThrow(
      /needs per-use approval.*--approve SHA256:A+:sign.*--approve-all/s
    );
  });
});

describe("once means once", () => {
  it("asks again for an identical second request", async () => {
    const gate = vi.fn(async () => "once");
    setApprovalGate(gate);
    await requireApproval(baseRequest());
    await requireApproval(baseRequest());
    expect(gate).toHaveBeenCalledTimes(2);
  });

  it("counts requests within a run, and resets on the next run", async () => {
    const seen = [];
    setApprovalGate(async (r) => {
      seen.push(r.requestIndex);
      return "once";
    });
    await requireApproval(baseRequest());
    await requireApproval(baseRequest());
    beginApprovalRun();
    await requireApproval(baseRequest());
    expect(seen).toEqual([1, 2, 1]);
  });
});

describe("denial", () => {
  it("says what did not happen, and names key and digest", async () => {
    setApprovalGate(async () => "deny");
    await expect(requireApproval(baseRequest())).rejects.toThrow(
      /approval denied — nothing was signed\..*key SHA256:.*payload sha256:1a2b3c4d…/s
    );
  });

  it("phrases decrypt denials as decryption", async () => {
    setApprovalGate(async () => "deny");
    await expect(
      requireApproval(baseRequest({ use: "decrypt", stepName: "agent.decrypt" }))
    ).rejects.toThrow(/nothing was decrypted/);
  });

  it("is never remembered — a re-run asks again", async () => {
    const gate = vi.fn(async () => "deny");
    setApprovalGate(gate);
    await expect(requireApproval(baseRequest())).rejects.toThrow();
    await expect(requireApproval(baseRequest())).rejects.toThrow();
    expect(gate).toHaveBeenCalledTimes(2);
  });
});

describe("session grants are scoped, visible and expiring", () => {
  it("covers later uses of the same key and use, without asking", async () => {
    const gate = vi.fn(async () => "session");
    setApprovalGate(gate);
    await requireApproval(baseRequest());
    await requireApproval(baseRequest());
    await requireApproval(baseRequest());
    expect(gate).toHaveBeenCalledTimes(1);
  });

  it("does not cover the other kind of use", async () => {
    const gate = vi.fn(async () => "session");
    setApprovalGate(gate);
    await requireApproval(baseRequest({ use: "sign" }));
    await requireApproval(baseRequest({ use: "decrypt", stepName: "agent.decrypt" }));
    expect(gate).toHaveBeenCalledTimes(2);
  });

  it("does not cover a different key", async () => {
    const gate = vi.fn(async () => "session");
    setApprovalGate(gate);
    await requireApproval(baseRequest());
    await requireApproval(baseRequest({ keyId: "SHA256:BBBB" }));
    expect(gate).toHaveBeenCalledTimes(2);
  });

  it("counts its uses live, so the grant can be watched", async () => {
    setApprovalGate(async () => "session");
    await requireApproval(baseRequest());
    await requireApproval(baseRequest());
    const [grant] = listApprovalGrants();
    expect(grant.uses).toBe(2);
    expect(grant.use).toBe("sign");
    expect(grant.expiresAt).toBeGreaterThan(Date.now());
  });

  it("expires on the agent-session clock and asks again after", async () => {
    vi.useFakeTimers();
    const gate = vi.fn(async () => "session");
    setApprovalGate(gate);
    await requireApproval(baseRequest());
    vi.advanceTimersByTime(5 * 60 * 1000 + 1);
    expect(listApprovalGrants()).toHaveLength(0);
    await requireApproval(baseRequest());
    expect(gate).toHaveBeenCalledTimes(2);
  });

  it("is revocable — Lock kills it mid-life", async () => {
    const gate = vi.fn(async () => "session");
    setApprovalGate(gate);
    await requireApproval(baseRequest());
    revokeApprovalGrants(baseRequest().keyId);
    expect(listApprovalGrants()).toHaveLength(0);
    await requireApproval(baseRequest());
    expect(gate).toHaveBeenCalledTimes(2);
  });
});

describe("per-run batch (§27d)", () => {
  it("covers exactly the remaining items of a known loop", async () => {
    const gate = vi.fn(async () => "run");
    setApprovalGate(gate);
    for (let i = 0; i < 12; i++) {
      await requireApproval(baseRequest({ runTotal: 12 }));
    }
    expect(gate).toHaveBeenCalledTimes(1);
    // The batch dies with the run: the next run asks again.
    beginApprovalRun();
    await requireApproval(baseRequest({ runTotal: 12 }));
    expect(gate).toHaveBeenCalledTimes(2);
  });

  it("degrades to once when no total is known", async () => {
    // A linear recipe asking three times is three decisions — there is no
    // count to batch, and silently treating it as a blanket grant would be
    // the rubber stamp this whole design exists to prevent.
    const gate = vi.fn(async () => "run");
    setApprovalGate(gate);
    await requireApproval(baseRequest({ runTotal: null }));
    await requireApproval(baseRequest({ runTotal: null }));
    expect(gate).toHaveBeenCalledTimes(2);
  });

  it("shows the loop's true count to the surface before any batch is offered", async () => {
    const seen = [];
    setApprovalGate(async (r) => {
      seen.push({ index: r.requestIndex, total: r.runTotal, preview: r.payloadPreview });
      return "once";
    });
    await requireApproval(baseRequest({ runTotal: 12 }));
    // The first request already carries the count and a real payload
    // preview, which is what makes the batch offer legitimate.
    expect(seen[0]).toEqual({ index: 1, total: 12, preview: "hello" });
  });
});

describe("agent.sign end to end", () => {
  it("signs with a vault key without the key entering the pipeline", async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const saved = await execAgentSave(
      { type: "keypair", data: pair, meta: { alg: "ed25519" } },
      { protection: "device", email: "boundary@basilisk" }
    );

    /** @type {import("../lib/toolkit/approval-gate.js").ApprovalRequest|null} */
    let request = null;
    setApprovalGate(async (r) => {
      request = r;
      return "once";
    });

    const payload = "sign me at the boundary";
    const out = await execAgentSign(
      { type: "text", data: payload },
      { fpr: saved.meta.fingerprint, namespace: "git" },
      {}
    );

    // The banner got real facts, not inferred ones.
    expect(request.keyId).toBe(saved.meta.fingerprint);
    expect(request.keyKind).toBe("ssh");
    expect(request.namespace).toBe("git");
    expect(request.payloadBytes).toBe(payload.length);
    expect(request.payloadSha256).toBe(
      await digestForApproval(new TextEncoder().encode(payload))
    );
    expect(request.payloadPreview).toBe(payload);
    expect(request.stepText).toContain("agent.sign");

    // And the signature is real: it verifies against the stored public line.
    expect(out.data).toContain("BEGIN SSH SIGNATURE");
    const { blob } = parsePublicLine(saved.meta.publicLine);
    await expect(
      sshsigVerify(new TextEncoder().encode(payload), out.data, {
        namespace: "git",
        publicBlob: blob,
      })
    ).resolves.toBe(true);
  });

  it("does not sign when the gate denies", async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const saved = await execAgentSave(
      { type: "keypair", data: pair, meta: { alg: "ed25519" } },
      { protection: "device" }
    );
    setApprovalGate(async () => "deny");
    await expect(
      execAgentSign({ type: "text", data: "nope" }, { fpr: saved.meta.fingerprint }, {})
    ).rejects.toThrow(/approval denied — nothing was signed/);
  });

  it("refuses format=gpg on an ssh key, naming both", async () => {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const saved = await execAgentSave(
      { type: "keypair", data: pair, meta: { alg: "ed25519" } },
      { protection: "device" }
    );
    setApprovalGate(async () => "once");
    await expect(
      execAgentSign(
        { type: "text", data: "x" },
        { fpr: saved.meta.fingerprint, format: "gpg" },
        {}
      )
    ).rejects.toThrow(/is an SSH key — format=gpg needs a pgp-kind key/);
  });
});
