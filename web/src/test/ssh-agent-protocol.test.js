/**
 * The ssh-agent protocol (§30c), exercised in process.
 *
 * `handleAgentRequest` maps one request frame to one response frame with no
 * socket involved, so the whole protocol is testable here and the socket
 * layer is left doing only framing and I/O — which is the part CI cannot
 * meaningfully check on both a Unix socket and a Windows named pipe.
 *
 * The signatures below are verified with the *same* WebCrypto/noble
 * primitives a real client would use, over the raw RFC 4253 signature
 * format — not sshsig. Conflating those two is the classic way an
 * ssh-agent reimplementation passes its own tests and fails against `ssh`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  MSG,
  SIGN_FLAGS,
  frame,
  handleAgentRequest,
  readFrames,
} from "../../cli/ssh-agent-protocol.js";
import { agentKeyFromFile } from "../../cli/agent-server.js";
import { SshReader, writeString, writeText, writeU32, concatBytes } from "../lib/ssh/wire.js";
import { parsePublicLine } from "../lib/ssh/wire.js";

const fixturePath = (name) =>
  fileURLToPath(new URL(`./fixtures/ssh/${name}`, import.meta.url));
const fixture = (name) => readFileSync(fixturePath(name), "utf8");

const DATA = new TextEncoder().encode("session identity blob");

/** Unwrap one framed response. */
function unframe(framed) {
  const { messages } = readFrames(framed);
  expect(messages).toHaveLength(1);
  return messages[0];
}

const requestIdentities = () => frame(new Uint8Array([MSG.REQUEST_IDENTITIES]));
const signRequest = (blob, data, flags = 0) =>
  frame(
    concatBytes([
      new Uint8Array([MSG.SIGN_REQUEST]),
      writeString(blob),
      writeString(data),
      writeU32(flags),
    ])
  );

describe("request-identities", () => {
  it("lists every key with its blob and comment", async () => {
    const keys = [
      await agentKeyFromFile(fixturePath("id_ed25519")),
      await agentKeyFromFile(fixturePath("id_ecdsa256")),
    ];
    const res = unframe(await handleAgentRequest(unframe(requestIdentities()), { keys: () => keys }));
    expect(res[0]).toBe(MSG.IDENTITIES_ANSWER);
    const r = new SshReader(res.subarray(1));
    expect(r.u32("count")).toBe(2);
    for (const k of keys) {
      expect(Buffer.from(r.string("blob")).toString("base64")).toBe(
        Buffer.from(k.publicBlob).toString("base64")
      );
      expect(r.text("comment")).toBe("fixture@basilisk");
    }
    r.done("identities answer");
  });

  it("answers an empty list rather than failing when it holds nothing", async () => {
    const res = unframe(await handleAgentRequest(unframe(requestIdentities()), { keys: () => [] }));
    expect(res[0]).toBe(MSG.IDENTITIES_ANSWER);
    expect(new SshReader(res.subarray(1)).u32("count")).toBe(0);
  });
});

describe("sign-request", () => {
  it("produces an ed25519 signature a client can verify", async () => {
    const key = await agentKeyFromFile(fixturePath("id_ed25519"));
    const res = unframe(
      await handleAgentRequest(unframe(signRequest(key.publicBlob, DATA)), {
        keys: () => [key],
      })
    );
    expect(res[0]).toBe(MSG.SIGN_RESPONSE);
    const outer = new SshReader(res.subarray(1));
    const sig = new SshReader(outer.string("signature"));
    expect(sig.text("sig type")).toBe("ssh-ed25519");
    const sigBlob = sig.string("sig blob");
    const { pub } = parsePublicLine(fixture("id_ed25519.pub"));
    expect(ed25519.verify(sigBlob, DATA, pub)).toBe(true);
  });

  it("produces an ECDSA signature a client can verify", async () => {
    const key = await agentKeyFromFile(fixturePath("id_ecdsa256"));
    const res = unframe(
      await handleAgentRequest(unframe(signRequest(key.publicBlob, DATA)), {
        keys: () => [key],
      })
    );
    const outer = new SshReader(res.subarray(1));
    const sig = new SshReader(outer.string("signature"));
    expect(sig.text("sig type")).toBe("ecdsa-sha2-nistp256");
    const blob = new SshReader(sig.string("sig blob"));
    const r = blob.mpint("r");
    const s = blob.mpint("s");
    const pad = (b) => {
      const out = new Uint8Array(32);
      out.set(b.subarray(-32), 32 - Math.min(32, b.length));
      return out;
    };
    const { point } = parsePublicLine(fixture("id_ecdsa256.pub"));
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      point,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      concatBytes([pad(r), pad(s)]),
      DATA
    );
    expect(ok).toBe(true);
  });

  it("honours the client's RSA hash flags, and never emits SHA-1 ssh-rsa", async () => {
    const key = await agentKeyFromFile(fixturePath("id_rsa"));
    const typeFor = async (flags) => {
      const res = unframe(
        await handleAgentRequest(unframe(signRequest(key.publicBlob, DATA, flags)), {
          keys: () => [key],
        })
      );
      const outer = new SshReader(res.subarray(1));
      return new SshReader(outer.string("signature")).text("sig type");
    };
    expect(await typeFor(SIGN_FLAGS.RSA_SHA2_256)).toBe("rsa-sha2-256");
    expect(await typeFor(SIGN_FLAGS.RSA_SHA2_512)).toBe("rsa-sha2-512");
    // No flags: bare ssh-rsa is SHA-1 and modern servers refuse it, so
    // emitting it would only produce a rejection later.
    expect(await typeFor(0)).toBe("rsa-sha2-512");
  });

  it("fails for a key it does not hold", async () => {
    const key = await agentKeyFromFile(fixturePath("id_ed25519"));
    const other = await agentKeyFromFile(fixturePath("id_rsa"));
    const res = unframe(
      await handleAgentRequest(unframe(signRequest(other.publicBlob, DATA)), {
        keys: () => [key],
      })
    );
    expect(res[0]).toBe(MSG.FAILURE);
  });
});

describe("per-key confirmation (§27f)", () => {
  it("signs when the confirmation is granted", async () => {
    const key = await agentKeyFromFile(fixturePath("id_ed25519"), { confirm: true });
    const res = unframe(
      await handleAgentRequest(unframe(signRequest(key.publicBlob, DATA)), {
        keys: () => [key],
        confirm: async () => true,
      })
    );
    expect(res[0]).toBe(MSG.SIGN_RESPONSE);
  });

  it("refuses when there is nobody to ask, and stays up", async () => {
    // Refusing is the correct headless degradation for a gate whose whole
    // point is a human — and one refused request must not kill the agent.
    const key = await agentKeyFromFile(fixturePath("id_ed25519"), { confirm: true });
    const lines = [];
    const host = { keys: () => [key], log: (l) => lines.push(l) };
    const res = unframe(await handleAgentRequest(unframe(signRequest(key.publicBlob, DATA)), host));
    expect(res[0]).toBe(MSG.FAILURE);
    expect(lines.join(" ")).toMatch(/refused a signature/);

    // The very next request on the same host still works.
    const plain = await agentKeyFromFile(fixturePath("id_ed25519"));
    const ok = unframe(
      await handleAgentRequest(unframe(signRequest(plain.publicBlob, DATA)), {
        keys: () => [plain],
      })
    );
    expect(ok[0]).toBe(MSG.SIGN_RESPONSE);
  });

  it("refuses when the human declines", async () => {
    const key = await agentKeyFromFile(fixturePath("id_ed25519"), { confirm: true });
    const res = unframe(
      await handleAgentRequest(unframe(signRequest(key.publicBlob, DATA)), {
        keys: () => [key],
        confirm: async () => false,
      })
    );
    expect(res[0]).toBe(MSG.FAILURE);
  });
});

describe("what this agent refuses to be", () => {
  it("fails add/remove/lock rather than implementing them", async () => {
    // An agent that let a client add keys to your keyring is a different,
    // worse thing. FAILURE is what every client already handles.
    for (const type of [17, 18, 19, 22, 23, 27]) {
      const res = unframe(
        await handleAgentRequest(new Uint8Array([type]), { keys: () => [] })
      );
      expect(res[0], `message ${type}`).toBe(MSG.FAILURE);
    }
  });

  it("fails a truncated sign request instead of throwing", async () => {
    const res = unframe(
      await handleAgentRequest(new Uint8Array([MSG.SIGN_REQUEST, 0, 0, 9]), {
        keys: () => [],
      })
    );
    expect(res[0]).toBe(MSG.FAILURE);
  });

  it("fails an empty message", async () => {
    const res = unframe(await handleAgentRequest(new Uint8Array(0), { keys: () => [] }));
    expect(res[0]).toBe(MSG.FAILURE);
  });
});

describe("framing", () => {
  it("pulls whole messages out of a split stream and keeps the remainder", () => {
    const a = frame(new Uint8Array([MSG.REQUEST_IDENTITIES]));
    const b = frame(new Uint8Array([MSG.SIGN_REQUEST, 1, 2, 3]));
    const stream = concatBytes([a, b]);
    // A client's writes arrive in arbitrary chunks; a frame reader that
    // assumed message boundaries would work locally and fail over a socket.
    const first = readFrames(stream.subarray(0, a.length + 3));
    expect(first.messages).toHaveLength(1);
    expect(first.rest.length).toBe(3);
    const rest = readFrames(concatBytes([first.rest, stream.subarray(a.length + 3)]));
    expect(rest.messages).toHaveLength(1);
    expect(rest.rest.length).toBe(0);
  });
});
