/**
 * `age.*` — age-encryption.org/v1 interop.
 *
 * The claim these ops make is interop, so the tests check the *wire format*
 * against the spec (C2SP `age.md`) and not merely that this code can read what
 * it wrote. A round trip through one library proves nothing about whether the
 * `age` CLI will open the file; the header line, the stanza type, the exact
 * base64 body widths, and the armor labels do.
 *
 * What is not testable here: running `age -d` against the output, which needs
 * the CLI. The structural assertions below are the closest stand-in, and the
 * reason the implementation goes through typage — age's author's own library —
 * rather than a reimplementation of the spec.
 */
import { describe, expect, it } from "vitest";
import {
  execAgeDecrypt,
  execAgeEncrypt,
  execAgeKeygen,
  execAgeRecipient,
} from "../lib/toolkit/age-ops.js";
import { getStep } from "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

const text = (v) => new TextDecoder().decode(v);
const utf8 = (s) => new TextEncoder().encode(s);

/** A pipeline value carrying bytes. */
const bytesValue = (data, meta = {}) => ({ type: "bytes", data, meta });
/** A pipeline value carrying text. */
const textValue = (data, meta = {}) => ({ type: "text", data, meta });

/** Bindings whose `resolveSlot` serves one fixed map. */
const slots = (map) => ({
  resolveSlot: (ref) => (ref in map ? { data: map[ref] } : null),
});

async function identityPair() {
  const id = await execAgeKeygen();
  const rec = await execAgeRecipient(id);
  return { identity: String(id.data), recipient: String(rec.data) };
}

describe("age.keygen / age.recipient", () => {
  it("mints an AGE-SECRET-KEY-1 identity and marks it sensitive", async () => {
    const v = await execAgeKeygen();
    expect(v.data).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
    expect(v.meta.sensitive).toBe(true);
    // The shareable half rides along so a masked tile still has something to show.
    expect(v.meta.recipient).toMatch(/^age1[0-9a-z]+$/);
  });

  it("derives the same recipient the identity already advertises", async () => {
    const id = await execAgeKeygen();
    const rec = await execAgeRecipient(textValue(id.data));
    expect(rec.data).toBe(id.meta.recipient);
    // A public key is publishable; masking it would be a lie about its nature.
    expect(rec.meta.sensitive).toBe(false);
  });

  it("passes an age1… through, so the op is safe when you are unsure", async () => {
    const { recipient } = await identityPair();
    expect((await execAgeRecipient(textValue(recipient))).data).toBe(recipient);
  });

  it("refuses anything that is neither", async () => {
    await expect(execAgeRecipient(textValue("ssh-ed25519 AAAA"))).rejects.toThrow(
      /expects an AGE-SECRET-KEY-1/
    );
  });
});

describe("wire format", () => {
  it("writes a real age-encryption.org/v1 header with an X25519 stanza", async () => {
    const { recipient } = await identityPair();
    const ct = await execAgeEncrypt(bytesValue(utf8("interop")), { to: recipient }, {});
    const lines = text(ct.data).split("\n");
    // Spec §"Header": the first line is exactly the version, then one stanza
    // per recipient, then the HMAC line.
    expect(lines[0]).toBe("age-encryption.org/v1");
    expect(lines[1]).toMatch(/^-> X25519 [A-Za-z0-9+/]+$/);
    expect(lines.find((l) => l.startsWith("---"))).toMatch(/^--- [A-Za-z0-9+/]+$/);
  });

  it("writes an scrypt stanza in passphrase mode, as `age -p` does", async () => {
    const ct = await execAgeEncrypt(
      bytesValue(utf8("pw")),
      { passphrase: "correct horse battery staple" },
      {}
    );
    expect(text(ct.data).split("\n")[1]).toMatch(/^-> scrypt [A-Za-z0-9+/]+ \d+$/);
  });

  it("emits one stanza per recipient for a multi-recipient file", async () => {
    const a = await identityPair();
    const b = await identityPair();
    const ct = await execAgeEncrypt(
      bytesValue(utf8("both")),
      { to: `${a.recipient} ${b.recipient}` },
      {}
    );
    const stanzas = text(ct.data)
      .split("\n")
      .filter((l) => l.startsWith("-> X25519 "));
    expect(stanzas.length).toBe(2);
    // …and either identity alone opens it.
    for (const who of [a, b]) {
      const out = await execAgeDecrypt(ct, { key: who.identity }, {});
      expect(text(out.data)).toBe("both");
    }
  });

  it("armors with the PEM-style labels the spec names", async () => {
    const { recipient } = await identityPair();
    const armored = await execAgeEncrypt(
      bytesValue(utf8("armored")),
      { to: recipient, armor: "true" },
      {}
    );
    expect(armored.type).toBe("text");
    expect(String(armored.data)).toMatch(/^-----BEGIN AGE ENCRYPTED FILE-----\n/);
    expect(String(armored.data).trimEnd()).toMatch(/-----END AGE ENCRYPTED FILE-----$/);
  });
});

describe("round trips", () => {
  it("recipient → identity", async () => {
    const { identity, recipient } = await identityPair();
    const ct = await execAgeEncrypt(bytesValue(utf8("hello age")), { to: recipient }, {});
    const out = await execAgeDecrypt(ct, { key: identity }, {});
    expect(text(out.data)).toBe("hello age");
    expect(out.meta.sensitive).toBe(true);
  });

  it("passphrase mode", async () => {
    const ct = await execAgeEncrypt(bytesValue(utf8("pw")), { passphrase: "hunter2" }, {});
    const out = await execAgeDecrypt(ct, { passphrase: "hunter2" }, {});
    expect(text(out.data)).toBe("pw");
  });

  it("armored, whether it comes back as text or as bytes read off disk", async () => {
    const { identity, recipient } = await identityPair();
    const armored = await execAgeEncrypt(
      bytesValue(utf8("via armor")),
      { to: recipient, armor: "true" },
      {}
    );
    expect(text((await execAgeDecrypt(armored, { key: identity }, {})).data)).toBe(
      "via armor"
    );
    // The same file after `file.read` — armored text arrives as octets.
    const asBytes = bytesValue(utf8(String(armored.data)));
    expect(text((await execAgeDecrypt(asBytes, { key: identity }, {})).data)).toBe(
      "via armor"
    );
  });

  it("resolves to= and key= through @slots", async () => {
    const { identity, recipient } = await identityPair();
    const bindings = slots({ "@pub": recipient, "@id": identity });
    const ct = await execAgeEncrypt(bytesValue(utf8("slotted")), { to: "@pub" }, bindings);
    const out = await execAgeDecrypt(ct, { key: "@id" }, bindings);
    expect(text(out.data)).toBe("slotted");
  });

  it("accepts a slot whose value is bytes — an identity file read off disk", async () => {
    const { identity, recipient } = await identityPair();
    const bindings = slots({ "@id": utf8(`${identity}\n`) });
    const ct = await execAgeEncrypt(bytesValue(utf8("from file")), { to: recipient }, {});
    expect(text((await execAgeDecrypt(ct, { key: "@id" }, bindings)).data)).toBe(
      "from file"
    );
  });
});

describe("refusals", () => {
  it("rejects a tampered ciphertext rather than returning garbage", async () => {
    const { identity, recipient } = await identityPair();
    const ct = await execAgeEncrypt(bytesValue(utf8("tamper me")), { to: recipient }, {});
    const forged = ct.data.slice();
    forged[forged.length - 5] ^= 0x40;
    await expect(execAgeDecrypt(bytesValue(forged), { key: identity }, {})).rejects.toThrow();
  });

  it("rejects the wrong identity", async () => {
    const a = await identityPair();
    const b = await identityPair();
    const ct = await execAgeEncrypt(bytesValue(utf8("for a")), { to: a.recipient }, {});
    await expect(execAgeDecrypt(ct, { key: b.identity }, {})).rejects.toThrow();
  });

  it("refuses to mix recipients and a passphrase, which age cannot express", async () => {
    const { recipient } = await identityPair();
    await expect(
      execAgeEncrypt(bytesValue(utf8("x")), { to: recipient, passphrase: "p" }, {})
    ).rejects.toThrow(/not both/);
  });

  it("requires one of them", async () => {
    await expect(execAgeEncrypt(bytesValue(utf8("x")), {}, {})).rejects.toThrow(
      /to=.*is required/
    );
    await expect(execAgeDecrypt(bytesValue(new Uint8Array(4)), {}, {})).rejects.toThrow(
      /key=@identity.*is required/
    );
  });

  it("rejects a recipient that is not one", async () => {
    await expect(
      execAgeEncrypt(bytesValue(utf8("x")), { to: "ssh-rsa AAAAB3" }, {})
    ).rejects.toThrow(/not an age recipient/);
  });

  it("rejects a recipient handed to key=, which would be a silent no-op", async () => {
    const { recipient } = await identityPair();
    await expect(
      execAgeDecrypt(bytesValue(new Uint8Array(4)), { key: recipient }, {})
    ).rejects.toThrow(/must hold an AGE-SECRET-KEY-1/);
  });

  it("encrypts to the public half when handed an identity by mistake", async () => {
    // A slip with exactly one safe reading — better than an error that pushes
    // the author toward pasting the secret somewhere else.
    const { identity } = await identityPair();
    const ct = await execAgeEncrypt(bytesValue(utf8("oops")), { to: identity }, {});
    expect(text((await execAgeDecrypt(ct, { key: identity }, {})).data)).toBe("oops");
  });

  it("reports a missing slot resolver rather than treating @pub as a literal", async () => {
    await expect(execAgeEncrypt(bytesValue(utf8("x")), { to: "@pub" }, {})).rejects.toThrow(
      /slot resolver missing/
    );
  });
});

describe("filenames", () => {
  it("derives the ciphertext name from the plaintext's", async () => {
    const { recipient } = await identityPair();
    const ct = await execAgeEncrypt(
      bytesValue(utf8("x"), { filename: "report.pdf" }),
      { to: recipient },
      {}
    );
    expect(ct.meta.filename).toBe("report.pdf.age");
  });

  it("strips the suffix again on the way back", async () => {
    const { identity, recipient } = await identityPair();
    const ct = await execAgeEncrypt(
      bytesValue(utf8("x"), { filename: "report.pdf" }),
      { to: recipient },
      {}
    );
    const out = await execAgeDecrypt({ ...ct, meta: ct.meta }, { key: identity }, {});
    expect(out.meta.filename).toBe("report.pdf");
  });
});

describe("registry wiring", () => {
  it("sits in its own toolbox, not under OpenPGP", () => {
    for (const name of ["age.keygen", "age.recipient", "age.encrypt", "age.decrypt"]) {
      expect(getStep(name)?.toolbox, name).toBe("age");
    }
  });

  it("pairs encrypt/decrypt as conjugates", () => {
    expect(getStep("age.encrypt").conjugate).toBe("age.decrypt");
    expect(getStep("age.decrypt").conjugateOf).toBe("age.encrypt");
  });

  it("compiles the documented file pipeline", () => {
    const { validation } = compileRecipe(
      `age.keygen | out @id

in @id | age.recipient | out @pub

file.read | age.encrypt to=@pub | file.save name=doc.age`
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
  });

  it("takes a literal recipient but refuses a literal identity", () => {
    // The asymmetry is the point: `age -r age1…` is how everyone writes a
    // recipient, and it is public. An identity written inline would be a
    // private key in recipe text — which Copy link, Export, and the workspace
    // library all carry off. So `key=` is slot-typed and rejects a literal.
    expect(
      compileRecipe("file.read | age.encrypt to=age1abcdef | out @ct").validation.ok
    ).toBe(true);
    expect(
      compileRecipe("file.read | age.encrypt age1abcdef | out @ct").validation.ok
    ).toBe(true);
    const literalIdentity = compileRecipe(
      "file.read | age.decrypt key=AGE-SECRET-KEY-1ABC | out @pt"
    );
    expect(literalIdentity.validation.ok).toBe(false);
    expect(literalIdentity.validation.errors.map((e) => e.message).join(" ")).toMatch(
      /require @|unknown slot/i
    );
  });

  it("switches its output type on armor=", () => {
    expect(getStep("age.encrypt").effectiveIo({ armor: true }).output).toBe("text");
    expect(getStep("age.encrypt").effectiveIo({ armor: false }).output).toBe("bytes");
  });
});
