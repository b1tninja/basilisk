/**
 * The SSH and age templates.
 *
 * The ops shipped with byte-exact `ssh-keygen` interop, a full sshsig
 * implementation, and typage-backed `age` — and not one of the 55 templates
 * mentioned either, so none of it was reachable from the Templates menu.
 *
 * `recipe.test.js` already proves *every* preset compiles; what these pin is
 * that the ones that can run headlessly actually do, and produce the bytes the
 * blurbs promise. A template is the first thing a new user clicks, so "it
 * parses" is not the bar — the P-521 line really has to come back reading
 * `ecdsa-sha2-nistp521`, and the age round trip really has to hand back the
 * plaintext.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  PRESETS,
  PRESET_GROUP_ORDER,
  compileRecipe,
} from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import {
  resolvePresetPair,
  stitchPresetPair,
} from "../lib/toolkit/conjugate-stitch.js";

const byId = (id) => PRESETS.find((p) => p.id === id);
const inGroup = (g) => PRESETS.filter((p) => p.group === g);
const ssh = () => inGroup("SSH");
const age = () => inGroup("age");
const added = () => [...ssh(), ...age()];

/** Errors live at `validation.errors`, never `result.errors` — reading the
 *  wrong field passes a recipe that is in fact broken. */
const errorsIn = (recipe) =>
  compileRecipe(recipe).validation.errors.map((e) => e.message);

/**
 * Run a recipe headlessly. `input` reads `bindings.inputs.text.value`, so a
 * template whose only unresolved need is text can be exercised for real.
 * @param {string} recipe
 * @param {string} [text]
 */
async function run(recipe, text = "the quick brown fox") {
  const { ast, validation } = compileRecipe(recipe);
  expect(validation.errors.map((e) => e.message)).toEqual([]);
  const artifacts = await runRecipe(ast, { inputs: { text: { value: text } } });
  return Object.fromEntries(artifacts.map((a) => [a.label, a.content]));
}

describe("the groups exist and are reachable", () => {
  it("puts SSH straight after Keys, where the errand starts", () => {
    // Menu order is by what a user reaches for, not by how deep the format
    // sits in the stack — "make me an SSH key" is a Keys-shaped errand.
    expect(PRESET_GROUP_ORDER.indexOf("SSH")).toBe(
      PRESET_GROUP_ORDER.indexOf("Keys") + 1
    );
    expect(ssh().length).toBe(8);
  });

  it("gives age its own shelf, next to Encrypt", () => {
    // Half the age arc (keygen, recipient) is key management, so it is not
    // simply more Encrypt rows.
    expect(PRESET_GROUP_ORDER.indexOf("age")).toBe(
      PRESET_GROUP_ORDER.indexOf("Encrypt") + 1
    );
    expect(age().length).toBe(3);
  });

  it("names every new group in PRESET_GROUP_ORDER", () => {
    for (const p of added()) {
      expect(PRESET_GROUP_ORDER, p.id).toContain(p.group);
    }
  });

  it("keeps ids unique across the whole PRESETS array", () => {
    const ids = PRESETS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("compiles every new template with zero validation errors", () => {
    for (const p of added()) {
      expect(errorsIn(p.recipe), p.id).toEqual([]);
      expect(compileRecipe(p.recipe).validation.ok, p.id).toBe(true);
    }
  });

  it("writes a blurb that teaches rather than narrates the steps", () => {
    for (const p of added()) {
      expect(p.title, p.id).toBeTruthy();
      expect(p.blurb.length, p.id).toBeGreaterThan(60);
    }
  });

  it("uses each pair id in exactly two presets", () => {
    const counts = new Map();
    for (const p of PRESETS) {
      if (p.pair) counts.set(p.pair, (counts.get(p.pair) || 0) + 1);
    }
    for (const [pair, n] of counts) expect(n, pair).toBe(2);
    for (const pair of ["ssh-pem", "age-file"]) {
      expect(counts.get(pair), pair).toBe(2);
    }
  });

  it("leaves sign/verify unpaired, and says why in the source", () => {
    // They are conjugates, but `stitchPresetPair` bridges the forward's last
    // output into the reverse's first source — for sshsig that is the
    // signature, while a verifier wants the message on the stem and the
    // signature in a slot. `hmac-sign-verify` and `gpg-sign-verify` are
    // unpaired for the same reason. If this ever gains a `pair`, the stitched
    // recipe must still compile: `recipe-conjugates.test.js` enforces that.
    expect(byId("ssh-sign-git").pair).toBeUndefined();
    expect(byId("ssh-verify-git").pair).toBeUndefined();
  });

  it("stitches the pairs it does declare into recipes that compile", () => {
    for (const id of ["ssh-pem", "age-file"]) {
      const pair = resolvePresetPair(id);
      expect(pair, id).toBeTruthy();
      const st = stitchPresetPair(pair.forward, pair.reverse);
      expect(errorsIn(st.recipe), `${id} (${st.mode})`).toEqual([]);
    }
  });
});

describe("the templates that need nothing pasted, run", () => {
  it("ssh-github emits the line GitHub accepts", async () => {
    const out = await run(byId("ssh-github").recipe);
    expect(out.pub).toMatch(
      // 51-byte blob: the `ssh-ed25519` name, then the 32-byte point.
      /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43} you@host$/
    );
  });

  it("ssh-p521 proves the point its blurb makes", async () => {
    // The whole reason this template exists: someone read the `sha2` in the
    // key type as a default they could override. It is not — RFC 5656 fixes
    // the name from the curve, and there is no param to say otherwise.
    const out = await run(byId("ssh-p521").recipe);
    expect(out.pub.split(" ")[0]).toBe("ecdsa-sha2-nistp521");
    expect(byId("ssh-p521").recipe).not.toMatch(/hash=|sha/i);
  });

  it("ssh-verify-git verifies the signature it just made", async () => {
    const out = await run(byId("ssh-verify-git").recipe);
    expect(out.pub).toMatch(/^ssh-ed25519 AAAA/);
    expect(out.sig).toMatch(/^-----BEGIN SSH SIGNATURE-----/);
    expect(String(out.ok)).toBe("true");
  });

  it("ssh-sign-git writes a real sshsig envelope", async () => {
    const out = await run(byId("ssh-sign-git").recipe);
    expect(out.sig).toMatch(/^-----BEGIN SSH SIGNATURE-----\n/);
    expect(out.sig.trimEnd()).toMatch(/-----END SSH SIGNATURE-----$/);
  });

  it("age-identity derives an age1 recipient from the identity", async () => {
    const out = await run(byId("age-identity").recipe);
    expect(out.id).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
    expect(out.pub).toMatch(/^age1[a-z0-9]+$/);
  });

  it("age-encrypt produces an armored age file", async () => {
    const out = await run(byId("age-encrypt").recipe, "attack at dawn");
    expect(out.ct).toMatch(/^-----BEGIN AGE ENCRYPTED FILE-----\n/);
    expect(out.ct.trimEnd()).toMatch(/-----END AGE ENCRYPTED FILE-----$/);
    expect(out.ct).not.toContain("attack at dawn");
  });

  it("the age round trip hands back the plaintext", async () => {
    // `age-decrypt` reaches for `file.read`, which is main-thread only, so the
    // pair cannot be stitched headlessly. Appending the decrypt chain to the
    // encrypt template exercises the same two ops against each other and
    // proves the ciphertext the template emits is really openable.
    const out = await run(
      `${byId("age-encrypt").recipe}\n\nin @ct | age.decrypt key=@id | utf8 | out @plain`,
      "attack at dawn"
    );
    expect(out.plain).toBe("attack at dawn");
  });
});

describe("the templates that need a paste, run on real material", () => {
  /** Real ssh-keygen-shaped fixtures, made by the engine itself. */
  async function fixtures() {
    return run(`genkey ed25519 | tee
  - ssh.encode format=private | out @priv
| tee
  - export pkcs8 | pem | out @pem
| ssh.encode comment="you@host" | out @pub`);
  }

  it("ssh-fingerprint matches ssh-keygen -lf's shape", async () => {
    const f = await fixtures();
    const out = await run(byId("ssh-fingerprint").recipe, f.pub);
    // `ssh-keygen -lf` prints unpadded base64 of the SHA-256: 43 chars.
    expect(out.fp).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("ssh-to-pem turns an openssh private block into PKCS#8", async () => {
    const f = await fixtures();
    expect(f.priv).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
    const out = await run(byId("ssh-to-pem").recipe, f.priv);
    expect(out.pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
  });

  it("pem-to-ssh goes back, and lands on the same key", async () => {
    const f = await fixtures();
    const out = await run(byId("pem-to-ssh").recipe, f.pem);
    expect(out.pub).toBe(f.pub);
  });
});

describe("what cannot run headlessly says so plainly", () => {
  it("only ssh-key-vault and age-decrypt are compile-only", () => {
    // `agent.save` needs a vault (IndexedDB) and `file.read` needs a document;
    // both are refused outside the page. Everything else above was executed.
    const compileOnly = added()
      .filter((p) => /agent\.save|file\.(read|save)/.test(p.recipe))
      .map((p) => p.id)
      .sort();
    expect(compileOnly).toEqual(["age-decrypt", "ssh-key-vault"]);
    for (const id of compileOnly) expect(errorsIn(byId(id).recipe)).toEqual([]);
  });

  it("ssh-key-vault really does tee the public line off the saved half", () => {
    // The point of the template: one run yields both the text to paste and a
    // vault entry. A version that only saved would teach half of it.
    const p = byId("ssh-key-vault");
    expect(p.recipe).toContain("ssh.encode");
    expect(p.recipe).toContain("agent.save");
    expect(p.recipe).toContain("tee");
  });

  it("age-decrypt keeps the identity out of recipe text", () => {
    // `key=` is a slot for exactly this reason; a literal would ship a secret
    // key inside anything Copy link or Export carries off.
    const p = byId("age-decrypt");
    expect(p.recipe).toContain("key=@id");
    expect(p.recipe).not.toMatch(/AGE-SECRET-KEY/);
    // Two pickers, matching `age -d -i key.txt doc.age`. It is also what lets
    // the pair stitch: an `input` here would collide with the encrypt half's.
    expect(p.recipe.match(/file\.read/g)).toHaveLength(2);
    expect(p.recipe).not.toMatch(/\binput\b/);
  });
});

describe("no template invents syntax the registry does not have", () => {
  const SRC = readFileSync(
    fileURLToPath(new URL("../lib/toolkit/recipe.js", import.meta.url)),
    "utf8"
  );
  /** Comments strip first — the group-order rationale names ops in prose. */
  const stripComments = (t) =>
    t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

  it("still names ssh. and age. ops in the presets themselves", () => {
    const code = stripComments(SRC);
    for (const op of [
      "ssh.encode",
      "ssh.decode",
      "ssh.fingerprint",
      "ssh.sign",
      "ssh.verify",
      "age.keygen",
      "age.recipient",
      "age.encrypt",
      "age.decrypt",
    ]) {
      expect(code, op).toContain(op);
    }
  });

  it("covers all five ssh ops and all four age ops across the templates", () => {
    const all = added()
      .map((p) => p.recipe)
      .join("\n");
    for (const op of [
      "ssh.encode",
      "ssh.decode",
      "ssh.fingerprint",
      "ssh.sign",
      "ssh.verify",
      "age.keygen",
      "age.recipient",
      "age.encrypt",
      "age.decrypt",
    ]) {
      expect(all, op).toContain(op);
    }
  });
});
