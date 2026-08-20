/**
 * The refusal a holder of enveloped shares meets, and what it is allowed to say.
 *
 * `combineRawShares` refuses when a decoded set's header carries the envelope
 * flag, because recombining such a set yields the key to a separate AES-GCM
 * blob rather than the secret. The sentence it refused with asked for "the
 * original envelope.bin.b64 blob" — an input the product provably cannot
 * accept. `cb19c51` deleted the only branch that read one, on the finding that
 * nothing in the app had ever written the field it read, so there is no tray
 * row, no parameter and no file picker a holder could put that blob into. The
 * commit left the sentence standing and said so, because what a legacy holder
 * should be told depends on a format whose producer is outside this repo.
 *
 * The fix is to the sentence, not the format. What is true and sayable:
 *
 * - this build cannot read an enveloped share set;
 * - it never wrote one either — `splitRawShares` has had `flags = 0` since its
 *   first commit — so the cards came from some other tool;
 * - that tool is therefore the only party holding both halves, which is the one
 *   act the holder can actually perform.
 *
 * What it must not say is anything about the legacy format beyond the bit its
 * own header sets, and it must not offer `envelope.asc` as a substitute: that
 * is an OpenPGP message on the live `gpg.symdecrypt` path, a different object,
 * and the old sentence's second half offered it in a way that read as a
 * conversion. There is no converter here and none is invented.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { combineRawShares, splitRawShares } from "../lib/slip39/slip39.js";
import { BLIP39_ENVELOPE_FLAG } from "../lib/slip39/blip39.js";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "node_modules" || name === "test") continue;
      walk(path, out);
    } else if (/\.(js|ts|tsx)$/.test(path)) {
      out.push(path);
    }
  }
  return out;
}

/** A set that claims the envelope flag, with no envelope to go with it. */
const ENVELOPED = {
  raw: [
    { index: 1, data: new Uint8Array(16).fill(0x11) },
    { index: 2, data: new Uint8Array(16).fill(0x22) },
  ],
  threshold: 2,
  flags: BLIP39_ENVELOPE_FLAG,
};

/** The message, or "" when the call unexpectedly succeeded. */
async function refusalFor(shareSet) {
  try {
    await combineRawShares(shareSet);
    return "";
  } catch (err) {
    return String(err?.message || err);
  }
}

describe("the enveloped-share refusal names only what is true", () => {
  it("asks for no input this build cannot accept", async () => {
    const said = await refusalFor(ENVELOPED);
    expect(said, "an enveloped set combined without complaint").not.toBe("");
    // The named-but-unaccepted file, gone. This is the whole defect: a remedy
    // that sends somebody looking for a field no screen of this product has.
    expect(said, `the refusal: ${said}`).not.toMatch(/envelope\.bin/i);
    expect(said, `the refusal: ${said}`).not.toMatch(/\.b64/i);
    // And no offer of the armored envelope in its place — a different object,
    // whose appearance beside this refusal read as a conversion that does not
    // exist. `symencrypt` went with it for the same reason.
    expect(said, `the refusal: ${said}`).not.toMatch(/envelope\.asc/i);
    expect(said, `the refusal: ${said}`).not.toMatch(/symencrypt/i);
  });

  it("states the state, the provenance and one performable act", async () => {
    const said = await refusalFor(ENVELOPED);
    // The state: these shares are marked, and the mark is the reason.
    expect(said, `the refusal: ${said}`).toContain("marked enveloped");
    // The provenance, which is deduced rather than guessed — and the deduction
    // is checkable, three lines down in this file.
    expect(said, `the refusal: ${said}`).toContain("flags = 0");
    expect(said, `the refusal: ${said}`).toContain("some other tool");
    // The act: go back to the producer. It is the only party that holds both
    // the shares' format and the envelope, and it is outside this repo, which
    // is exactly why no migration is described.
    expect(said, `the refusal: ${said}`).toMatch(/[Rr]ecover the secret with the tool/);
    // Nothing about how the legacy format is laid out, or how it might be
    // converted. Two words that would signal an invented road back.
    expect(said, `the refusal: ${said}`).not.toMatch(/migrat/i);
    expect(said, `the refusal: ${said}`).not.toMatch(/re-?split/i);
  });

  it("is checkably true about this product never dealing one", async () => {
    // The claim the sentence makes about provenance, asserted rather than
    // trusted: if `splitRawShares` ever starts stamping the flag, the refusal
    // becomes a lie about where the cards came from and this fails first.
    const dealt = await splitRawShares(new Uint8Array(32).fill(7), { threshold: 2, shares: 3 });
    expect(dealt.flags).toBe(0);
    expect(dealt.enveloped).toBe(false);
    expect(dealt.flags & BLIP39_ENVELOPE_FLAG).toBe(0);
  });

  it("still combines an unenveloped set — the refusal is the flag, not the path", async () => {
    // The control. A refusal that had simply swallowed every recombination
    // would pass every line above, and the sentence's own promise — that the
    // mnemonics are fine and it is the envelope that has no way in — would be
    // false.
    const dealt = await splitRawShares(new Uint8Array(32).fill(7), { threshold: 2, shares: 3 });
    const back = await combineRawShares({ raw: dealt.raw.slice(0, 2), threshold: 2, flags: 0 });
    expect(Array.from(back)).toEqual(Array.from(new Uint8Array(32).fill(7)));
  });

  it("leaves no source naming the blob a holder cannot produce", () => {
    // `88fcfd0`'s precedent, and the same shape as the `envelopeB64` sweep: an
    // absence asserted over the whole app rather than over the one file the
    // string was last seen in. A re-add anywhere — a tooltip, a doc string, a
    // placeholder in a tray that still has no field behind it — fails here.
    const left = walk(SRC_ROOT)
      .map((path) => ({
        file: relative(WEB_ROOT, path).replace(/\\/g, "/"),
        text: readFileSync(path, "utf8"),
      }))
      .filter((s) => /envelope\.bin/i.test(s.text))
      .map((s) => s.file);
    expect(left, left.join(", ")).toEqual([]);
  });
});
