/**
 * Derivations behind the §37 artifact tiles (design_handoff_artifact_actions).
 *
 * §37a's corollary is that several of the brief's candidate *actions* are
 * really *views*: "inspect packets" on a ciphertext is not a button, it is
 * what the ciphertext tile should show. These are the functions that turn an
 * artifact's body into what its tile shows.
 *
 * They live in `lib/` rather than inside the widgets for the reason
 * `share-cards.js` and `share-check.js` do: tests here run in node with no
 * DOM, so a read-out written inside a component is a read-out with no tests.
 * Every function is total — it returns null rather than throwing, because a
 * malformed body must degrade to the raw text the tile would have shown
 * anyway (§32d), never blank a cell for a computation that succeeded.
 *
 * Nothing here decrypts, verifies or re-derives a value. A ciphertext's packet
 * map is the framing that is already in the clear; an sshsig read-out is the
 * envelope, not a verdict. Verification takes a key and a payload, which a
 * tile does not have — that is `ssh.verify` and `run.verify`, and §37a is why
 * they stay ops.
 */

import { dearmorToBytes, mapPacketSpans } from "../packet-map.js";
import { parseSshsig } from "../ssh/sshsig.js";
import { parsePublicBlob } from "../ssh/wire.js";
import { sshFingerprint } from "../ssh/fingerprint.js";
import { parseReceipt } from "./receipt.js";
import { bytesToBase64 } from "./encode.js";

/**
 * The packet framing of an OpenPGP message, for the ciphertext and envelope
 * tiles (§37b).
 *
 * `mapPacketSpans` walks headers only, so this says what the message is made
 * of — a PKESK per recipient, an SKESK for a passphrase, the SEIPD that holds
 * the body — without a key and without decrypting anything. That is exactly
 * the question a ciphertext tile can honestly answer: *who could open this,
 * and how is it wrapped*, not *what does it say*.
 *
 * @param {string} armored
 * @returns {{ rows: { tag: number, name: string, bytes: number }[], bytes: number } | null}
 */
export function packetSummary(armored) {
  const text = String(armored || "");
  if (!text.includes("-----BEGIN PGP")) return null;
  try {
    const binary = dearmorToBytes(text);
    const spans = mapPacketSpans(binary);
    if (!spans.length) return null;
    return {
      rows: spans.map((s) => ({
        tag: s.tag,
        name: s.name,
        bytes: s.end - s.headerStart,
      })),
      bytes: binary.length,
    };
  } catch (_) {
    return null;
  }
}

/**
 * The rows of a `recipients` artifact (§37b).
 *
 * The engine already serializes exactly these five fields
 * (`engine.js`, the `recipients` branch of `materializeOutArtifacts`), so this
 * reads them back rather than re-deriving anything. A row missing a
 * fingerprint is dropped: the fingerprint is the only field that identifies a
 * recipient, and a row that cannot be identified must not be shown as one.
 *
 * @param {string} json
 * @returns {{ fingerprint: string, label: string, email: string,
 *   approvalState: string, encryptCapable: boolean }[] | null}
 */
export function recipientRows(json) {
  let parsed;
  try {
    parsed = JSON.parse(String(json || ""));
  } catch (_) {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  const rows = parsed
    .filter((r) => r && typeof r === "object" && r.fingerprint)
    .map((r) => ({
      fingerprint: String(r.fingerprint),
      label: String(r.label || ""),
      email: String(r.email || ""),
      approvalState: String(r.approvalState || ""),
      encryptCapable: r.encryptCapable !== false,
    }));
  return rows.length ? rows : null;
}

/**
 * The sshsig envelope: namespace, hash, signer (§37b).
 *
 * `namespace` is the one field people get wrong and the one that decides
 * whether a signature verifies at all — a `git` signature can never verify as
 * a `file` signature — so it leads. The signer is rendered as the `SHA256:…`
 * fingerprint `ssh-keygen -lf` prints, per §28a, so it can be compared against
 * an `allowed_signers` line character for character.
 *
 * Async because the fingerprint is a digest; the caller renders when it lands,
 * exactly as `KeyCard` does.
 *
 * @param {string} armor
 * @returns {Promise<{ namespace: string, hashAlg: string, sigType: string,
 *   keyType: string, fingerprint: string } | null>}
 */
export async function sshsigSummary(armor) {
  try {
    const { publicBlob, namespace, hashAlg, sigType } = parseSshsig(String(armor || ""));
    let keyType = "";
    try {
      keyType = parsePublicBlob(publicBlob).type;
    } catch (_) {
      // An unsupported key type is still a readable envelope. Naming the
      // namespace and hash of a signature we cannot name the signer of beats
      // showing nothing, so this is not fatal to the read-out.
      keyType = "";
    }
    return {
      namespace,
      hashAlg,
      sigType,
      keyType,
      fingerprint: await sshFingerprint(publicBlob),
    };
  } catch (_) {
    return null;
  }
}

/**
 * A run receipt reduced to what `run.verify` compares (§37b).
 *
 * The tile shows the digest table and nothing else — no "verify this" button,
 * because verifying means re-running the recipe, which is `run.verify`, an op
 * (§37a). What the tile *can* do is show a witness the same rows the
 * comparison walks, so a mismatch reported later has somewhere to be read.
 *
 * `parseReceipt` is reused rather than re-parsed so the cleartext-signature
 * unwrap holds here too: a signed receipt is the normal shape of a receipt
 * that has left the machine, and it should not render worse than an unsigned
 * one. A v1 receipt throws inside it, this returns null, and the tile shows
 * the raw JSON — `run.verify` owns the sentence explaining the version (§38c).
 *
 * @param {string} text
 * @returns {{ label: string, createdAt: string, registry: string,
 *   recipeDigest: string, artifacts: number,
 *   cells: { index: number, recipe: string, inputs: number,
 *     outputs: { label: string, role: string, digest: string,
 *       length: number, sensitive: boolean }[] }[] } | null}
 */
export function receiptSummary(text) {
  let receipt;
  try {
    receipt = parseReceipt(String(text || ""));
  } catch (_) {
    return null;
  }
  const cells = (receipt.cells || []).map((c, i) => ({
    index: Number(c.index ?? i),
    recipe: String(c.recipe ?? ""),
    inputs: (c.inputs || []).length,
    outputs: (c.outputs || []).map((o) => ({
      label: String(o.label ?? ""),
      role: String(o.role ?? ""),
      digest: String(o.digest ?? ""),
      length: Number(o.length ?? 0),
      sensitive: !!o.sensitive,
    })),
  }));
  return {
    label: String(receipt.label || ""),
    createdAt: String(receipt.createdAt || ""),
    registry: String(receipt.registry || ""),
    recipeDigest: String(receipt.recipeDigest || ""),
    artifacts: cells.reduce((n, c) => n + c.outputs.length, 0),
    cells,
  };
}

/**
 * A QR artifact's SVG as an `<img>` source (§37b).
 *
 * `img-src 'self' data:` permits this. The alternative — dropping the SVG
 * string into `dangerouslySetInnerHTML` — would be a script-injection surface
 * for a value that came out of the pipeline, which is the one place a value is
 * least under our control. Encoding through UTF-8 bytes rather than `btoa`
 * because an SVG may carry non-Latin-1 characters and `btoa` throws on them.
 *
 * @param {string} svg
 * @returns {string | null}
 */
export function qrDataUri(svg) {
  const text = String(svg || "");
  if (!/^\s*<svg[\s>]/.test(text)) return null;
  try {
    return `data:image/svg+xml;base64,${bytesToBase64(new TextEncoder().encode(text))}`;
  } catch (_) {
    return null;
  }
}

/**
 * What a share tile can say while the share itself stays masked (§33e).
 *
 * Which share this is, and how many are needed, are facts about the *split* —
 * they are printed on the card and said aloud in the room. Neither derives
 * from the masked material, which is what §34b's rule asks of anything drawn
 * on a masked tile. Before this, a masked share tile said "sensitive — value
 * not shown" and nothing else, so the one question a custodian actually has
 * ("is this share 2 or share 3?") could only be answered by revealing it.
 *
 * @param {{ shareIndex?: number, tags?: string[],
 *   traits?: { shareOf?: number, threshold?: number } }} artifact
 * @returns {{ index: number, threshold: number, flavour: string } | null}
 */
export function shareIdentity(artifact) {
  const traits = artifact?.traits || {};
  const index = Number(traits.shareOf ?? artifact?.shareIndex ?? 0) || 0;
  const threshold = Number(traits.threshold ?? 0) || 0;
  if (!index && !threshold) return null;
  const tags = (artifact?.tags || []).map(String);
  // `encrypted` is checked first because a GPG-encrypted share carries
  // `blip39` too — it is armor *around* a mnemonic, and calling it a mnemonic
  // would tell a custodian to read words off a tile that holds none.
  const flavour = tags.includes("encrypted")
    ? "encrypted share"
    : tags.includes("blip39")
      ? "BLIP39 mnemonic"
      : tags.includes("raw")
        ? "raw share"
        : "";
  return { index, threshold, flavour };
}
