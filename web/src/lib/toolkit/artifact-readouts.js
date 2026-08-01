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
import { parseOpensshPrivateKey } from "../ssh/openssh-key-v1.js";
import { parsePublicBlob, parsePublicLine } from "../ssh/wire.js";
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
 * What an SSH key artifact says about itself: key type, fingerprint, comment.
 *
 * One function for both halves on purpose. The three facts are identical
 * questions of a public line and of an openssh-key-v1 block — and for the
 * private block they are exactly the facts that stay drawable while the secret
 * is masked (§33e/§34b), because every one of them comes off the *public*
 * blob the container carries or off the comment beside it. Nothing derived
 * from the private scalar is read, and none of the private fields
 * `parseOpensshPrivateKey` returns is retained here: the summary is three
 * strings.
 *
 * The fingerprint is `sshFingerprint`'s, so it is the `SHA256:…` line
 * `ssh-keygen -lf` prints (§28a) and the one `ssh.fingerprint` puts on the
 * tile beside it — a tile and an op that disagreed about a key's identity
 * would be worse than a tile that showed nothing.
 *
 * Total, like everything here. A passphrase-protected block throws
 * `ENCRYPTED_KEY_MESSAGE` inside the parser — the read-out has no passphrase
 * to offer it, and a tile is the wrong place to prompt for one — and that is
 * a body with no read-out, not an error to raise at someone: null, and the
 * kind's `empty` sentence stands in. (The three facts *are* all readable
 * from the container's cleartext public blob; showing them would mean
 * teaching this function that a key it cannot open is still describable,
 * which is a change to what the tile claims, not a bug fix.)
 *
 * @param {string} text
 * @returns {Promise<{ form: "public"|"private", keyType: string,
 *   comment: string, fingerprint: string } | null>}
 */
export async function sshKeySummary(text) {
  const body = String(text || "").trim();
  if (!body) return null;
  try {
    const isPrivate = body.includes("BEGIN OPENSSH PRIVATE KEY");
    const material = isPrivate ? await parseOpensshPrivateKey(body) : parsePublicLine(body);
    const blob = isPrivate ? material.publicBlob : material.blob;
    if (!blob) return null;
    return {
      form: isPrivate ? "private" : "public",
      keyType: String(material.type || ""),
      comment: String(material.comment || ""),
      fingerprint: await sshFingerprint(blob),
    };
  } catch (_) {
    return null;
  }
}

/**
 * How an authenticator groups the digits it shows — `123 456`, not `123456`.
 *
 * A grouping, never a different value: the string the artifact carries is
 * untouched, Copy still copies the code, and this exists only because six
 * unbroken digits are read one at a time and three plus three are read as two
 * chunks. Eight digits split evenly; seven takes the odd digit on the left,
 * which is where every 7-digit token puts it.
 *
 * @param {string} code
 * @returns {string[]}
 */
export function groupOtpCode(code) {
  const s = String(code || "");
  if (s.length === 6) return [s.slice(0, 3), s.slice(3)];
  if (s.length === 7) return [s.slice(0, 4), s.slice(4)];
  if (s.length === 8) return [s.slice(0, 4), s.slice(4)];
  return [s];
}

/**
 * What an `otp.code` tile shows (§37b): the code, whose it is, and — for TOTP
 * — the instant it stops being the current one.
 *
 * The one piece of arithmetic here is the reason this function exists.
 * `otpExpiresIn` is a **snapshot taken while the op ran**, so a tile that
 * printed it would say "23s left" about a code computed four minutes ago. But
 * a TOTP step has an *absolute* end: step number `T` covers `[T·period,
 * (T+1)·period)` from the Unix epoch, so `otpStep` and `otpPeriod` together
 * pin the expiry to a wall-clock instant that does not care when the artifact
 * was made, when the tab was opened, or how long it sat there. That is what
 * makes an honest countdown possible without recomputing anything: the widget
 * ticks a clock against `expiresAt` and the *value* stays the value the recipe
 * produced — which is what the receipt digested, and the only value that has a
 * derivation behind it (§37a).
 *
 * `snapshotSeconds` is carried alongside so the two can be compared: at run
 * time `expiresAt - now` is exactly `otpExpiresIn`, which is what the test
 * asserts, and the moment they disagree one of them is wrong.
 *
 * HOTP gets no `expiresAt`, and that is the honest answer rather than a
 * missing feature: an event counter has no clock, so a HOTP code does not
 * expire — it gets spent. The tile says which counter, and nothing about time.
 *
 * Total, like everything here: a body that is not digits, or an artifact
 * carrying no OTP facts at all, returns null and the tile renders the raw
 * body it would have rendered anyway (§32d).
 *
 * @param {string} content
 * @param {Record<string, *>|null|undefined} traits
 * @returns {{ code: string, groups: string[], mode: "totp"|"hotp",
 *   digits: number, label: string, period: number|null, step: string|null,
 *   counter: number|null, expiresAt: number|null,
 *   snapshotSeconds: number|null } | null}
 */
export function otpCodeReadout(content, traits) {
  const code = String(content ?? "").trim();
  if (!/^[0-9]{6,8}$/.test(code)) return null;
  const t = traits || {};
  // No OTP facts at all — an artifact from a build that did not carry them, or
  // one restored from somewhere that dropped them. The digits are already on
  // the tile; inventing a period would be worse than saying nothing.
  if (!t.otpMode) return null;
  const mode = String(t.otpMode) === "hotp" ? "hotp" : "totp";
  const period = Number.isInteger(Number(t.otpPeriod)) && Number(t.otpPeriod) > 0
    ? Number(t.otpPeriod)
    : null;
  const step = /^[0-9]+$/.test(String(t.otpStep ?? "")) ? String(t.otpStep) : null;
  const counter =
    Number.isInteger(Number(t.otpCounter)) && Number(t.otpCounter) >= 0
      ? Number(t.otpCounter)
      : null;
  return {
    code,
    groups: groupOtpCode(code),
    mode,
    digits: Number(t.otpDigits) || code.length,
    label: String(t.otpLabel || ""),
    period,
    step,
    counter,
    expiresAt: mode === "totp" && period && step ? (Number(step) + 1) * period : null,
    snapshotSeconds: Number.isFinite(Number(t.otpExpiresIn))
      ? Number(t.otpExpiresIn)
      : null,
  };
}

/**
 * Seconds of life left in a code, right now — negative once it is over.
 *
 * Split out and exported for the reason `expiryTone` is: it is the one piece
 * of the countdown with a decision in it, and a test can walk it past zero in
 * a millisecond where a real code takes half a minute.
 *
 * @param {{ expiresAt: number|null, period: number|null }|null} readout
 * @param {number} nowSeconds  Unix seconds
 * @returns {{ seconds: number, expired: boolean, fraction: number }|null}
 */
export function otpTimeLeft(readout, nowSeconds) {
  if (!readout?.expiresAt || !readout.period) return null;
  const seconds = Math.ceil(readout.expiresAt - Number(nowSeconds));
  return {
    seconds,
    expired: seconds <= 0,
    // Clamped, because a stale artifact is arbitrarily far past its expiry and
    // a bar that ran backwards off the end would be a drawing bug reporting
    // itself as data.
    fraction: Math.min(1, Math.max(0, seconds / readout.period)),
  };
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
