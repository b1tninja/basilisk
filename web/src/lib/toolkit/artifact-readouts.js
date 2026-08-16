/**
 * **The representation layer.** Derivations behind the §37 artifact tiles
 * (design_handoff_artifact_actions).
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
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * ## The boundary this module is one third of
 *
 * `sshKeySummary` was written with a rule in its own docstring — *one
 * derivation, used by the card and by the action, so an op and a tile cannot
 * disagree about the same fact* — and the rule was true in exactly this file.
 * Everywhere else, formatting and derivation were scattered across the engine,
 * the kind table, the cards and the actions, and **six defects in one session
 * are traceable to that**: `publicOnly` doing two jobs so a masked *private*
 * tile captioned itself "public half"; `OpenPgpKeyCard` captioning a private
 * key "public" for the whole of a lazy import; the badge rendering the `role`
 * while `resolvedKind.label` sat one line above, so naming problems were fixed
 * by growing the *matching* vocabulary; `glyph` declared on fourteen kinds and
 * rendered by nothing; a second download namer that was avoided only because
 * someone noticed; and two disabled reasons living as literals beside the
 * module that exists to hold them. So the boundary gets written down.
 *
 * | Layer | Owns | Where |
 * | --- | --- | --- |
 * | **Engine** | *facts* — content, filename, mime, role, tags, traits, sensitive. Computed once, at emit, by the step that produced the value; digested by the receipt. Nothing downstream recomputes one. | `engine.js` and the ops |
 * | **Representation** | *read-outs* — what a human reads **off** those facts, and how it is shaped: a fingerprint in the form the matching CLI prints, a key type, a comment, a packet map, a code and the instant its step ends. | this module |
 * | **View** | *layout only* — where a read-out sits, what is masked, what a `publicView` may draw, how a fraction becomes a CSS bucket. No parsing, no derivation. | `toolkit/widgets/**`, `artifact-kinds/registry.tsx` |
 *
 * ### The rule: a fact derived in two places is a bug
 *
 * Not "avoid duplication" — the stronger claim, that two derivations of one
 * fact are a **defect already**, whether or not they currently agree. Every
 * item in the list above is two answers to one question that had not yet been
 * asked in a state where they differ.
 *
 * ### How a reviewer checks it — three passes, in order
 *
 * 1. **Does a widget parse?** Grep `toolkit/widgets/**` for `JSON.parse`,
 *    `atob`, `TextDecoder`, `readKey`, `await import(` of a codec, or a regex
 *    over `content`. Every hit is either a call into this module or a defect.
 *    `InspectorArtifact`, `JwtArtifact` and `NetworkArtifact` draw structured
 *    data the **engine** attached (`inspectSnapshot`, `jose`, `netData`), so
 *    there is nothing there to parse; they are not exceptions to the rule.
 * 2. **Does one fact have two spellings?** Name the fact, then grep for it.
 *    "Which half is this OpenPGP armor" was answered in three places — the
 *    card's own parse, `hasPrivateKeyMaterial`, and the engine's
 *    `openpgp`/`private` tags — which is how a private key captioned itself
 *    public. If two sites answer one question, one of them calls the other.
 *    (`openpgpKeyForm` is now that one place, and `openpgpKeySummary` calls
 *    it rather than reading the fact a second way off its own parse.)
 * 3. **Does an action need what the card shows?** If a card displays a fact
 *    and an action's `available()` or `run()` needs the same fact, both reach
 *    it through the same exported function here. `sshKeySummary` is the worked
 *    example: `SshKeyCard` draws it, `key.copyFingerprint` copies it.
 *
 * ### What a read-out is allowed to read
 *
 * **`content`, `traits`, `role` and `tags` — and nothing else.** There are
 * three hops between an engine artifact and a tile (`engine` → `useNotebook`'s
 * `cellOutputs` → each of `ToolkitShell`'s two `OutputArtifact` mappings), each
 * an explicit field list that silently drops what it does not name; `traits` is
 * the only open bag copied wholesale. A read-out that reaches for a named field
 * is a read-out a projection nobody edited can disconnect. `shareIdentity` is
 * the standing example and the reason this is a rule rather than a preference:
 * it reads `artifact.shareIndex`, **no** shell mapping copies it, and the share
 * tile works only because the function prefers `traits.shareOf`. The field is
 * dead and the bag saved it. Put a new fact in `traits`, and derive from
 * `traits`.
 *
 * ### What the boundary does not say
 *
 * It does not say every parse in a widget is misplaced. A derivation with one
 * consumer whose output is only ever laid out is view-local, and a refactor
 * that moved everything here on principle would be worse than the scattering:
 * it would put layout decisions behind a function boundary and buy nothing.
 * The test is pass 3 — two consumers, or a fact an action also needs.
 */

import { dearmorToBytes, mapPacketSpans } from "../packet-map.js";
import { parseSshsig } from "../ssh/sshsig.js";
import { parseOpensshPrivateKey } from "../ssh/openssh-key-v1.js";
import { parsePublicBlob, parsePublicLine } from "../ssh/wire.js";
import { sshFingerprint } from "../ssh/fingerprint.js";
import { parseReceipt } from "./receipt.js";
import { bytesToBase64 } from "./encode.js";
// Counting third parties in a server list is the WebRTC layer's fact, not a
// second regex here — the same census `rtc.gather` stamps into its output.
import { iceServerCensus } from "../webrtc/ice.js";
// Same rule: what a relay can and cannot observe is stated once, in the layer
// that arranges for one, and quoted here rather than re-worded per surface.
import { RELAY_DISCLOSURE } from "../webrtc/relay-fallback.js";

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
 * `encryptCapable` is read as three states and not two. `false` is a key the
 * directory has shown cannot receive; `null` is a key nobody has read, which is
 * every row of an `hkp.search` result, because capability lives in a
 * certificate's packets and the directory stores no column for it. `r.x !==
 * false` used to sit here and answer `true` for both of the last two — the
 * unverified row rendering exactly like the verified one, in the list somebody
 * checks before pressing encrypt.
 *
 * @param {string} json
 * @returns {{ fingerprint: string, label: string, email: string,
 *   approvalState: string, encryptCapable: boolean|null }[] | null}
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
      encryptCapable: r.encryptCapable == null ? null : !!r.encryptCapable,
    }));
  return rows.length ? rows : null;
}

/**
 * The rows of a recipient list that match what someone typed.
 *
 * A filter is a *view* — §47c's test is "could this interaction change what
 * Copy copies", and it cannot: the artifact keeps every row, the raw toggle
 * shows the whole JSON, and Copy copies the body. So the input box belongs to
 * the card. **Which rows match does not**, for the one reason that decides it:
 * a fingerprint is stored and displayed in grouped-hex, and a user typing one
 * copies it from wherever they have it — a `gpg --list-keys` line, an email,
 * this tile — so the spaces are arbitrary on both sides. `formatFingerprint`
 * puts them in; this takes them out of both the haystack and the needle. A
 * card that compared the strings as typed would silently match nothing for the
 * one field people paste rather than type, which is a filter that looks broken
 * and reads as "no such recipient".
 *
 * Empty query returns the rows unchanged (the same array, not a copy) so the
 * unfiltered case costs nothing. Order is never touched: it is the order the
 * engine serialized, which is the order `gpg.encrypt` will walk.
 *
 * @param {{ fingerprint: string, label: string, email: string,
 *   approvalState: string, encryptCapable: boolean|null }[]} rows
 * @param {string} query
 */
export function filterRecipientRows(rows, query) {
  const list = Array.isArray(rows) ? rows : [];
  const q = String(query || "").trim().toLowerCase();
  if (!q) return list;
  const bare = q.replace(/\s+/g, "");
  return list.filter((r) => {
    const fpr = String(r?.fingerprint || "").toLowerCase().replace(/\s+/g, "");
    return (
      String(r?.label || "").toLowerCase().includes(q) ||
      String(r?.email || "").toLowerCase().includes(q) ||
      fpr.includes(bare)
    );
  });
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
 * Which half an OpenPGP armor block holds — **the one place that answers it.**
 *
 * The fact had three spellings. `materializeOutArtifacts` tags the artifact
 * `openpgp` + `public`/`private`; `hasPrivateKeyMaterial` in
 * `artifact-actions.js` asks a regex whether any armor carries a private half;
 * and `OpenPgpKeyCard` used to take it off `readKey`'s result. The third one is
 * what bit: `parsed` is null for the whole of the lazy `openpgp` import and
 * permanently for armor that will not parse, so `parsed?.isPrivate ? "private"
 * : "public"` captioned a **private** key *public* — a two-state caption
 * driven by a three-state fact, whose null case defaults to the wrong half.
 *
 * The fix that shipped first was to make the caption *wait* for the parse,
 * which is correct about the disagreement and wrong about the answer: the
 * armor's own header states this synchronously, always, for every key OpenPGP
 * will ever emit, and a tile that knows which half it is holding should say so
 * on the first frame. What made waiting look like the only option was that
 * there was nowhere to put a second derivation that was not a *second source*.
 * There is now: this is the source, and `openpgpKeySummary` calls it rather
 * than reading the fact off its own parse, so the two cannot differ.
 *
 * Header-only on purpose. RFC 9580 §6.2 fixes both labels, and the alternative
 * — deciding from packet tags — would need the parse this exists to precede.
 * Anything that is not one of the two returns null and the caller says nothing,
 * which is `KeyCard.half`'s rule and the reason it exists.
 *
 * @param {string} armored
 * @returns {"public"|"private"|null}
 */
export function openpgpKeyForm(armored) {
  const text = String(armored || "");
  if (text.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")) return "private";
  if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) return "public";
  return null;
}

/**
 * What an OpenPGP key artifact says about itself: whose it is, its fingerprint,
 * and the two dates.
 *
 * An armored key is base64 packets — unreadable as text and actively
 * misleading as a preview, because the first lines are identical for every key
 * ever generated. The one question a reader has is *whose is this*, and the
 * armor answers it only after parsing.
 *
 * This lived inside `OpenPgpKeyCard` and moved here for the reason the module
 * header gives: it is a parse of a body, it is the third-largest derivation in
 * the tile layer, and inside a component it had **no test at all** — the suite
 * is `environment: "node"`, so nothing could reach it. It is also the parse
 * `key.publish`'s confirmation deliberately declines to repeat ("the uid would
 * have to come from a second parse of the armor"); that decision stands, and it
 * is now a decision about *what to say* rather than one forced by there being
 * only one place the answer existed.
 *
 * The import stays lazy. `openpgp` is a large module and most tiles are not
 * keys, so this awaits it rather than pulling it into every bundle that touches
 * a read-out — the same call the card made, kept.
 *
 * `expiresAt` rides alongside the formatted date because a reader's question is
 * "is it still good", not "when does it expire" (§48b), and `expiryNote` in
 * `GpgKeyBinder.tsx` already turns an instant into that verdict. Handing back a
 * pre-formatted string alone would have forced whoever wires that up to parse
 * the date this function already had.
 *
 * Total, like everything here: malformed or truncated armor returns null and
 * the tile renders the armor it would have rendered anyway (§32d). Our
 * inability to describe a value is not the user's problem to debug.
 *
 * @param {string} armored
 * @returns {Promise<{ form: "public"|"private", uid: string,
 *   fingerprint: string, created: string, expires: string|null,
 *   expiresAt: number|null } | null>}
 */
export async function openpgpKeySummary(armored) {
  const text = String(armored || "");
  const form = openpgpKeyForm(text);
  if (!form) return null;
  try {
    const { readKey } = await import("openpgp");
    const key = await readKey({ armoredKey: text });
    const primary = await key.getPrimaryUser().catch(() => null);
    const exp = await key.getExpirationTime().catch(() => null);
    // `getExpirationTime` answers `Infinity` for a key that does not expire,
    // which is not a Date — so the guard is the null branch and "does not
    // expire" is said in words by the caller rather than drawn as a date.
    const expiresAt =
      exp instanceof Date && Number.isFinite(exp.getTime()) ? exp.getTime() : null;
    return {
      form,
      uid: primary?.user?.userID?.userID || "",
      fingerprint: key.getFingerprint().toUpperCase(),
      created: key.getCreationTime().toISOString().slice(0, 10),
      expires: expiresAt ? new Date(expiresAt).toISOString().slice(0, 10) : null,
      expiresAt,
    };
  } catch (_) {
    return null;
  }
}

/**
 * When a validity window ends, as a Unix millisecond instant — or null.
 *
 * One normalizer because the three things that expire around here state it
 * three ways: `openpgpKeySummary` hands back `expiresAt` in milliseconds, the
 * vault's `VaultKeyRow.expires` is milliseconds, and `rtc.cert`'s DTLS
 * certificate carries an **ISO string** (`rtc-ops.js` — `new Date(cert.expires)
 * .toISOString()`). Left to the call sites that is a `Date.parse` inside a
 * widget and a bare subtraction in another, which is a fact with two spellings
 * before anyone has written the second one.
 *
 * Total: anything unparseable is *no known expiry*, not zero — a certificate
 * whose date we cannot read has not expired, it is undescribed, and the caller
 * says nothing rather than "expired".
 *
 * @param {number|string|Date|null|undefined} expires
 * @returns {number|null}
 */
export function expiryInstant(expires) {
  if (expires == null || expires === "") return null;
  if (expires instanceof Date) {
    return Number.isFinite(expires.getTime()) ? expires.getTime() : null;
  }
  if (typeof expires === "number") return Number.isFinite(expires) ? expires : null;
  const parsed = Date.parse(String(expires));
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Days until a validity window closes, rounded up. Null when nothing expires.
 *
 * @param {number|string|Date|null|undefined} expires
 * @param {number} [now]  Unix milliseconds
 * @returns {number|null}
 */
export function daysUntilExpiry(expires, now = Date.now()) {
  const at = expiryInstant(expires);
  if (at == null) return null;
  return Math.ceil((at - now) / 86_400_000);
}

/**
 * **Is this still good** — the verdict a reader wants where a card prints a
 * date (§48b, D5).
 *
 * `expires 2027-08-01` answers a question nobody asked. The question is
 * whether the thing is usable *now*, and every card that showed a bare date
 * was handing its reader two dates and a subtraction. This is §47b's **tier
 * 1**: recomputed at render against `Date.now()`, resolution in days, and
 * therefore **no timer** — the text cannot differ if it re-renders a second
 * later, which is the whole test for which tier a live fact belongs in.
 *
 * Only speaks up inside a month. A key expiring in a year is not news, and a
 * warning shown on every row would train people to ignore the one that counts.
 * That discipline is what makes it safe to add to *every* card that shows an
 * expiry rather than to the ones someone remembered.
 *
 * **It lived in `GpgKeyBinder.tsx`** and was correct there under the boundary's
 * own exception — one consumer, output only laid out, view-local. It stopped
 * being one the moment `OpenPgpKeyCard` and `NetworkArtifact`'s certificate
 * panel needed the same verdict: three consumers of one derivation, which is
 * check 3 in this module's header, and a widget is where the two copies would
 * have gone. Nothing about the answer changed in the move — the strings and the
 * thresholds are the shipped ones, asserted verbatim in `gpg-key-binder.test.js`
 * — because a "while I am here" rewording is how a tested sentence rots.
 *
 * `now` is a parameter for the reason `otpTimeLeft`'s is: the boundaries are
 * 30 days, 7 days, today and past, and a test that had to wait for one of them
 * would be a test nobody runs. It is also D3's lesson — a fixture pinned to the
 * day it was written reads *expired* forever.
 *
 * @param {number|string|Date|null|undefined} expires
 * @param {number} [now]  Unix milliseconds
 * @returns {{ text: string, severity: "warn"|"error" }|null}
 */
export function expiryNote(expires, now = Date.now()) {
  const days = daysUntilExpiry(expires, now);
  if (days == null) return null;
  if (days < 0) return { text: "expired", severity: "error" };
  if (days === 0) return { text: "expires today", severity: "error" };
  if (days <= 30) {
    return {
      text: `expires in ${days} day${days === 1 ? "" : "s"}`,
      severity: days <= 7 ? "error" : "warn",
    };
  }
  return null;
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
 * `pinnedAt` is the one field here that is not arithmetic on the others. It is
 * the instant the *recipe* named with `at=`, and it is absent when the recipe
 * meant "now". Without it the two cases arrive identically — same trait shape,
 * same absolute expiry — and a code computed for 2023 draws the same draining
 * bar as one computed a second ago, lands on **expired**, and tells its reader
 * to re-run the cell for the current one. Re-running a pinned step produces
 * the same digits forever, so that instruction was the one guaranteed to fail.
 * TOTP only: `at=` is a claim about a clock and HOTP has none.
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
 *   snapshotSeconds: number|null, pinnedAt: number|null } | null}
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
  const pinned = Number(t.otpPinnedAt);
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
    pinnedAt: mode === "totp" && Number.isFinite(pinned) && pinned > 0 ? pinned : null,
  };
}

/**
 * Seconds of life left in a code, right now — negative once it is over.
 *
 * Split out and exported for the reason `expiryTone` is: it is the one piece
 * of the countdown with a decision in it, and a test can walk it past zero in
 * a millisecond where a real code takes half a minute.
 *
 * **It is also the one place that decides whether a clock applies at all**, and
 * null is that answer for two different objects. A HOTP code has no clock to
 * measure against: an event counter does not expire, it gets spent. A *pinned*
 * code has a clock, but not this one — the recipe named the instant, and:
 *
 * > A card may tick only against an instant the recipe did not choose. If the
 * > recipe named the instant, the card states it. If the recipe meant *now*,
 * > the run fixed an instant and the card may count from it.
 *
 * Counting a pinned code down against wall-clock now answers a question nobody
 * asked — it expired relative to the instant `at=` named, which is a different
 * statement — and it is what produced *"expired — run the cell again for the
 * current one"* over a value that is identical on every run by construction.
 * Refusing the arithmetic here rather than branching in the widget is why the
 * rule is testable in node, and why a second card reading these fields cannot
 * reintroduce the same claim.
 *
 * @param {{ expiresAt: number|null, period: number|null,
 *   pinnedAt?: number|null }|null} readout
 * @param {number} nowSeconds  Unix seconds
 * @returns {{ seconds: number, expired: boolean, fraction: number }|null}
 */
export function otpTimeLeft(readout, nowSeconds) {
  if (readout?.pinnedAt) return null;
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
 * The set id joins them for the reason the other two are here: it is the fact
 * that decides whether two cards belong together, `decodeShareSet` names it in
 * the refusal a custodian meets when they do not, and "Check a share…" prints
 * it as `set XXXX`. A tile that shows it lets those three be compared without
 * anybody revealing a share to do it. It is public by construction — the
 * fifteen bits are drawn at encode time and carried in the clear in every one
 * of the set's mnemonics, so it distinguishes splits and discloses nothing
 * about the secret.
 *
 * The recipient joins them because a *sealed* share tile could not answer the
 * question it exists to raise. `seal to=each` and `gpg.encrypt mode=separate`
 * make one artifact per holder, and the plain-ciphertext branch names the
 * holder in the label (`GPG ciphertext for <fingerprint>`) and in the filename.
 * The share branch does not: it labels `Share 2 (GPG)` and writes
 * `share-2.asc`, so a dealer holding three sealed files to hand out had the
 * index and the threshold and nothing at all saying *whose* each one is. The
 * artifact has carried `recipientFingerprint` the whole time, whole, with no
 * reader on any surface — this is the reader, and `traits.sealedTo` is how it
 * arrives. The named field alone would not have done: it is dropped by all
 * three projections between the engine and a tile, so a read-out built on it
 * renders under test and nowhere a person can look, which is the same defect
 * one layer along.
 *
 * Local by construction, and that matters here: the sealed *value* drops
 * `shareIndex` precisely so a published envelope cannot tell the room which
 * share went to whom. This is the dealer's own artifact list on the dealer's
 * own machine — the side already entitled to know, the same side
 * `sealed-share-envelope.test.js` labels "the machine entitled to know" — and
 * nothing here crosses a wire.
 *
 * Whole, never a tail. The 8-hex form this replaces is the defect `88fcfd0`
 * swept out of `src`; a fingerprint on a tile is what a sender checks before
 * handing a file over, and two keys ending alike is exactly the case it has to
 * survive.
 *
 * @param {{ shareIndex?: number, tags?: string[], recipientFingerprint?: string,
 *   traits?: { shareOf?: number, threshold?: number, setId?: string,
 *     sealedTo?: string } }} artifact
 * @returns {{ index: number, threshold: number, setId: string, flavour: string,
 *   recipient: string } | null}
 */
export function shareIdentity(artifact) {
  const traits = artifact?.traits || {};
  const index = Number(traits.shareOf ?? artifact?.shareIndex ?? 0) || 0;
  const threshold = Number(traits.threshold ?? 0) || 0;
  const setId = String(traits.setId ?? "").toUpperCase();
  // `traits` first, for the reason this module's header gives about
  // `shareOf`: the named field beside it survives no projection, so a read-out
  // that trusted it would render in a test and nowhere a person can look.
  const recipient = String(traits.sealedTo ?? artifact?.recipientFingerprint ?? "").toUpperCase();
  if (!index && !threshold && !setId) return null;
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
  return { index, threshold, setId, flavour, recipient };
}
/* ══════════════════════════════════════════════════════════════════════════
 *  WebRTC read-outs — the three panels a user lands on when a call fails
 * ══════════════════════════════════════════════════════════════════════════
 *
 * These exist because the WebRTC panels were the one family that rendered
 * every field correctly and answered none of the reader's question. A user
 * only opens `rtc.state`, `stun.check` or an SDP blob when a connection did
 * not form, so the bar for each of them is **why did this not connect, and
 * what do I do next** — not "is `iceConnectionState` shown".
 *
 * They live here rather than in `NetworkArtifact.tsx` for the reason the whole
 * module exists: a verdict written inside a component is a verdict with no
 * test, and these are the sentences most worth pinning.
 */

/**
 * Verdict, cause and next step for one peer's connection state (§30d).
 *
 * **The strip had no state for `failed`.** Its five stages were
 * `new → connecting → connected → disconnected → closed`, and
 * `RTCPeerConnection.connectionState` also takes the value `"failed"` — which
 * `rtc.state` emits verbatim. `indexOf("failed")` was `-1`, so no segment was
 * marked reached and no label was bolded: **a peer connection that had failed
 * rendered pixel-identical to one that had not started.** That is the single
 * state the panel exists for.
 *
 * The fix is not a sixth segment. `disconnected`, `failed` and `closed` are
 * not later milestones on the way to something — they are *outcomes*, and
 * drawing them in line with `connecting` said a connection progresses toward
 * being closed. So the track is the three stages that really are a sequence,
 * and an outcome is a terminal verdict beside it.
 *
 * `iceConnectionState` and `channelState` refine the cause: ICE up with no
 * open channel is the SCTP phase, which is a different problem from ICE never
 * finding a route, and telling a reader to add TURN in that case wastes their
 * afternoon.
 *
 * @param {{ connectionState?: string, iceConnectionState?: string,
 *   signalingState?: string, channelState?: string }} peer
 * @returns {{
 *   stages: { name: string, state: "past"|"current"|"ahead" }[],
 *   terminal: { name: string, tone: "warn"|"error"|"muted" } | null,
 *   tone: "brand"|"caret"|"warn"|"error"|"muted",
 *   headline: string,
 *   why: string | null,
 *   next: string | null,
 * }}
 */
export function connStateReadout(peer) {
  const conn = String(peer?.connectionState || "new");
  const ice = String(peer?.iceConnectionState || "");
  const chan = String(peer?.channelState || "");
  const track = ["new", "connecting", "connected"];
  /** @type {Record<string, "warn"|"error"|"muted">} */
  const OUTCOMES = { disconnected: "warn", failed: "error", closed: "muted" };
  const outcome = OUTCOMES[conn] || null;
  // An outcome is reached *from* connected, so the track behind it stays lit —
  // a failed call did get somewhere, and blanking the track would hide how far.
  const at = outcome ? track.length - 1 : Math.max(0, track.indexOf(conn));
  const stages = track.map((name, i) => ({
    name,
    state: /** @type {"past"|"current"|"ahead"} */ (
      outcome ? (i <= at ? "past" : "ahead") : i < at ? "past" : i === at ? "current" : "ahead"
    ),
  }));

  if (conn === "failed") {
    return {
      stages,
      terminal: { name: "failed", tone: "error" },
      tone: "error",
      headline: "Could not connect",
      why: "ICE checked every candidate pair it had and none of them worked, so there is no route between the two ends.",
      // What to do next depends on whether a relay has already been tried, and
      // this row now carries that. Telling someone to "add a TURN relay" after
      // the fallback has added one and failed anyway is the same class of
      // mistake as reporting a declined STUN server as a fault.
      next: relayNextStep(peer?.relay),
    };
  }
  if (conn === "disconnected") {
    return {
      stages,
      terminal: { name: "disconnected", tone: "warn" },
      tone: "warn",
      headline: "Connection lost",
      why: "The transport stopped answering. ICE keeps rechecking for a while before it declares the connection failed, so this can recover on its own.",
      next: "Wait, or restart the connection — that renegotiates ICE in place and keeps the room and the roster.",
    };
  }
  if (conn === "closed") {
    return {
      stages,
      terminal: { name: "closed", tone: "muted" },
      tone: "muted",
      headline: "Closed",
      why: "This peer connection has been torn down. Nothing further will arrive on it.",
      next: null,
    };
  }
  if (conn === "connected") {
    // ICE and DTLS are up but SCTP has not finished — the phase 28a put in the
    // log and no panel ever named. Reported because "connected" beside a
    // channel that will not open is the most confusing state in the set.
    if (chan && chan !== "open") {
      return {
        stages,
        terminal: null,
        tone: "warn",
        headline: "Connected, channel not open",
        why: `The transport is up and DTLS completed, but the data channel is ${chan} — SCTP has not finished negotiating on top of it.`,
        next: "Give it a moment. If it stays here, both ends have to agree the channel's label and negotiation mode; a channel opened on one side only never opens.",
      };
    }
    return { stages, terminal: null, tone: "brand", headline: "Connected", why: null, next: null };
  }
  if (conn === "connecting") {
    return {
      stages,
      terminal: null,
      tone: "caret",
      headline: ice === "checking" ? "Checking candidate pairs" : "Connecting",
      why: null,
      next: null,
    };
  }
  return {
    stages,
    terminal: null,
    tone: "muted",
    headline: "Not started",
    why: "Nothing has been negotiated on this connection yet.",
    next: null,
  };
}

/**
 * What a `stun.check` result means, and what to do about it (§22b).
 *
 * `stun.check` reports the candidate mix it gathered (`host ×4 srflx ×0`) —
 * added the day the transport was first driven against real browsers, because
 * a "blocked" badge sent the reader to a screen that could not say *what* had
 * been gathered. Which types arrived **is** the diagnosis:
 *
 *  - `srflx` present — the STUN round trip completed. STUN is not the problem.
 *  - `srflx` absent but `host` present — the browser gathered fine and the
 *    STUN server never answered. That is a blocked UDP path or a dead server,
 *    and it is a different fix from "no TURN".
 *  - nothing at all — the gather itself produced nothing, which is a config or
 *    secure-context problem rather than a network one.
 *
 * **This function never mentions relay.** `stun.check` refuses any `server=`
 * that is not `stun:`/`stuns:` and allocates with no credential, so it never
 * attempts a TURN allocation and its relay count is a constant, not a
 * measurement — verified against a live coturn that was relaying for two peers
 * at the time. A "no TURN configured" verdict derived from a number the op
 * never took would be the panel guessing, on the one screen a user reaches
 * when a connection has already failed. Whether a relay candidate exists is
 * `rtc.gather`'s question, and its own panel answers it.
 *
 * @param {{ ok?: boolean, publicAddress?: string,
 *   candidates?: Record<string, number> }} data
 * @returns {{ tone: "brand"|"warn"|"error", verdict: string,
 *   why: string, next: string | null }}
 */
export function stunReachability(data) {
  const mix = data?.candidates;
  const host = Number(mix?.host || 0);
  const srflx = Number(mix?.srflx || 0);

  // No mix *reported* is not a mix of zeroes. `stun.check` only began counting
  // candidates on the day the transport was first driven against real
  // browsers, so an older result — or a replayed one — carries a verdict and
  // an address and nothing else. Reading that absence as "gathered nothing"
  // would print `nothing gathered` beside a discovered public address, which
  // is the same class of mistake as the relay count next door: a number the op
  // never took, rendered as a measurement.
  if (!mix) {
    const ok = data?.ok !== false && !!data?.publicAddress;
    return {
      tone: ok ? "brand" : "warn",
      verdict: ok ? "reachable" : "blocked",
      why: ok
        ? `A reflexive address came back${data?.publicAddress ? ` at ${data.publicAddress}` : ""}. This result carries no candidate breakdown, so which types were gathered is not known.`
        : "STUN did not report a reachable address, and this result carries no candidate breakdown to say how far it got.",
      next: ok ? null : "Re-run stun.check — a current result reports the candidate mix, which is what separates a blocked STUN path from an empty ICE server list.",
    };
  }
  if (!(host + srflx)) {
    return {
      tone: "error",
      verdict: "nothing gathered",
      why: "The browser produced no ICE candidates at all — not even a host one, which needs no network.",
      next: "Check that the ICE server list is not empty and that the page is a secure context; RTCPeerConnection gathers nothing outside one.",
    };
  }
  if (!srflx) {
    return {
      tone: "warn",
      verdict: "STUN did not answer",
      why: `Gathering worked — ${host} host candidate${host === 1 ? "" : "s"} — but no server-reflexive candidate came back, so the STUN round trip never completed.`,
      next: "The usual cause is UDP blocked outbound. Try another server with rtc.ice stun=…; if that returns nothing either, the network is filtering and only a TURN relay over TCP/TLS will get out.",
    };
  }
  return {
    tone: "brand",
    verdict: "STUN answered",
    why: `A server-reflexive candidate came back${data?.publicAddress ? ` at ${data.publicAddress}` : ""}, so this network reaches a STUN server and a peer can learn where to send.`,
    // No next step, and that is the honest answer: STUN working is as far as
    // this op looks. If a connection still will not form, the next screen is
    // `rtc.gather`'s candidate list, which is the one that can say whether a
    // relay route exists.
    next: null,
  };
}

/**
 * What an `rtc.ice` config *does to you*, read off the list itself (§22b).
 *
 * The defaults were invisible in both directions: a blank `stun=` contacted
 * Cloudflare and Google, and the artifact that came out listed two URLs with
 * nothing to say they were a fallback rather than a choice. This is the panel
 * line that states the consequence — who learns what, when a connection is
 * built from this config — and it is the same sentence whether the list came
 * from the defaults, from typed URLs, or from `stun=none`.
 *
 * The empty case is not an error and is not drawn as one. It is the answer to
 * a question the app previously would not let anyone answer.
 *
 * @param {{ iceServers?: unknown }} data
 * @returns {{ tone: "brand"|"warn"|"muted", verdict: string,
 *   why: string, next: string | null } | null}
 */
export function iceServerPolicy(data) {
  if (!Array.isArray(data?.iceServers)) return null;
  const { stun, turn } = iceServerCensus(
    /** @type {RTCIceServer[]} */ (data.iceServers)
  );
  if (!stun && !turn) {
    return {
      tone: "muted",
      verdict: "no third party",
      why: "This config names no STUN and no TURN server. A connection built from it gathers host candidates only — your machine's own addresses — and no packet goes anywhere except to the peer.",
      next: "Host candidates reach peers on the same network. Across NAT there is no reflexive address to offer and the connection will not form; that is the trade this config makes.",
    };
  }
  if (turn) {
    return {
      tone: "warn",
      verdict: `${stun} STUN · ${turn} TURN`,
      why: `A relay carries the connection's packets. The channel stays end-to-end encrypted — a TURN server forwards DTLS it cannot read — but it sees both addresses, the timing and the volume, which a STUN server never does.`,
      next: null,
    };
  }
  return {
    tone: "brand",
    verdict: `${stun} STUN`,
    why: `Each of these ${stun === 1 ? "server" : "servers"} learns this machine's public address when a connection is made, and nothing else — a STUN binding request carries no traffic.`,
    next: "Write `rtc.ice stun=none` for a config that contacts nobody at all.",
  };
}

/* ───────────────────────── the relay fallback (§22c) ───────────────────── */

/**
 * What to say after a connection has failed, given what the relay fallback did.
 *
 * Five different sentences because they are five different situations, and the
 * one that used to be printed for all of them — "Add a TURN relay" — is only
 * right for the first. After the fallback has tried a relay and the connection
 * failed anyway, that instruction is advice to do the thing that just did not
 * work.
 *
 * @param {{ phase?: string, reason?: string } | null | undefined} relay
 * @returns {string}
 */
export function relayNextStep(relay) {
  const phase = String(relay?.phase || "off");
  if (phase === "escalating") {
    return "A relay credential is being minted now, and ICE will restart with the relay in place. Nothing was asked of a relay operator until this moment.";
  }
  if (phase === "escalated") {
    return "A relay was added and ICE restarted. If it connects, the relay is carrying the traffic — it cannot read it, but it can see both addresses and the volume.";
  }
  if (phase === "exhausted") {
    return "A relay was already added and the connection failed anyway, so there is nothing further to try automatically. The remaining causes are outside this page: the relay refused the credential, or the network blocks it too.";
  }
  if (phase === "unavailable") {
    const why = String(relay?.reason || "").trim();
    return `No relay was available${why ? ` — ${why}` : ""}. This deployment may have none configured; a relay you operate can be named directly with \`rtc.ice turn=\`.`;
  }
  return "Host and server-reflexive candidates only describe routes a peer can reach directly; with both ends behind symmetric NAT there is no such route to find. A TURN relay is the fix — name one with `rtc.ice turn=`, or turn on the relay fallback, which contacts one only after a failure like this one.";
}

/**
 * The relay's status on one link, as a panel line — and the disclosure with it.
 *
 * `configured`, `escalated` and `relayed` are three facts and this keeps them
 * three. A relay that was added and then not used carried nothing and is
 * reported as such; saying "relayed" there would overstate what a third party
 * saw, which is the same defect as understating it.
 *
 * The disclosure travels with every state except `off`, because the moment a
 * relay is in the picture is the moment its terms matter — and the terms are
 * `RELAY_DISCLOSURE`'s exact words, not a paraphrase per surface.
 *
 * @param {{ relay?: { phase?: string, configured?: boolean, reason?: string },
 *   relayed?: boolean }} row
 * @returns {{ tone: "brand"|"warn"|"muted"|"error", verdict: string,
 *   why: string, disclosure: string | null }}
 */
export function relayFallbackReadout(row) {
  const phase = String(row?.relay?.phase || "off");
  const disclosure = phase === "off" ? null : RELAY_DISCLOSURE.summary;
  if (phase === "off") {
    return {
      tone: /** @type {"muted"} */ ("muted"),
      verdict: "no relay",
      why: "No relay is configured for this connection and none will be contacted. Packets go between the two ends, or nowhere.",
      disclosure: null,
    };
  }
  if (phase === "armed") {
    return {
      tone: /** @type {"muted"} */ ("muted"),
      verdict: "relay on standby",
      why: "This connection gathered and connected with no relay in its list, so no relay operator has heard of it. One is asked for only if ICE fails outright.",
      disclosure,
    };
  }
  if (phase === "escalating") {
    return {
      tone: /** @type {"warn"} */ ("warn"),
      verdict: "asking for a relay",
      why: "ICE failed, so a short-lived relay credential is being minted. This is the first moment a relay operator learns this connection exists.",
      disclosure,
    };
  }
  if (phase === "unavailable") {
    return {
      tone: /** @type {"warn"} */ ("warn"),
      verdict: "no relay available",
      why: `The fallback asked for a relay and did not get one${row?.relay?.reason ? ` — ${row.relay.reason}` : ""}. Nothing was relayed, and nothing was disclosed beyond the request itself.`,
      disclosure,
    };
  }
  if (phase === "exhausted") {
    return {
      tone: /** @type {"error"} */ ("error"),
      verdict: "relay did not help",
      why: "A relay was added and ICE failed again. One escalation per connection is the rule, so nothing further will be tried on its own.",
      disclosure,
    };
  }
  // escalated
  return {
    tone: /** @type {"warn"} */ ("warn"),
    verdict: row?.relayed ? "relayed" : "relay added",
    why: row?.relayed
      ? "This connection is going through the relay, which is forwarding every packet in both directions."
      : "A relay was added and ICE restarted. The selected candidate pair is not a relay one, so the relay allocated and is carrying nothing.",
    disclosure,
  };
}

/**
 * Why a candidate type is missing — a choice, or a fault (§26a).
 *
 * `rtc.gather` now records the ICE config it gathered against, which is what
 * makes this answerable at all. The relay row used to name all three possible
 * causes at once and say so honestly, *because the output carried no server
 * list and the panel could not know which had happened*. It knows now, for
 * anything gathered since; an older artifact carries no `ice` field and gets
 * the same undecided sentence it always did, because that one is still true.
 *
 * The distinction is `stunReachability`'s, one level down: *not probed* is not
 * the same fact as *probed and absent*, and a deliberate no-third-party run is
 * the first of those. Saying "none gathered" for a STUN server the user
 * declined would report their own choice back to them as a fault.
 *
 * @param {string} type  one of host / prflx / srflx / relay
 * @param {{ ice?: { stun?: number, turn?: number } }} data
 * @returns {string}
 */
export function candidateAbsence(type, data) {
  const ice = data?.ice;
  if (type === "prflx") {
    return "none — peer-reflexive only appears during negotiation";
  }
  if (type === "srflx") {
    if (ice && !Number(ice.stun || 0)) {
      return "none — no STUN server was configured for this gather, so no reflexive candidate could be asked for. This is the config you ran, not a network failure.";
    }
    return "none gathered — a STUN server was configured and no reflexive candidate came back, so the round trip did not complete";
  }
  if (type === "relay") {
    if (ice && !Number(ice.turn || 0)) {
      return "no relay route — no TURN server was configured for this gather. Informational, not a failure.";
    }
    if (ice) {
      return "no relay route — a TURN server was configured and allocated nothing: it refused the credential, or never answered. Both arrive here as nothing, and only `icecandidateerror` 401 tells them apart.";
    }
    // Verified end to end against a live coturn on the day this was written,
    // and the same run showed that a wrong password and a dead server both
    // yield exactly this empty result. An artifact from before `rtc.gather`
    // recorded its config cannot say which of the three happened, and says so
    // rather than picking the flattering one.
    return "no relay route — either no TURN is configured, or one is and it refused the credential or never answered. All three arrive here as nothing.";
  }
  return "none gathered";
}

/**
 * The one place the SDP-carrying instruction is written down.
 *
 * This constant used to say the opposite, and was correct at the time:
 * `rtc.offer`/`rtc.answer` closed their own `RTCPeerConnection` before
 * returning, so the ICE credentials and fingerprint named a transport that was
 * already gone and no amount of carrying the blob could complete a handshake.
 * `peer.offer`/`peer.answer` keep the connection under a name (§55), so the
 * limit is lifted and the note becomes what to *do* with the blob instead of
 * why it cannot work.
 */
export const SDP_CARRY_NOTE =
  "The connection this describes is live, held under its peer.* name. Carry " +
  "this blob to the other side by any channel you like: an offer goes into " +
  "peer.answer there, and the answer that comes back goes into peer.accept " +
  "here. peer.wait then blocks until ICE completes.";

/**
 * What a link's origin means for the traffic on it — the one place the
 * authentication difference is worded (§58b).
 *
 * Two consumers on day one, which is why it is a read-out and not a string in
 * a component: the Connections panel's section caution, and the `connstate`
 * tile. Both must say the same thing, because the difference is a security
 * property rather than a label — a `quorum` channel's far end proved possession
 * of a PGP key and its traffic is sealed under a pairwise key bound to both
 * DTLS fingerprints; a `peer` channel's far end is whoever received the offer.
 *
 * @param {string} origin
 * @returns {{ label: string, tone: "brand"|"warn", why: string }}
 */
export function linkOriginNote(origin) {
  if (String(origin) === "quorum") {
    return {
      label: "verified",
      tone: /** @type {"brand"} */ ("brand"),
      why: "Identity-bound: the far end proved possession of a key in this room's audience, and traffic is sealed under a pairwise key derived over a transcript that includes both DTLS fingerprints.",
    };
  }
  return {
    label: "unauthenticated",
    tone: /** @type {"warn"} */ ("warn"),
    why: "DTLS encrypts the wire, but nothing here proves who is on the other end — it is whoever received the offer. Use quorum.offer / quorum.join when the peer's identity has to be proven.",
  };
}

/**
 * What is actually in an SDP blob, and what can be done with it (§30d).
 *
 * Two jobs, and the second is the one that matters.
 *
 * **A read-out.** An SDP blob is 700 bytes of line-oriented text, and the
 * three things a human reads it for are the DTLS fingerprint, the candidates
 * it carries, and the transport line. Those are pulled out here; the raw text
 * stays below them, because a fingerprint you have to hunt for is a
 * fingerprint nobody checks.
 *
 * **What to do with it, stated plainly.** This half used to be a refusal: the
 * ops that made an SDP closed its transport before returning, so the panel said
 * the hand-carried flow could not complete rather than letting a reader find
 * out by watching a handshake time out. `peer.*` keeps the connection alive
 * (§55), so the same slot now carries the instruction instead of the limit —
 * 28c's rule either way: say what the platform really does, and never imply a
 * capability that is not there.
 *
 * This does **not** restate `sdpRole()`'s offer/answer rule (`rtc-ops.js`),
 * which is what `peer.answer` refuses on. It prints the `a=setup:` line — the
 * datum that rule reads — and leaves the verdict where it is written.
 * `rtc-ops.js` is deliberately not imported: it is loaded dynamically so that
 * `RTCPeerConnection` stays out of the base bundle, and a static import here
 * would pull it into every page that draws an artifact tile.
 *
 * Total: an unparseable blob yields empty fields and the same standing note,
 * never a throw.
 *
 * @param {string} sdp
 * @returns {{
 *   fingerprint: { algorithm: string, value: string } | null,
 *   setup: string,
 *   transport: string,
 *   candidates: { type: string, count: number }[],
 *   lines: number,
 *   liveTransport: boolean,
 *   note: string,
 * }}
 */
export function sdpReadout(sdp) {
  const text = String(sdp || "");
  const fpr = text.match(/^a=fingerprint:(\S+)\s+(\S+)/m);
  const setup = text.match(/^a=setup:(\S+)/m);
  const mline = text.match(/^m=(\S+)\s+\S+\s+(\S+)/m);
  /** @type {Record<string, number>} */
  const byType = {};
  for (const m of text.matchAll(/^a=candidate:.*?\styp\s(\S+)/gm)) {
    byType[m[1]] = (byType[m[1]] || 0) + 1;
  }
  return {
    fingerprint: fpr ? { algorithm: fpr[1], value: fpr[2] } : null,
    setup: setup ? setup[1] : "",
    transport: mline ? `${mline[1]} ${mline[2]}` : "",
    candidates: ["host", "srflx", "relay", "prflx"]
      .filter((t) => byType[t])
      .map((t) => ({ type: t, count: byType[t] })),
    lines: text ? text.split(/\r?\n/).filter(Boolean).length : 0,
    liveTransport: true,
    note: SDP_CARRY_NOTE,
  };
}
