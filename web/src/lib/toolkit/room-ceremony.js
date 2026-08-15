/**
 * The split-key ceremony for a room, generated from the room.
 *
 * `ceremony.js` beside this file is the *solo* ceremony: one machine splits, one
 * machine verifies, one machine prints cards, and `@peer` appears in it zero
 * times. This is the other one — the secret is dealt to the people who are in
 * the room, over the room.
 *
 * ## This notebook is the deal and nothing else
 *
 * It used to also contain the recovery — return cells for every holder, the
 * dealer's own return, a gather armed with a thirty-minute wait — and the
 * dealer-absent e2e proved what that costs: `runFrom(i)` walks to the end of
 * the document, the dealer's return cell sat below the split, so the one press
 * that dealt the secret also gave the dealer's share back, and every later
 * recovery silently preferred it. The picker's phase labels ("Dealing — run
 * once, together" / "Recovering — run when the secret is wanted back") were
 * doctrine with no mechanism: nothing in the product can run one phase.
 *
 * A deal and its reversal are made at different times, by different sets of
 * people — the recoverer's whole premise is that the dealer may be gone — under
 * different threat models. **They are two agreements, so they are two
 * notebooks.** This module writes the deal; `room-recovery.js` beside it writes
 * the recovery, at recovery time, from the shares' own BLIP39 headers. There is
 * nothing below the deal for a run to walk into, so the phases this module used
 * to label do not exist to be mislabelled.
 *
 * ## Why this is still a generator and not a preset
 *
 * Because the receive-cell count depends on who is in the room, and a `@peer`
 * header addresses a whole fingerprint — so the notebook cannot be written
 * until the room is known. The order is therefore: **choose the audience, and
 * the notebook falls out of it.** Nothing here is authored against a
 * placeholder that is resolved later — see `ROOM_CEREMONY_PLACEHOLDERS` for
 * why a placeholder could not have worked.
 *
 * ## What the room decides
 *
 * - **`shares` is the room size.** One share per member, so a count that
 *   disagrees with the number of people is unreachable by construction rather
 *   than refused after the fact — and it is the count `scatter to=room` will
 *   verify against the live exchange before anything moves.
 * - **`threshold` is a majority**, `floor(shares / 2) + 1`. Majority rather than
 *   any smaller fraction because any two qualifying sets then intersect: with
 *   `2/4`, two disjoint pairs could each rebuild the secret without the other
 *   knowing it had happened, and no record anywhere would show two recoveries.
 *   A majority makes that arithmetically impossible.
 * - **Who holds which share is the canonical audience order.** `scatter` deals
 *   share i to member i in `canonicalAudience`'s order — sorted, deduped,
 *   derived on every machine and chosen by nobody — so the receive slots here
 *   are numbered by that same derivation, through the same function. A second
 *   opinion about the order would be the one divergence nothing could report.
 *
 * ## What it is, said plainly
 *
 * A **dealer-based split**. One machine draws the secret and sees every share
 * before dealing them out. That is the right tool when you are splitting a
 * secret you already hold, and it is *not* distributed key generation — nobody
 * ever holds the whole secret in DKG, and `dkg.run` is the dealerless verb in
 * this toolbox. A reader who sees "split key ceremony" will assume the stronger
 * property unless told, so `DEALER_BASED` is copy this module owns and the
 * picker prints.
 *
 * @module lib/toolkit/room-ceremony
 */

import { canonicalAudience } from "../notebook/room.js";
import { canonicalizeRecipe, parseRecipe, serializeRecipe } from "./recipe.js";

/**
 * The largest room this ceremony can be written for.
 *
 * `sss.split`'s `shares` param is `min: 1, max: 16` in the registry, and this
 * ceremony spends one share per member — so sixteen people is the ceiling, and
 * it is the registry's number rather than a second opinion about it. A larger
 * room is refused *here*, at the picker, naming the count: refusing at compile
 * time would mean a notebook was written first and then declined, which is the
 * shape of failure this whole generator exists to remove.
 */
export const MAX_ROOM = 16;

/** A room needs somebody to hand a share to, so two is the floor. */
export const MIN_ROOM = 2;

/**
 * The sentence that corrects the assumption a reader arrives with.
 *
 * Exported rather than inlined in the widget because it is a claim about what
 * the cryptography does, and a claim like that belongs beside the recipe that
 * makes it true rather than in a JSX tree somebody may copy.
 */
export const DEALER_BASED =
  "This is a dealer-based split: this machine draws the secret and sees every share before dealing them out. That is what you want when you are splitting a secret you already hold. It is not distributed key generation — in DKG no machine ever holds the whole secret, and `dkg.run` is that verb.";

/**
 * The master never reaches a slot, and the reason to keep it that way.
 *
 * `random 32` flows straight into `sss.split`; the only thing written down is a
 * SHA-256 of it, on a `tee` branch. So the secret is in no slot, in no output
 * tile, in no receipt, and in nothing the Slots tray can be asked to reveal.
 * The digest is what makes a recovery checkable without ever showing the
 * secret again — which is `ceremony.js`'s decision 1 and 2, applied here for
 * the same reasons.
 */
export const MASTER_NEVER_OUT =
  "The secret itself is never written to a slot — only a SHA-256 of it, so there is something to check a recovery against without putting the secret on screen a second time. It is in no output tile, no receipt and no Slots row, on any machine.";

/**
 * What the deal leaves on the dealer's machine, stated because the old shape
 * left the opposite.
 *
 * The generated notebook used to bind every share into a revealable `$set` on
 * the dealer, with nothing on any screen saying to delete it — a 2-of-3 that
 * was a 1-of-1 until somebody remembered. Under `scatter` the shares flow from
 * the split straight onto the wire: the hazard is not warned about, it is
 * unconstructable, and this sentence is the picker's record of that property.
 */
export const DEALER_KEEPS_ONE =
  "Dealing leaves this machine holding exactly one share — its own, in $share. The others go straight from the split onto the wire, each to its member, so there is no set of shares anywhere to reveal or to forget to delete.";

/**
 * Why this notebook contains no recovery, said where the deal is offered.
 *
 * The claim that makes it safe to say is the BLIP39 header: threshold, share
 * count and set id ride in every mnemonic, so a recovery can be written years
 * later, by whoever is recovering, from the shares themselves — the dealer,
 * this notebook, and this machine can all be gone. `room-recovery.js` is the
 * generator that does it.
 */
export const RECOVERY_IS_ITS_OWN_NOTEBOOK =
  "This notebook is the deal and nothing else. Getting the secret back is a separate agreement made at a different time by whichever holders are doing it — each share carries the threshold, the count and the set id in its own header, so the recovering quorum writes its own recovery notebook when the day comes, dealer present or not.";

/**
 * What two people get, said before they press rather than discovered later.
 *
 * A majority of two is two, so a two-member room is `2/2`: both shares are
 * needed and losing either one loses the secret. That is a legitimate thing to
 * want — it is exactly "neither of us alone" — but it has no redundancy at all,
 * and the word "quorum" invites people to assume there is some.
 */
export const NO_REDUNDANCY_AT_TWO =
  "A room of two gets 2-of-2: both shares are needed and neither person can lose theirs. That is the strongest possible split of two and it has no redundancy at all — add a third person if a lost share should be survivable.";

/**
 * Why `@me` / `@holderN` are a way of talking about this and never text.
 *
 * The obvious design is to write the notebook once with placeholders and swap
 * them for fingerprints when the audience is chosen. It cannot work, and the
 * reason is worth writing down so nobody tries it again: a peer is named in two
 * different grammatical positions here. `@peer` in the header is a header, and
 * `setCellPeer` rewrites those — but `quorum.recv from=` is a *step parameter*,
 * and there is no mutator anywhere that edits one. Worse, `from=@holder1` does
 * not parse at all: `@` is not a legal character in a param value, so a
 * notebook full of placeholders would not compile while it waited to be
 * resolved, and every cell would be drawing a compile error at the reader.
 *
 * So the audience comes first and the whole notebook is generated from it. The
 * placeholders below exist only in prose, where they are a way of describing the
 * shape.
 */
export const ROOM_CEREMONY_PLACEHOLDERS = Object.freeze(["@me", "@holderN"]);

/**
 * The quorum this room implies.
 *
 * @param {number} size  how many keys are in the room, including yours
 * @returns {{ shares: number, threshold: number }}
 */
export function ceremonyQuorum(size) {
  const shares = Math.max(0, Math.floor(Number(size) || 0));
  return { shares, threshold: Math.floor(shares / 2) + 1 };
}

/**
 * Why this room cannot have a ceremony written for it, in the picker's words.
 *
 * Every sentence names the number that is actually true and a move that can
 * actually be made from the panel it is printed on — the rule the refusals in
 * `session-flow.js` are held to. "Remove four people" is performable; "use a
 * bigger threshold" would not be, because nothing here can raise a registry
 * bound.
 *
 * @param {object} room
 * @param {string[]} room.audience  every key in the room, including yours
 * @param {string} room.self        the key you are joining as
 * @returns {string[]}
 */
export function roomCeremonyIssues({ audience = [], self = "" } = {}) {
  /** @type {string[]} */
  const issues = [];
  const room = canonicalAudience(audience);
  const me = String(self || "").toUpperCase();
  if (!me) {
    issues.push(
      "Choose the key you are joining as. The first cell of the ceremony draws the secret and runs on that key, so there is nobody to write it for yet."
    );
  } else if (!room.includes(me)) {
    // Reachable: the chooser and the room are two lists, and a key can be
    // picked above and removed below. Naming it is what tells the reader which
    // of the two to fix.
    issues.push(
      "The key you are joining as is not one of the keys in the room, so no cell could be placed on you. Add it above, or choose a key that is in the list."
    );
  }
  if (room.length < MIN_ROOM) {
    issues.push(
      `A ceremony deals a share to each person in the room, and this room has ${
        room.length === 1 ? "one key in it — yours" : "nobody in it"
      }. Add at least one more person.`
    );
  }
  if (room.length > MAX_ROOM) {
    issues.push(
      `One share per person means ${room.length} shares, and \`sss.split\` makes at most ${MAX_ROOM}. Remove ${
        room.length - MAX_ROOM
      } ${room.length - MAX_ROOM === 1 ? "person" : "people"} from the room, or split for ${MAX_ROOM} of them and let the rest hold nothing.`
    );
  }
  return issues;
}

/**
 * @typedef {object} CeremonyCell
 * @property {string} peer    whole fingerprint this cell is placed on
 * @property {string} recipe  the pipeline, with no header on it
 * @property {string} why     one line, for the preview — what this cell is for
 */

/**
 * @typedef {object} RoomCeremony
 * @property {CeremonyCell[]} cells
 * @property {string} text        the whole notebook, headers and all
 * @property {string} title
 * @property {number} shares
 * @property {number} threshold
 * @property {string} dealer      whole fingerprint of the machine that splits
 * @property {string[]} issues    empty when `cells` is worth anything
 */

/**
 * Write the deal for this room.
 *
 * Returns cells with their peer beside them rather than a block of text with
 * headers in it, because the caller writes those headers through
 * `nb.setCellPeer` — the same mutator the "Who runs this cell" menu presses. A
 * header is then produced by `serializeChain` exactly as a person choosing from
 * the menu would have it, and this module never spells one. `text` is for the
 * preview and comes from `serializeRecipe`, so it is the same function's answer
 * and cannot drift from what the notebook will hold.
 *
 * @param {object} room
 * @param {string[]} room.audience
 * @param {string} room.self
 * @returns {RoomCeremony}
 */
export function roomCeremony({ audience = [], self = "" } = {}) {
  const issues = roomCeremonyIssues({ audience, self });
  // The same derivation the engine's `scatter` reads off the live exchange —
  // one function, so the slot numbers written here and the pairing performed
  // there cannot be two opinions.
  const members = canonicalAudience(audience);
  const me = String(self || "").toUpperCase();
  const { shares, threshold } = ceremonyQuorum(members.length);
  if (issues.length) {
    return {
      cells: [],
      text: "",
      title: "",
      shares,
      threshold,
      dealer: me,
      issues,
    };
  }

  /** @type {CeremonyCell[]} */
  const cells = [];

  // The whole deal, in one cell. `scatter to=room` zips the split against the
  // canonical audience and its body runs once per (share, member) pair:
  // `send to=each` delivers each pair's share to that pair's member over the
  // room's own channel, and the one pair whose member is this machine never
  // touches a wire — a dealer deals to the whole table, themselves included.
  // `out $share` after the send binds that one retained share, and only it:
  // a delivered pair's pipe ends at the verb that delivered it, so exactly
  // one value reaches the `out`. There is deliberately no `$set` — the old
  // notebook's highest-ranked finding was the dealer keeping every share in a
  // revealable slot with nothing saying to delete it, and under this form
  // that state is unconstructable rather than warned about.
  //
  // The `tee` branch is what makes a recovery checkable. `random 32` never
  // reaches an `out`, so the master is in no slot on any machine — but a
  // plain Shamir recombination of a corrupted set returns a *different*
  // secret rather than an error, so without something to compare against, a
  // recovery that quietly produced the wrong bytes would look exactly like
  // one that worked. The digest is that something, and it discloses nothing:
  // it is a SHA-256 of thirty-two random bytes.
  cells.push({
    peer: me,
    why: `Draws the secret, splits it ${threshold}-of-${shares}, and deals share i to member i over the room — writing down a digest of the secret, never the secret, and keeping only this machine's own share in $share.`,
    recipe: [
      "random 32 | tee",
      "  - digest sha-256 | encode hex | out $expected",
      // The quorum as the verb's object — the canonical spelling, so the text
      // this generator writes is the text `serializeRecipe` would write back
      // and the preview cannot differ from the notebook by a respelling.
      `| sss.split ${threshold}/${shares} | blip39.encode | scatter to=room`,
      "  - send to=each | out $share",
    ].join("\n"),
  });

  // One receive per holder, numbered by the share the pairing will hand them:
  // the member at canonical position i is dealt share i, so the slot is
  // `$share-i` — a person comparing a slot against a printed card that says
  // "share 3 of 3" sees the same number in both places. Each holder writes
  // their own slot because the compiler reads the whole notebook: two cells
  // placed on two machines still live in one document, and `out $share`
  // twice would be `Duplicate out slot $share`. The dealer's own number never
  // appears — their share stays in the unnumbered `$share` the deal cell
  // binds, which is honest: it is the one share that was never received.
  members.forEach((m, i) => {
    if (m === me) return;
    cells.push({
      peer: m,
      why: `Receives share ${i + 1}, on the holder's own machine, into a slot named for it.`,
      recipe: `quorum.recv from=${me} | out $share-${i + 1}`,
    });
  });

  return {
    cells,
    text: ceremonyText(cells),
    title: roomCeremonyTitle({ threshold, shares }),
    shares,
    threshold,
    dealer: me,
    issues: [],
  };
}

/**
 * The notebook as text, for the preview and for anything comparing the two.
 *
 * Built by parsing each body and hanging the peer on the chain, then handing the
 * lot to `serializeRecipe` — so the headers here are written by the same
 * function `setCellPeer` writes them with, and the preview cannot say something
 * the notebook will not.
 *
 * @param {CeremonyCell[]} cells
 * @returns {string}
 */
function ceremonyText(cells) {
  const chains = cells.map((cell) => {
    const { ast } = parseRecipe(cell.recipe);
    const chain = ast?.chains?.[0] || { steps: ast?.steps || [] };
    return { ...chain, peer: cell.peer };
  });
  return serializeRecipe(chains);
}

/**
 * A title for the notebook, saying the quorum rather than a room name.
 *
 * The quorum is the fact a reader most needs off a tab, and a room has no name
 * — it is derived from fingerprints and never given one.
 *
 * @param {{ threshold: number, shares: number }} quorum
 */
export function roomCeremonyTitle({ threshold, shares }) {
  return `Room ceremony — ${threshold}-of-${shares}`;
}

/**
 * What the ceremony is about to do, as sentences for the panel.
 *
 * Assembled here rather than in the widget so the numbers in the prose and the
 * numbers in the recipe come from one place. Every sentence names a state that
 * is true of *this* room; nothing is a general remark about splitting secrets.
 *
 * @param {RoomCeremony} ceremony
 * @returns {string[]}
 */
export function roomCeremonySummary(ceremony) {
  if (!ceremony || ceremony.issues.length || !ceremony.cells.length) return [];
  const { shares, threshold } = ceremony;
  /** @type {string[]} */
  const lines = [
    `One share each for ${shares} people, and any ${threshold} of them rebuild the secret. Fewer than ${threshold} reveal nothing at all.`,
    // Said for every room, not only the ones where it is surprising: the reason
    // for a majority is the property it buys, and a reader who is told the
    // number without the reason will try to lower it.
    `${threshold} is a majority of ${shares}, so no two separate groups can ever rebuild it independently — any two groups of ${threshold} share at least one person.`,
    MASTER_NEVER_OUT,
    DEALER_KEEPS_ONE,
    RECOVERY_IS_ITS_OWN_NOTEBOOK,
    DEALER_BASED,
  ];
  if (shares === 2) lines.push(NO_REDUNDANCY_AT_TWO);
  return lines;
}

/**
 * Canonicalise generated text the way the notebook will hold it.
 *
 * Only used by tests and by anything comparing this module's output with a live
 * notebook's Source view. `loadRecipeText` compiles what it is given and the
 * editor re-serializes, so `blip39` is drawn back as `blip39.encode`; a
 * comparison against the text this module composed would be comparing two
 * spellings of one recipe.
 *
 * @param {string} text
 * @returns {string}
 */
export function canonicalCeremonyText(text) {
  return canonicalizeRecipe(text).text;
}
