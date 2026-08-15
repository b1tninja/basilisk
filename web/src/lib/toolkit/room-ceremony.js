/**
 * The split-key ceremony for a room, generated from the room.
 *
 * `ceremony.js` beside this file is the *solo* ceremony: one machine splits, one
 * machine verifies, one machine prints cards, and `@peer` appears in it zero
 * times. This is the other one — the secret is dealt to the people who are in
 * the room, over the room, and it is put back together on a machine that never
 * held it.
 *
 * ## Why this is a generator and not a preset
 *
 * Because the cell count depends on who is in the room, and nothing in the
 * language can vary a recipient per iteration. `foreach` declares `params: []`,
 * so there is no `to=` for it to change between rounds; `tee`'s `-` lines
 * concatenate a stem rather than branching to different addressees. So one send
 * cell per holder and one receive cell per holder is not a stylistic choice, it
 * is the only shape that exists — and a template that is a fixed string cannot
 * have a variable number of cells in it.
 *
 * That is also what dissolves the chicken-and-egg the product owner reported.
 * A `@peer` header addresses a whole fingerprint, and `to=`/`from=` carry whole
 * fingerprints too, so the notebook cannot be written until the room is known.
 * The order is therefore: **choose the audience, and the notebook falls out of
 * it.** Nothing here is authored against a placeholder that is resolved later —
 * see `ROOM_CEREMONY_PLACEHOLDERS` for why a placeholder could not have worked.
 *
 * ## What the room decides
 *
 * - **`shares` is the room size.** One share per member, so a count that
 *   disagrees with the number of people is unreachable by construction rather
 *   than refused after the fact.
 * - **`threshold` is a majority**, `floor(shares / 2) + 1`. Majority rather than
 *   any smaller fraction because any two qualifying sets then intersect: with
 *   `2/4`, two disjoint pairs could each rebuild the secret without the other
 *   knowing it had happened, and no record anywhere would show two recoveries.
 *   A majority makes that arithmetically impossible.
 * - **Who recombines is the first holder**, not the dealer. The dealer already
 *   saw the secret, so a dealer who recovers it demonstrates nothing; a holder
 *   recovering it from shares that crossed the room demonstrates that the
 *   secret outlives the machine that made it.
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
 * How long the recovery gather waits, in milliseconds.
 *
 * Exported so the picker's prose and the recipe's `wait=` are one number, and
 * so a test can pin it without reading it out of a generated string. Thirty
 * minutes: see the gather cell below for the argument.
 */
export const RECOVERY_WAIT_MS = 1_800_000;

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
 * The digest is what makes the recovery checkable without ever showing it again
 * — which is `ceremony.js`'s decision 1 and 2, applied here for the same
 * reasons.
 */
export const MASTER_NEVER_OUT =
  "The secret itself is never written to a slot — only a SHA-256 of it, so there is something to check the recovery against without putting the secret on screen a second time. It is in no output tile, no receipt and no Slots row, on any machine.";

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
 * `setCellPeer` rewrites those — but `quorum.send to=` and `quorum.recv from=`
 * are *step parameters*, and there is no mutator anywhere that edits one. Worse,
 * `to=@holder1` does not parse at all: `@` is not a legal character in a param
 * value, so a notebook full of placeholders would not compile while it waited to
 * be resolved, and every cell would be drawing a compile error at the reader.
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
  const room = canonicalMembers(audience);
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
 * The audience as the room reads it: upper case, de-duplicated, order kept.
 *
 * Order is kept rather than sorted because it is the order the reader built the
 * list in, and share 2 goes to whoever is second on the panel they are looking
 * at. `deriveRoomMaterial` sorts for its own purposes; nothing here depends on
 * that and this is deliberately not a second opinion about it.
 *
 * @param {string[]} audience
 * @returns {string[]}
 */
function canonicalMembers(audience) {
  /** @type {string[]} */
  const out = [];
  for (const raw of audience || []) {
    const hex = String(raw || "").toUpperCase().replace(/\s+/g, "");
    if (hex && !out.includes(hex)) out.push(hex);
  }
  return out;
}

/**
 * @typedef {object} CeremonyCell
 * @property {string} peer    whole fingerprint this cell is placed on
 * @property {string} recipe  the pipeline, with no header on it
 * @property {"deal"|"recover"} phase
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
 * @property {string} recoverer   whole fingerprint of the machine that recombines
 * @property {string[]} issues    empty when `cells` is worth anything
 */

/**
 * Write the ceremony for this room.
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
  const members = canonicalMembers(audience);
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
      recoverer: "",
      issues,
    };
  }

  // You are the dealer, and the rest of the room are holders in the order the
  // reader put them in. `holders[0]` is the one who will recombine.
  const holders = members.filter((m) => m !== me);
  const recoverer = holders[0];
  // Which share the recoverer is holding, by the same arithmetic that deals
  // them: the dealer keeps share 1, so the holder at position `i` gets `i + 2`.
  // Derived rather than written as `2` so that a change to which holder
  // recombines moves the gather's `with=` with it.
  const recovererShare = holders.indexOf(recoverer) + 2;

  /** @type {CeremonyCell[]} */
  const cells = [];

  /* ── dealing ────────────────────────────────────────────────────────────── */

  // The `tee` branch is the whole reason the ceremony can be checked. `random
  // 32` never reaches an `out`, so the master is in no slot on any machine —
  // but a plain Shamir recombination of a corrupted set returns a *different*
  // secret rather than an error, so without something to compare against, a
  // recovery that quietly produced the wrong bytes would look exactly like a
  // recovery that worked. The digest is that something, and it discloses
  // nothing: it is a SHA-256 of thirty-two random bytes.
  cells.push({
    peer: me,
    phase: "deal",
    why: "Draws the secret, splits it, and writes down a digest of it — never the secret.",
    recipe: [
      "random 32 | tee",
      "  - digest | encode hex | out $expected",
      `| sss.split threshold=${threshold} shares=${shares} | blip39 | out $set`,
    ].join("\n"),
  });

  // **There is no `$set | at 1 | out $mine` cell, and the reason is a trap.**
  // The obvious way to say "share 1 is mine" is to pull it out into a slot of
  // its own — and it does not work: `slot-registry.register` diverts any value
  // carrying `meta.shareIndex` into `slotsByIndex` and returns *before*
  // `slotsByLabel.set`, so a selected share never becomes a named slot. The cell
  // runs, reports `ok`, writes a tile, and the next cell to read `$mine` fails
  // with `in $mine: unknown slot (register earlier with out $mine)` — an error
  // naming a remedy that had already been performed. `dc5d7cb` records the same
  // divert from the other direction. So share 1 stays inside `$set`, where the
  // dealer already has every share anyway, and the cell that hands it back
  // selects it again at that moment.

  // One send per holder, addressed by whole fingerprint. Never `publish`: a
  // value leaves this machine because a verb said so, and a header that also
  // disclosed it would be a second road out of the same cell.
  holders.forEach((h, i) => {
    cells.push({
      peer: me,
      phase: "deal",
      why: `Hands share ${i + 2} to one holder, over the room's own channel.`,
      recipe: `$set | at ${i + 2} | quorum.send to=${h}`,
    });
  });

  // One receive per holder. Each writes its own slot: `out $share` twice would
  // be `Duplicate out slot $share`, because the compiler reads the whole
  // notebook rather than the part that runs here — the two holders' cells are
  // in one document even though they never run on one machine.
  //
  // **The slot is numbered by the share, not by the holder.** It used to be
  // `$share-${i + 1}`, one below the `at ${i + 2}` that selected the share
  // being sent — so the machine dealt share 3 kept it in `$share-2`, and a
  // person comparing a slot against a printed card that says "share 3 of 3"
  // had no way to tell whether they had been dealt the wrong one. There is
  // deliberately no `$share-1` anywhere in the notebook, and that is now
  // honest rather than an off-by-one: share 1 is the dealer's and stays inside
  // `$set`, for the `slotsByIndex` reason written above.
  holders.forEach((h, i) => {
    cells.push({
      peer: h,
      phase: "deal",
      why: `Receives share ${i + 2}, on the holder's own machine, into a slot named for it.`,
      recipe: `quorum.recv from=${me} | out $share-${i + 2}`,
    });
  });

  /* ── recovering ─────────────────────────────────────────────────────────── */

  // Everybody except the recoverer offers their share back. Running these is
  // what "a majority agreed" looks like as a sequence of presses: whoever does
  // not run theirs simply does not count toward the threshold, and the gather
  // below takes the first `threshold - 1` that arrive.
  cells.push({
    peer: me,
    phase: "recover",
    why: "Returns your own share — share 1, selected out of the set again.",
    recipe: `$set | at 1 | quorum.send to=${recoverer}`,
  });
  holders.slice(1).forEach((h, i) => {
    cells.push({
      peer: h,
      phase: "recover",
      why: `Returns share ${i + 3} when a recovery is called for.`,
      recipe: `$share-${i + 3} | quorum.send to=${recoverer}`,
    });
  });

  // The gather, on a machine that never held the secret. `count=` is one short
  // of the threshold because the recoverer's own share makes up the difference,
  // and `from=` is deliberately absent: any majority may rebuild it, so the cell
  // must not name which holders those are. `shares` is the collector `dc5d7cb`
  // added for exactly this — it reads the pipe and the slot `with=` names, so a
  // holder recombines what reached them without being sent to a paste tray for
  // values they are already holding.
  //
  // **`wait=` is written out, and it is written long.** `quorum.recv`'s
  // registry default is 120000 ms, which is the right default for a step
  // somebody is watching — and this is the one cell in the notebook that is
  // pressed at a different time from every other. The picker says so itself:
  // "Recovering — run when the secret is wanted back". Two minutes is a
  // network timeout; what happens here is that a person telephones another
  // custodian, who walks to a machine, opens a notebook and finds a cell. The
  // failure that follows a 120 s wait tells the reader to "give it a longer
  // `wait=`" — an edit to a generated recipe, in a notebook whose other
  // copies then no longer match it, made by the one person who cannot fix the
  // problem from their own screen. Half an hour is the length of the act.
  cells.push({
    peer: recoverer,
    phase: "recover",
    why: `Recombines ${threshold} shares back into the secret, and digests it so it can be checked against the dealer's. Waits up to ${RECOVERY_WAIT_MS / 60000} minutes for the ${threshold - 1 === 1 ? "other custodian" : "other custodians"} to run their cell.`,
    recipe: [
      `quorum.recv count=${threshold - 1} wait=${RECOVERY_WAIT_MS} | shares with=$share-${recovererShare} | blip39 -d | sss.combine | tee`,
      "  - digest | encode hex | out $recovered",
      "| encode hex | out $secret",
    ].join("\n"),
  });

  return {
    cells,
    text: ceremonyText(cells),
    title: roomCeremonyTitle({ threshold, shares }),
    shares,
    threshold,
    dealer: me,
    recoverer,
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
 * editor re-serializes, so `at 1` is drawn back as `[1]` and `blip39` as
 * `blip39.encode`; a comparison against the text this module composed would be
 * comparing two spellings of one recipe.
 *
 * @param {string} text
 * @returns {string}
 */
export function canonicalCeremonyText(text) {
  return canonicalizeRecipe(text).text;
}
