/**
 * The recovery for a dealt split, generated at recovery time.
 *
 * `room-ceremony.js` writes the deal and nothing else — a deal and its
 * reversal are two agreements, made at different times by different sets of
 * people, so they are two notebooks. This module writes the second one, when
 * the day comes, for whoever is actually doing the recovering.
 *
 * ## What it asks, and what it reads
 *
 * It asks one thing: **who is contributing.** Everything else is read off the
 * shares themselves — a BLIP39 mnemonic carries its share index, the
 * threshold, the share count and the set id in its header, before a word of
 * data, which is how the "Check a share…" panel answers `share 2 of 3 · any 2
 * recombine · set 465E` from one mnemonic, offline. So the recovering machine
 * needs no dealer, no original notebook and no memory of the deal beyond the
 * share slots the deal bound; the quorum writes its own agreement listing
 * exactly the contributors it has, and dealer-absent recovery is the default
 * shape rather than an achievement.
 *
 * ## Why the generated gather waits half an hour
 *
 * `quorum.recv`'s registry default is 120000 ms, which is the right default
 * for a step somebody is watching — and a recovery is the one cell pressed at
 * a different time from everything else. What happens between the press and
 * the message arriving is a telephone call and a walk to another machine, so
 * the wait is the length of the act, and it is written into the text where
 * both ends can read it rather than discovered as a timeout.
 *
 * ## Who holds what, and how this module knows
 *
 * The deal notebook is the record of the deal: every holder's receive cell
 * names their key in its header and their share's slot in its `out`, and the
 * dealer's scatter cell binds their own share to `$share`. `dealHoldings`
 * reads that record off the chains the caller is holding. A contributor's
 * send cell then names a slot this *recovery* document never writes — which
 * is correct, the deal wrote it, on that contributor's machine — and the
 * compiler defers a placed cell's unknown slot to the run for exactly this
 * shape (see `validateRecipe`).
 *
 * @module lib/toolkit/room-recovery
 */

import { parseRecipe, serializeRecipe } from "./recipe.js";

/**
 * What a share says about itself — `readShareHeader`'s answer, taken as an
 * argument rather than read here. The share's words stay in the kernel's slot
 * registry: this module writes recipe text, and a mnemonic passed through it
 * would be key material one `why` string away from a preview. The caller
 * (`useNotebook.shareFacts`) resolves the slot and hands over only the four
 * facts the header carries.
 * @typedef {object} ShareHeaderFacts
 * @property {number} index
 * @property {number} total
 * @property {number} threshold
 * @property {string} setId
 */

/**
 * How long the recovery gather waits, in milliseconds.
 *
 * Exported so the picker's prose and the recipe's `wait=` are one number, and
 * so a test can pin it without reading it out of a generated string. Thirty
 * minutes: the argument is in the module note above, and it lives here now
 * because the gather does — the deal notebook no longer arms one.
 */
export const RECOVERY_WAIT_MS = 1_800_000;

/**
 * The one-cell notebook for a custodian holding words on paper.
 *
 * No headers, no peers, no session: a cold custodian has none of those, and
 * the `shares` collector reads the Inputs tray when the recipe names nothing
 * else — which is the only road in for somebody holding cards. The `tee`
 * digest branch is not decoration: a plain Shamir recombination of a corrupted
 * or mismatched set returns a *different* secret rather than an error, so the
 * digest is the only way to know the recovery produced the right bytes rather
 * than merely some bytes.
 */
export const CUSTODIAN_RECOVERY = [
  "shares | blip39 -d | sss.combine | tee",
  "  - digest sha-256 | encode hex | out $recovered",
  "| encode hex | out $secret",
].join("\n");

/**
 * A share slot the deal notebook places on a peer.
 * @typedef {object} ShareHolding
 * @property {string} fingerprint  whole fingerprint, upper case
 * @property {string} slot         slot label without the sigil — `share`,
 *   `share-2`, …
 */

/**
 * Read who holds which share slot off a deal notebook's chains.
 *
 * The deal's text is the agreement, so it is also the record: a holder's
 * receive cell is `@<fpr>` over `quorum.recv … | out $share-N`, and the
 * dealer's cell binds `$share` inside the scatter body. Walked structurally —
 * bodies and branches included — rather than by regex over the source, so a
 * respelling of any verb costs nothing here.
 *
 * @param {Array<{ peer?: string, steps?: any[] }>} chains
 * @returns {ShareHolding[]}  one entry per peer that holds a share slot, in
 *   chain order; a peer with several share-shaped outs keeps the first
 */
export function dealHoldings(chains) {
  /** @type {ShareHolding[]} */
  const holdings = [];
  const seen = new Set();
  for (const chain of chains || []) {
    const peer = String(chain?.peer || "").toUpperCase();
    if (!peer || seen.has(peer)) continue;
    const slot = findShareOut(chain.steps || []);
    if (slot) {
      holdings.push({ fingerprint: peer, slot });
      seen.add(peer);
    }
  }
  return holdings;
}

/**
 * The first `out` in these steps (bodies included) that names a share slot.
 * @param {any[]} steps
 * @returns {string}
 */
function findShareOut(steps) {
  for (const step of steps || []) {
    if (step?.name === "out") {
      const name = String(step.params?.name || "").replace(/^\$/, "");
      if (/^share(-\d+)?$/.test(name)) return name;
    }
    const inBody = findShareOut(step?.body);
    if (inBody) return inBody;
    for (const br of step?.branches || []) {
      const inBranch = findShareOut(br?.body);
      if (inBranch) return inBranch;
    }
  }
  return "";
}

/**
 * @typedef {object} RecoveryCell
 * @property {string} peer    whole fingerprint, or "" for the custodian cell
 * @property {string} recipe  the pipeline, with no header on it
 * @property {string} why     one line, for the preview
 */

/**
 * @typedef {object} RoomRecovery
 * @property {RecoveryCell[]} cells
 * @property {string} text
 * @property {string} title
 * @property {number} threshold  read off the recoverer's own share header
 * @property {number} total      likewise
 * @property {string} setId      likewise — the four hex digits the check panel prints
 * @property {string} recoverer  whole fingerprint of the machine that recombines
 * @property {string[]} contributors  whole fingerprints, as agreed
 * @property {string[]} issues   empty when `cells` is worth anything
 */

/**
 * Why this recovery cannot be written yet, in the picker's words.
 *
 * Same rule as `roomCeremonyIssues`: every sentence names the state that is
 * actually true and a move performable from the panel it is printed on.
 *
 * @param {object} args
 * @param {string} args.self         the recovering machine's key
 * @param {ShareHeaderFacts|null} args.header  what this machine's own share
 *   says about itself, or null when its slot holds nothing readable
 * @param {ShareHolding[]} args.holdings
 * @param {string[]} args.contributors
 * @returns {string[]}
 */
export function roomRecoveryIssues({
  self = "",
  header = null,
  holdings = [],
  contributors = [],
} = {}) {
  /** @type {string[]} */
  const issues = [];
  const me = String(self || "").toUpperCase();
  const mine = holdings.find((h) => h.fingerprint === me);
  if (!me) {
    issues.push(
      "Choose the key you are recovering as — the gather runs on that key, and the contributors' shares are sent to it."
    );
  } else if (!mine) {
    issues.push(
      "The deal this notebook records places no share on this key, so a recovery here would hold nothing to start from. Recover on a machine the deal dealt to — or, holding a card, use the paste recovery instead: it reads mnemonics typed in by hand and needs no session."
    );
  }
  if (mine && !header) {
    issues.push(
      `The value in $${mine.slot} does not read as a BLIP39 share mnemonic, so the threshold and share count cannot be read off it. Has the deal been run on this machine?`
    );
  }
  const contrib = [...new Set(contributors.map((c) => String(c || "").toUpperCase()))];
  if (contrib.includes(me)) {
    issues.push(
      "You are the one recovering — your own share is already counted, so you are not also a contributor. Uncheck yourself."
    );
  }
  for (const c of contrib) {
    if (c === me) continue;
    if (!holdings.some((h) => h.fingerprint === c)) {
      issues.push(
        `${c} holds no share this deal records, so a send cell placed on them would have nothing to send. Choose contributors from the people the deal dealt to.`
      );
    }
  }
  if (header) {
    const others = contrib.filter((c) => c !== me).length;
    const need = header.threshold - 1;
    if (others < need) {
      issues.push(
        `This split is ${header.threshold}-of-${header.total}: you hold one share, and ${
          others === 0 ? "no contributor is" : `${others} contributor${others === 1 ? " is" : "s are"}`
        } listed — ${others + 1} of the ${header.threshold} needed. Name ${need - others} more ${
          need - others === 1 ? "contributor" : "contributors"
        }, or paste that many cards instead.`
      );
    }
  }
  return issues;
}

/**
 * Write the recovery the listed contributors have agreed to.
 *
 * The shape is the deal generator's, deliberately: cells with peers beside
 * them for `setCellPeer`, `text` from `serializeRecipe` for the preview, and
 * refusals computed by the same function the picker prints.
 *
 * Every contributor listed is gathered — `count=` is their number, not
 * `threshold - 1`. The old single-notebook gather took `threshold - 1` of
 * whatever arrived first, so with a spare custodian pressing, somebody's press
 * did nothing that anything reported (the three-party e2e's finding 6a). Here
 * the text lists exactly who contributes and the gather takes exactly those,
 * so every press in the agreement is a press the recovery consumed — and the
 * run's receipt names whose shares arrived, whichever machines they were.
 *
 * @param {object} args
 * @param {string} args.self
 * @param {ShareHeaderFacts|null} args.header  the recoverer's own share's facts
 * @param {ShareHolding[]} args.holdings
 * @param {string[]} args.contributors
 * @returns {RoomRecovery}
 */
export function roomRecovery({
  self = "",
  header = null,
  holdings = [],
  contributors = [],
} = {}) {
  const issues = roomRecoveryIssues({ self, header, holdings, contributors });
  const me = String(self || "").toUpperCase();
  const threshold = header?.threshold || 0;
  const total = header?.total || 0;
  const setId = header?.setId || "";
  const contrib = [...new Set(contributors.map((c) => String(c || "").toUpperCase()))]
    .filter((c) => c !== me)
    // Sorted for determinism — the picker's checkboxes have no order worth
    // keeping, and two machines generating from the same agreement must
    // produce one text.
    .sort();
  if (issues.length) {
    return {
      cells: [],
      text: "",
      title: "",
      threshold,
      total,
      setId,
      recoverer: me,
      contributors: contrib,
      issues,
    };
  }

  const mine = /** @type {ShareHolding} */ (
    holdings.find((h) => h.fingerprint === me)
  );

  /** @type {RecoveryCell[]} */
  const cells = [];

  // One send per contributor, reading the slot the *deal* bound on their
  // machine. This document never writes those slots and does not need to —
  // the compiler defers a placed cell's unknown slot to the run, and the slot
  // registry on the contributor's machine survives the notebook being
  // replaced (values are the machine's, not the notebook's). Running this
  // cell is what agreeing to the recovery looks like as a press.
  for (const c of contrib) {
    const holding = /** @type {ShareHolding} */ (
      holdings.find((h) => h.fingerprint === c)
    );
    cells.push({
      peer: c,
      why: `Sends the share this machine holds ($${holding.slot}) back for the recovery — running it is what agreeing looks like.`,
      recipe: `$${holding.slot} | quorum.send to=${me}`,
    });
  }

  // The gather, on the machine that recombines. `shares` collects the pipe
  // and the slot `with=` names, so the recoverer's own share joins the
  // received ones without a paste tray. `from=` is written when one
  // contributor is listed — the filter takes one fingerprint, so with several
  // senders the count is the agreement's own number and the run's receipt is
  // what names whose shares arrived (it names them in the one-contributor
  // case too; the filter is simply also enforceable there).
  const recv =
    contrib.length === 1
      ? `quorum.recv from=${contrib[0]} wait=${RECOVERY_WAIT_MS}`
      : `quorum.recv count=${contrib.length} wait=${RECOVERY_WAIT_MS}`;
  cells.push({
    peer: me,
    why: `Waits up to ${RECOVERY_WAIT_MS / 60000} minutes for the ${
      contrib.length === 1 ? "contributor" : `${contrib.length} contributors`
    } to run their cell, then recombines their share${
      contrib.length === 1 ? "" : "s"
    } with $${mine.slot} — and digests the result so it can be checked against the deal's $expected.`,
    recipe: [
      `${recv} | shares with=$${mine.slot} | blip39 -d | sss.combine | tee`,
      "  - digest sha-256 | encode hex | out $recovered",
      "| encode hex | out $secret",
    ].join("\n"),
  });

  return {
    cells,
    text: recoveryText(cells),
    title: roomRecoveryTitle({ threshold, total }),
    threshold,
    total,
    setId,
    recoverer: me,
    contributors: contrib,
    issues: [],
  };
}

/**
 * The paste-path recovery, for a custodian with cards and no session.
 *
 * The same result type as `roomRecovery` so one panel can offer either — the
 * one cell is unheaded, because the machine it runs on is whichever machine
 * the cards are carried to, and a header would place it on a key a cold
 * browser does not hold.
 *
 * @returns {RoomRecovery}
 */
export function custodianRecovery() {
  /** @type {RecoveryCell[]} */
  const cells = [
    {
      peer: "",
      why: "Reads mnemonics pasted into the share rows, recombines them, and digests the result for checking against the deal's $expected.",
      recipe: CUSTODIAN_RECOVERY,
    },
  ];
  return {
    cells,
    text: recoveryText(cells),
    title: "Recover from cards",
    threshold: 0,
    total: 0,
    setId: "",
    recoverer: "",
    contributors: [],
    issues: [],
  };
}

/**
 * The notebook as text — `serializeRecipe`'s answer, exactly as
 * `room-ceremony.js` produces its preview, and for the same reason: the
 * preview must not be able to say something the notebook will not.
 *
 * @param {RecoveryCell[]} cells
 * @returns {string}
 */
function recoveryText(cells) {
  const chains = cells.map((cell) => {
    const { ast } = parseRecipe(cell.recipe);
    const chain = ast?.chains?.[0] || { steps: ast?.steps || [] };
    return cell.peer ? { ...chain, peer: cell.peer } : { ...chain };
  });
  return serializeRecipe(chains);
}

/**
 * A title saying the quorum, like the deal's — the two notebooks of one split
 * should read as a pair on a tab bar.
 *
 * @param {{ threshold: number, total: number }} quorum
 */
export function roomRecoveryTitle({ threshold, total }) {
  return `Recovery — ${threshold}-of-${total}`;
}
