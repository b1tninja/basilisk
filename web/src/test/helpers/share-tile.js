/**
 * What a masked share tile says about the share behind it.
 *
 * Extracted from `three-party-ceremony.e2e.js` when `dealer-absent-recovery`
 * grew its own three-share check, and extracted rather than copied for
 * `toolkit-ui.js`'s stated reason: this function carries a correction that a
 * second, obvious-looking reimplementation would not have, and getting it wrong
 * does not fail — it passes, fifteen seconds late, for a reason that has
 * nothing to do with set ids.
 *
 * @module test/helpers/share-tile
 */

import { expect } from "vitest";

/**
 * Read one machine's share identity off the tile in cell `i`.
 *
 * `[data-share-identity]` rather than the "Check a share…" panel, and the
 * distinction is worth keeping: that panel is where `custodian-recovery.e2e.js`
 * reads a set id, because its custodian arrives holding *words* and nothing else
 * — no session, no notebook, no slot — so the cold panel is the only surface
 * that can decode them. Here every share is already sitting in a tile on the
 * machine that was dealt it, and both spellings come out of `formatSetId` on the
 * same `readShareHeader` of the same mnemonic. Driving a modal sheet to re-read
 * a header already on screen would be a second route to one fact.
 *
 * **The tile is shut first, and that is not tidying.** `ShareIdentity` is the
 * kind's `publicView`: it is drawn *while the value is masked* and not at all
 * once the body is showing, so on a screen where an earlier step opened the
 * share the span does not exist. Playwright waits for it rather than failing —
 * and gets it fifteen seconds later, when the list-wide auto-hide timer re-masks
 * the row. That passes, which is the problem: the read would be timing out and
 * recovering, and the day the timer changed the assertion would go red for a
 * reason that has nothing to do with set ids.
 *
 * The whole label is returned beside the parsed fields on purpose: every
 * assertion built on this compares one machine's four hex digits against
 * another's, so a failure is only diagnosable if the message can print what each
 * screen actually said. A bare `""` against `"4A1C"` names neither the tile that
 * was missing nor the machine it was missing on.
 *
 * @param {import("playwright").Page} page
 * @param {number} i  the notebook cell whose tile holds the share
 * @returns {Promise<{ labels: string, setId: string, index: string }>}
 */
export async function shareSetId(page, i) {
  const cell = page.locator("article").nth(i);
  const hide = cell.getByRole("button", { name: "Hide", exact: true });
  for (let guard = 0; guard < 4 && (await hide.count()); guard += 1) {
    await hide.first().click();
  }
  const span = cell.locator("[data-share-identity]").first();
  await span.waitFor({ state: "visible", timeout: 20000 });
  const labels = (await span.innerText()).replace(/\s+/g, " ");
  return {
    labels,
    setId: /set ([0-9A-F]{4})/.exec(labels)?.[1] ?? "",
    index: /Share (\d+)/.exec(labels)?.[1] ?? "",
  };
}

/**
 * Assert that every share read here belongs to **one split**.
 *
 * The claim `4c27d01` added to the three-party suite, in one place now that two
 * files make it. What it proves, and what it is careful not to:
 *
 * "Every peer ends holding a share of the same key" is not what a 2-of-3
 * recovery establishes. A recovery combines *two* shares and reports that those
 * two agree; it is silent about the third. A dealer that split twice and kept a
 * card from the second split would deal a room that recovers perfectly and would
 * be holding a card that recovers nothing with anybody, and every digest
 * assertion in both ceremony suites would still be green.
 *
 * What makes it checkable is the BLIP39 header: `encodeShareSet` draws a fresh
 * set id per split and writes it into every mnemonic before a word of data, and
 * `decodeShareSet` refuses to recombine two headers that disagree. Two splits of
 * the *same secret* get different ids — it is assigned per split, not derived
 * from the secret — so this checks that two deals were one deal, not merely that
 * two secrets matched.
 *
 * Three guards around the one that matters, each closing a way this could pass
 * while proving nothing:
 *
 * - **One read per browser in the room**, counted against the fixture rather
 *   than written as `3`: "all N" is the whole claim, so a fourth member has to
 *   fail here until somebody reads their share too.
 * - **Every id is shaped like an id**, because without it the equality below is
 *   three empty strings agreeing with each other.
 * - **The indices are distinct**, which is what stops one share being read three
 *   times and the room being called consistent.
 *
 * And the ids are compared **to each other, never to a literal**: a hard-coded
 * `4A1C` would pin one run's randomness, and it would also die under the control
 * mutation that rotates *every* share's id — where the split stays coherent and
 * only its name moves, which is not a defect.
 *
 * @param {{ who: string, labels: string, setId: string, index: string }[]} read
 * @param {number} expectedCount  how many browsers are actually in the room
 */
export function expectOneSplit(read, expectedCount) {
  const said = JSON.stringify(read);
  expect(read.length, `the shares read: ${said}`).toBe(expectedCount);
  for (const r of read) {
    expect(r.setId, `${r.who}'s share tile said: ${r.labels} — all: ${said}`).toMatch(
      /^[0-9A-F]{4}$/
    );
  }
  expect(new Set(read.map((r) => r.index)).size, `the shares read: ${said}`).toBe(read.length);
  expect(new Set(read.map((r) => r.setId)).size, `the shares read: ${said}`).toBe(1);
}
