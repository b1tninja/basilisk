import { ShareCards } from "basilisk-portal";

/*
 * The printable output of a split: one card per share, each carrying the share
 * itself, the quorum sentence, and a QR for getting it back without typing.
 *
 * These are made to be printed and physically separated — that is the point of
 * splitting a secret — so every card has to stand alone. A card reading only
 * "Share 2" is useless a year later in a drawer, which is why each restates
 * the threshold and the split id.
 *
 * **The whole split is passed, always.** The component derives the total from
 * the artifacts it is given, so handing it a subset makes every card misstate
 * itself: three cards out of a 3-of-5 split print "Share 1 of 3", and a single
 * card printed alone came out as "Share 2 of 1 — any 3 of these 1 reconstruct
 * the secret". There is no prop for the real total, and there should not be a
 * preview implying otherwise.
 *
 * The mnemonics and commitments below are one real ceremony —
 * `random 32 | vss.split threshold=3 shares=5 | blip39` — kept together so the
 * split id on the verifiable cards is genuinely the id of these shares.
 *
 * `traits.shareOf` is the share *number*, not the total: the name reads like
 * "of N" and means the opposite, and the engine sets it from `shareIndex`.
 * Putting a total there silently renumbers every card.
 *
 * "Quorum" here is the Shamir threshold — any k of n — not the transport of
 * the same name.
 */

const frame = { maxWidth: 620 };

const MNEMONICS = [
  "away spend calcium papa aluminum duckling guilt rebuild repeat domestic says dining merit amazing herd guest skin primary crazy soldier sweater lips system phantom rescue stadium brave aspect mobile result isolate election depict leaves",
  "away spend cubic papa aluminum sugar painting sprinkle dress blind husky privacy funding repeat activity skunk fawn prize muscle duration roster medal twice fraction require orange miracle papa purple river guest snapshot laser seafood",
  "away spend drift papa aluminum chew legs shame species dress identify campus similar penalty thunder equip alarm curly cluster superior improve prune prize shrimp imply require image born geology criminal wisdom building robin ting",
  "away spend example papa aluminum blue artist mental yoga process scout percent staff scroll boundary tactics tenant cradle sack lunch erode diploma threaten salon fortune perfect aquatic smell space escape response husky liberty acid",
  "away spend friar papa aluminum racism elephant crisis royal holiday holy emission legal ceiling nuclear marathon together payroll guest else enforce climate material elite injury forget gesture should aircraft capital pink oral alcohol froth",
];

const COMMITMENTS = [
  "030c620fc8e3244bf80ba7ef60827b66f4c6ad9e488dbd575311b4cbd49e13bbdf",
  "03aa4c8a9b09e7b34b3cdb8624289a89eb93ce55f054ad94cfc5e778dc0b71154e",
  "026d31135a32327f15f27aec89386ba03e0664dfbcfdaba0b8ef5a208439f42016",
];

const share = (i: number) => ({
  label: `share (share ${i})`,
  filename: `share-${i}.txt`,
  content: MNEMONICS[i - 1],
  role: "share",
  sensitive: true,
  shareIndex: i,
  mime: "text/plain; charset=utf-8",
  tags: ["mnemonic", "blip39"],
  traits: { shareOf: i, threshold: 3 },
});

const ALL_FIVE = [1, 2, 3, 4, 5].map(share);

/**
 * The full 3-of-5 split. Each card reads "Share n of 5 — any 3 of these 5
 * reconstruct the secret", which is the sentence its holder needs and the one
 * that only comes out right when the whole split is present.
 *
 * The bodies are masked behind Reveal for printing, and the banner says why:
 * printing sends five secrets to a print server. That warning belongs on the
 * screen where the decision is made, not in documentation.
 */
export const Default = () => (
  <div style={frame}>
    <ShareCards artifacts={ALL_FIVE} label="board-root" threshold={3} />
  </div>
);

/**
 * With commitments, which is what makes a card *checkable*.
 *
 * Each card gains the split id (Split 0C62-0FC8-E324) and the instruction to
 * check against the published commitments, and the amber "Unverifiable split"
 * warning disappears. Without them a card still works and simply cannot be
 * verified — so the split line is printed either way, and its absence is
 * itself the information.
 */
export const Verifiable = () => (
  <div style={frame}>
    <ShareCards
      artifacts={ALL_FIVE}
      label="board-root"
      threshold={3}
      commitments={COMMITMENTS}
    />
  </div>
);

/**
 * The threshold the recipe never recorded.
 *
 * `traits.threshold` is absent, so each card says "the recipe did not record
 * how many are required" and the recovery line degrades to "any K cards"
 * rather than naming a number. A printed card asserting the wrong quorum is
 * worse than one admitting it does not know — the first sends someone to find
 * two people when they needed three.
 */
export const ThresholdUnknown = () => (
  <div style={frame}>
    <ShareCards
      artifacts={ALL_FIVE.map((a) => ({ ...a, traits: { shareOf: a.shareIndex } }))}
      label="board-root"
    />
  </div>
);
