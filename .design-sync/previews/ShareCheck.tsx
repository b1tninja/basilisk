import { ShareCheck } from "basilisk-portal";

/*
 * The counterpart to a printed card: paste or scan a share and find out
 * whether it is genuine — *before* a recovery, not during one.
 *
 * **Every fixture below is real.** The mnemonics and commitments are the
 * actual output of `random 32 | vss.split threshold=3 shares=5 | blip39`, run
 * through this repo's own engine. Invented ones do not survive contact with
 * the panel: a mnemonic is a checksummed encoding over a fixed wordlist, and
 * plausible-looking words render "Unknown SLIP-39 word" — so a cell captioned
 * as a successful check would have shown a parse failure, stating the opposite
 * of what it claimed. That is the whole failure mode this panel exists to
 * prevent, and it is available to a preview too.
 *
 * The verdicts are deliberately graded. With commitments the panel verifies a
 * share against the split; without them it can confirm the encoding and
 * nothing more, and it says which of the two it did rather than letting
 * "well-formed" read as reassurance.
 */

const frame = { maxWidth: 560 };

const SHARE_1 =
  "away spend being vegan aluminum lend premium move spirit jury warn emphasis ancient crowd ounce blue belong starting grant enemy bedroom costume percent shrimp treat dining mailman ajar parking include evil forward ruin daughter";

const SHARE_2 =
  "away spend chemical vegan aluminum civil cinema frozen sniff thorn false fitness deal cargo blanket surface forward eraser flexible guilt squeeze knife average jacket quiet magazine laden yoga result involve type worthy knife order";

/** Exactly what `vss.commitments` writes — the JSON the panel is built to read. */
const COMMITMENTS =
  '{"v":1,"commitments":["039f26bbd060841e88d4995e4e376491319474d5e51101bd108334ede83086f706","035e014b986f7939e95c2e860b7acd2d126339f18c95f52f2917dfb3f6a4adc630","03ec30bb3172397acb12b04137d4501c93267394d45687024fe498f4cfa5ecf1d0"],"publicKey":"039f26bbd060841e88d4995e4e376491319474d5e51101bd108334ede83086f706"}';

/**
 * Empty, waiting for a share — the state a person meets, since the panel is
 * opened *in order to* paste something.
 */
export const Default = () => (
  <div style={frame}>
    <ShareCheck scanSupported={false} />
  </div>
);

/**
 * The full check: a genuine share against the commitments from its own split.
 * This is the only configuration in which the panel can say a share is real
 * rather than merely readable, and it is what a custodian should be doing
 * annually rather than on the day of a recovery.
 */
export const Verified = () => (
  <div style={frame}>
    <ShareCheck
      initialShare={SHARE_1}
      initialCommitments={COMMITMENTS}
      scanSupported={false}
    />
  </div>
);

/**
 * A second, different share from the same split, checked against the same
 * commitments. Included because a set of commitments verifies *every* share in
 * the split rather than one — and a custodian holding card 2 must not have to
 * find card 1 to check theirs.
 */
export const AnotherShareSameSplit = () => (
  <div style={frame}>
    <ShareCheck
      initialShare={SHARE_2}
      initialCommitments={COMMITMENTS}
      scanSupported={false}
    />
  </div>
);

/**
 * A genuine share with nothing to check it against. The panel confirms the
 * encoding and stops — a real but weaker claim than "this is one of the five
 * cards from your split", and keeping those two from reading alike is the
 * design's job here.
 */
export const NoCommitments = () => (
  <div style={frame}>
    <ShareCheck initialShare={SHARE_1} scanSupported={false} />
  </div>
);

/**
 * A damaged card. One word of a real share swapped for another valid wordlist
 * entry — the realistic corruption, since a transcription slip produces a word
 * that exists rather than nonsense. The checksum catches it, which is why
 * cards are worth checking before they are needed.
 */
export const CorruptedShare = () => (
  <div style={frame}>
    <ShareCheck
      initialShare={SHARE_1.replace(" jury ", " python ")}
      initialCommitments={COMMITMENTS}
      scanSupported={false}
    />
  </div>
);

/**
 * Scanning offered. `scanSupported` is true only where `BarcodeDetector`
 * exists, keeping the button out of browsers that cannot honour it — a photo
 * of a card is how most people will get a share back in, so where it works it
 * should be the obvious path.
 */
export const ScanAvailable = () => (
  <div style={frame}>
    <ShareCheck
      initialCommitments={COMMITMENTS}
      scanSupported
      onScanQr={async () => SHARE_1}
    />
  </div>
);
