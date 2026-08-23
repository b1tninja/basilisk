import { CeremonySheet, type CeremonySheetProps } from "basilisk-portal";

/*
 * The guided key ceremony, as a Sheet — the handoff's rule being that a design
 * needing a window is a `Sheet`.
 *
 * It owns sequence and wording, not execution. Every stage's work is ordinary
 * notebook cells, so the ceremony stays reproducible by hand, visible in
 * Source view, and shareable as recipe text; this component never touches the
 * engine. That is what keeps the guided path and the manual path the same
 * path, rather than a wizard that does something you cannot inspect.
 *
 * Stages run `setup → split → verify → cards → receipt`. The middle one is the
 * point of the whole flow: `verify` recombines the shares and compares the
 * digest against the original, so the cards are proven to work *before* anyone
 * relies on them. A ceremony that skipped it would print five cards nobody had
 * ever tested.
 *
 * Every cell renders `open`; a closed sheet photographs as an empty frame.
 */

const DIGEST = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

const MNEMONICS = [
  "away spend being vegan aluminum lend premium move spirit jury warn emphasis ancient crowd ounce blue belong starting grant enemy bedroom costume percent shrimp treat dining mailman ajar parking include evil forward ruin daughter",
  "away spend chemical vegan aluminum civil cinema frozen sniff thorn false fitness deal cargo blanket surface forward eraser flexible guilt squeeze knife average jacket quiet magazine laden yoga result involve type worthy knife order",
  "away spend demand vegan aluminum relate quiet sweater twice recall disaster sheriff album swing activity morning ticket midst anatomy failure maximum fantasy breathe tackle python isolate union tenant therapy engage extend health aspect diet",
];

const SHARE_ARTIFACTS = MNEMONICS.map((content, i) => ({
  label: `share (share ${i + 1})`,
  filename: `share-${i + 1}.txt`,
  content,
  role: "share",
  sensitive: true,
  shareIndex: i + 1,
  mime: "text/plain; charset=utf-8",
  tags: ["mnemonic", "blip39"],
  traits: { shareOf: i + 1, threshold: 3 },
}));

const COMMITMENTS =
  '{"v":1,"commitments":["039f26bbd060841e88d4995e4e376491319474d5e51101bd108334ede83086f706","035e014b986f7939e95c2e860b7acd2d126339f18c95f52f2917dfb3f6a4adc630","03ec30bb3172397acb12b04137d4501c93267394d45687024fe498f4cfa5ecf1d0"],"publicKey":"039f26bbd060841e88d4995e4e376491319474d5e51101bd108334ede83086f706"}';

const RECEIPT = `basilisk ceremony receipt
label      board-root
quorum     any 3 of 5
split id   9F26-BBD0-6084
digest     ${DIGEST}
verified   recombined 3 shares, digest matched
date       2023-06-01`;

const BASE = {
  open: true as const,
  onOpenChange: () => {},
  onStage: () => {},
  threshold: 3,
  shares: 5,
  label: "board-root",
  qr: true,
  onParams: () => {},
  onRunStage: () => {},
  expectedDigest: DIGEST,
  recoveredDigest: "",
  shareArtifacts: [],
  receiptText: "",
} satisfies Partial<CeremonySheetProps>;

/**
 * Stage one: the quorum itself. Nothing has run, and the only decisions are
 * how many shares exist and how many recover the secret — the two numbers
 * every later stage depends on and the only ones a person cannot change
 * afterwards without starting over.
 */
export const Setup = () => (
  <CeremonySheet {...BASE} stage="setup" runState="idle" />
);

/**
 * The split, mid-run. `runState: "running"` is a real state worth drawing: key
 * generation is not instant, and a ceremony that looks frozen invites someone
 * to click again.
 */
export const Splitting = () => (
  <CeremonySheet {...BASE} stage="split" runState="running" />
);

/**
 * Verification passed — the stage that earns the cards their trust.
 *
 * `recoveredDigest` matches `expectedDigest`, meaning the shares were actually
 * recombined and produced the original secret. Showing both rather than a
 * green tick is deliberate: the claim is checkable by the reader, which is the
 * standard the rest of the toolkit holds itself to.
 */
export const Verified = () => (
  <CeremonySheet
    {...BASE}
    stage="verify"
    runState="done"
    recoveredDigest={DIGEST}
    shareArtifacts={SHARE_ARTIFACTS}
    commitmentsText={COMMITMENTS}
  />
);

/**
 * Verification failed — the digests differ.
 *
 * This is the most important state in the flow and the reason `verify` exists
 * at all. Catching it here costs a restart; not catching it means five printed
 * cards that reconstruct nothing, discovered on the day they are needed.
 */
export const VerifyMismatch = () => (
  <CeremonySheet
    {...BASE}
    stage="verify"
    runState="error"
    runError="Recombined 3 shares, but the digest does not match the secret that was split."
    recoveredDigest="3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea"
    shareArtifacts={SHARE_ARTIFACTS}
    commitmentsText={COMMITMENTS}
  />
);

/**
 * The cards stage, with a signing key chosen. Signing the receipt is what lets
 * someone later prove which ceremony produced a given set of cards — the
 * receipt is the durable record, and an unsigned one is only a claim.
 */
export const Cards = () => (
  <CeremonySheet
    {...BASE}
    stage="cards"
    runState="done"
    recoveredDigest={DIGEST}
    shareArtifacts={SHARE_ARTIFACTS}
    commitmentsText={COMMITMENTS}
    signingKeys={[
      { fingerprint: "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388", uid: "Ada Lovelace <ada.lovelace@example.org>" },
      { fingerprint: "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43", uid: "Grace Hopper <grace@example.org>" },
    ]}
    signWith="D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388"
    onSignWith={() => {}}
  />
);

/**
 * The receipt — what the ceremony leaves behind once the cards are in
 * envelopes. It restates the quorum, the split id and the verification result
 * in text, because in a year the cards will be in a drawer and this is the
 * only thing that explains them.
 */
export const Receipt = () => (
  <CeremonySheet
    {...BASE}
    stage="receipt"
    runState="done"
    recoveredDigest={DIGEST}
    shareArtifacts={SHARE_ARTIFACTS}
    commitmentsText={COMMITMENTS}
    receiptText={RECEIPT}
  />
);
