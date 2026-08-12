import { CellAssign } from "basilisk-portal";

/*
 * Who runs this cell — the control that writes a `@peer` header.
 *
 * Until this existed the header was reachable only by knowing the grammar and
 * typing it into the source view, which made placement a finished feature with
 * no entry point: the parser read it, `serializeChain` wrote it, `planRun`
 * placed by it and `placementGate` enforced it, and nothing could produce one.
 *
 * It sets the same fields the text sets, so the two views cannot disagree
 * about where a cell runs. Every cell passes `defaultOpen`: a closed menu
 * photographs as a button, and the items are the whole of what this control is.
 */

const frame = { padding: "0 0 210px" };
const tall = { padding: "0 0 360px" };
const ROOM = ["ada", "grace", "lin"];

/** What a verifiable split writes: a check, a public thing, and a secret. */
const CEREMONY_SLOTS = ["expected", "commitments", "share"];

/**
 * Unassigned, which is most cells most of the time.
 *
 * The label is "anyone", not "unassigned" or a blank: a cell with no header
 * genuinely runs wherever the notebook runs, which is a real answer rather than
 * the absence of one. `publish` is not offered here — it says this cell's
 * output may leave the machine that made it, and that is a claim about a
 * boundary which does not exist until somebody is on the other side of it.
 */
export const Default = () => (
  <div style={frame}>
    <CellAssign peer={null} publish={false} choices={ROOM} onAssign={() => {}} defaultOpen />
  </div>
);

/**
 * A dealer's cell: three `out` slots, one of them published.
 *
 * This is the shape the control exists for. A verifiable split writes the
 * commitments every custodian needs to check their share, the shares
 * themselves, and a digest the room compares against later — three
 * destinations, one cell. "Publish its output" cannot mean all three, so each
 * slot is its own line, named by the change it makes rather than by its state.
 *
 * The trigger carries the whole header, `publish=$commitments` and all: a
 * reader scanning a notebook for what leaves their machine should not have to
 * open a menu, and "publish" alone would be the wrong answer here.
 */
export const PublishingOneSlot = () => (
  <div style={tall}>
    <CellAssign
      peer="ada"
      publish
      outSlots={CEREMONY_SLOTS}
      publishSlots={["commitments"]}
      choices={ROOM}
      onAssign={() => {}}
      defaultOpen
    />
  </div>
);

/**
 * The same cell publishing everything, which is what a bare `publish` means.
 *
 * Every slot reads "Keep … here", because every one of them is currently
 * leaving. There is no item for publishing nothing: an empty list *is* the
 * bare `publish`, so the way to stop is the line above — which is why the last
 * remaining slot cannot be switched off from here.
 */
export const PublishingEverything = () => (
  <div style={tall}>
    <CellAssign
      peer="ada"
      publish
      outSlots={CEREMONY_SLOTS}
      choices={ROOM}
      onAssign={() => {}}
      defaultOpen
    />
  </div>
);

/**
 * Assigned. The trigger shows the header the cell now carries, so the control
 * and the recipe text say the same thing in the same spelling — `@ada`, sigil
 * and all, because that is what is written in the notebook.
 *
 * Publishing is now offered, and it is the only item below the separator: the
 * constructive choices are the peers, and this is a change of what the cell is
 * allowed to do rather than of who does it.
 */
export const Assigned = () => (
  <div style={frame}>
    <CellAssign peer="ada" publish={false} choices={ROOM} onAssign={() => {}} defaultOpen />
  </div>
);

/**
 * Assigned and publishing. The trigger carries both, because a reader scanning
 * a notebook for what leaves their machine should not have to open a menu to
 * find out — and the menu's own item flips to "Stop publishing its output",
 * naming the change rather than the state.
 *
 * One `out` slot, so there is nothing to choose between: `publish=$only` and
 * `publish` are the same claim at different lengths, and the per-slot lines
 * appear only where they mean something.
 */
export const Publishing = () => (
  <div style={frame}>
    <CellAssign
      peer="ada"
      publish
      outSlots={["pubA"]}
      choices={ROOM}
      onAssign={() => {}}
      defaultOpen
    />
  </div>
);

/**
 * A notebook written before anyone joined.
 *
 * The choices are the room *and* the labels the notebook already names, so a
 * ceremony can be written on a Tuesday and run when the other person is free.
 * Only the room would make a header impossible to write until somebody was
 * present, which is backwards — and it is why `planRun` reports on an unbound
 * notebook at all.
 */
export const BeforeAnyoneJoins = () => (
  <div style={frame}>
    <CellAssign peer="witness" publish choices={["witness"]} onAssign={() => {}} defaultOpen />
  </div>
);
