import { HandoffQueue, type HandoffQueueProps } from "basilisk-portal";

/*
 * Cells crossing between machines, and the press each one is waiting for.
 *
 * Everything under this widget already existed and could not be reached:
 * `planRun` decides where a cell runs, `placementGate` declines the ones that
 * are not ours, `buildOfferFor` packs what a declined cell needs,
 * `acceptHandoffOffer` and `acceptCellResult` check what arrives. All five ship,
 * a two-browser end-to-end suite drives the whole arc — and nothing in the
 * product rendered a single one of them. This is the entry point.
 *
 * **Three lists, because there are three different waits**, and a single
 * "pending" would hide which of them is on you: you waiting on them, them
 * waiting on you, and an answer you owe. The middle one is the one with the
 * rule: an offer or a result arrives **pending and nothing more**. The session
 * parses it and checks a result's signature against that one peer's key, and
 * registers nothing. A result that resumed a run on a peer's say-so would
 * continue *this* machine on values nobody looked at, which is the failure the
 * whole exchange is built to avoid — so accepting is a person's act, and every
 * cell below shows a press that has not happened.
 */

const MARA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const OKAFOR = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";

const noop = () => {};
/**
 * `onDismiss` is not optional and is not a close button. It discards a document
 * another person is waiting on the answer to, and it tells them nothing — there
 * is no decline on this wire by design, so from their end a document you put
 * down and one you have not read yet look the same. Every pending row draws it
 * beside Accept and says so underneath.
 */
const actions = { onAccept: noop, onDismiss: noop, onOffer: noop, onSendResult: noop } satisfies Partial<HandoffQueueProps>;

/**
 * A session, and nothing crossing. The empty state teaches the mechanism — an
 * `@peer` header is what puts a cell in these lists — because a reader who has
 * never seen one has no way to guess what would fill the panel.
 */
export const Nothing = () => (
  <HandoffQueue {...actions} live pending={[]} placedAway={[]} owedBack={[]} />
);

/**
 * **The first thing a reload shows** — no session, nothing planned away, and an
 * answer you owed a minute ago missing from a panel that cannot say it ever
 * existed. The second paragraph is the whole reason this story is separate.
 *
 * "You owe them an answer" is built from a press. Accepting an offer is the only
 * moment anything knows a result will be owed, and that knowledge lives in shell
 * state a reload ends. Nothing restores it because nothing recorded it —
 * `quorum-ops` keeps no record of what it delivered and the session keeps none
 * of what it accepted, which is the property the exchange exists to have.
 * Writing the list to storage would trade that away to redraw a row.
 *
 * So the panel says it, and it has something worth saying: `offerCell` does not
 * remove the cell from the sender's skipped list, so their press is still
 * sitting there. Asking them to hand it over again recovers the whole thing,
 * and this paragraph is the only place a reader is ever told so.
 */
export const AfterAReload = () => (
  <HandoffQueue {...actions} live={false} pending={[]} placedAway={[]} owedBack={[]} />
);

/**
 * **No session, and the honest version of that.** A cell with an `@peer` header
 * is still planned and still declined at run time — placement does not depend on
 * a connection — it just has nowhere to go. Saying "nothing pending" here would
 * imply the notebook was running normally.
 */
export const NoSession = () => (
  <HandoffQueue
    {...actions}
    live={false}
    pending={[]}
    placedAway={[{ cell: 1, peer: "okafor", produces: ["b64"], offered: "none" }]}
    owedBack={[]}
  />
);

/**
 * You are waiting on them: the run declined cell 1 because the plan says it is
 * okafor's, and cell 2 reads what cell 1 writes — so the run handed it over as
 * it finished, carrying the values that cell reads and nothing else.
 * `buildOfferFor` refuses rather than trimming, because a partial offer says
 * "run this" while withholding something the cell needs.
 *
 * **`offered` is what the run already did, not what is queued.** The run decides
 * as it ends, so by the time this list is on screen the attempt has happened or
 * been ruled out, and the button says "again" rather than offering work that is
 * done.
 */
export const OweThemACell = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[]}
    placedAway={[{ cell: 1, peer: "okafor", produces: ["b64"], offered: "sent" }]}
    owedBack={[]}
  />
);

/**
 * The run tried and could not. The sentence is the handoff layer's own `why`,
 * rendered verbatim rather than paraphrased, because the remedy is in it — and
 * the button offers the retry the sentence implies.
 */
export const OfferRefused = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[]}
    placedAway={[
      {
        cell: 1,
        peer: "okafor",
        produces: ["b64"],
        offered: "refused",
        why: "The session dropped while the offer was in flight. Nothing left this machine.",
      },
    ]}
    owedBack={[]}
  />
);

/**
 * **`aside` is a decision, not a queue.** The run looked at this cell and chose
 * not to send: it reads no value made here and writes nothing this notebook goes
 * on to read, so an offer would carry nothing and answer nothing. Its sentence
 * is separate from `none` because the remedy is different — none at all, unless
 * the peer asks.
 */
export const LeftAside = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[]}
    placedAway={[{ cell: 5, peer: "okafor", produces: ["theirs"], offered: "aside" }]}
    owedBack={[]}
  />
);

/**
 * An offer arrived. It has been parsed and held; nothing has been checked
 * against your plan and no cell has run. Accepting is what checks it and
 * registers what it carries — and until then your own run stops in exactly the
 * same place it stopped before the offer landed.
 */
export const OfferWaiting = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[
      {
        id: "offer-1",
        kind: "offer",
        from: MARA,
        cell: 1,
        manifest: "4C1D9E07B8A2",
        ts: 1_760_000_000_000,
      },
    ]}
    placedAway={[]}
    owedBack={[]}
  />
);

/**
 * **A result — the more dangerous arrival, drawn as such.**
 *
 * The signature says this peer made the claim. It does not say the claim answers
 * a cell you handed out, and it does not say the values may be registered:
 * `acceptCellResult` asks both, of a plan and a record of what went out that the
 * session deliberately does not keep. The warn tint on the badge is the only
 * difference between the two kinds, and it is carrying that whole distinction.
 */
export const ResultWaiting = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[
      {
        id: "result-1",
        kind: "result",
        from: OKAFOR,
        cell: 1,
        manifest: "4C1D9E07B8A2",
        ts: 1_760_000_050_000,
      },
    ]}
    placedAway={[]}
    owedBack={[]}
    note="Accepted — 1 value registered. Run the notebook to use them."
  />
);

/**
 * You owe them an answer: a cell accepted, run here, and not yet returned. The
 * result is signed with the key the session was opened under, because
 * `sendResult` refuses anything that is not cleartext-signed — an unsigned
 * result is a value from whoever reached the channel.
 */
export const OweThemAnAnswer = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[]}
    placedAway={[]}
    owedBack={[{ cell: 1, to: MARA, label: "mara" }]}
  />
);

/**
 * All three at once, which a real placed run reaches: one cell handed out, one
 * document waiting on you, one answer owed back. The three headings are what
 * keep them from reading as one undifferentiated queue where the reader has to
 * work out, per row, whose move it is.
 */
export const AllThreeWaits = () => (
  <HandoffQueue
    {...actions}
    live
    pending={[
      {
        id: "result-2",
        kind: "result",
        from: OKAFOR,
        cell: 3,
        manifest: "4C1D9E07B8A2",
        ts: 1_760_000_090_000,
      },
    ]}
    placedAway={[{ cell: 4, peer: "okafor", produces: ["sig"], offered: "sent" }]}
    owedBack={[{ cell: 1, to: MARA, label: "mara" }]}
  />
);
