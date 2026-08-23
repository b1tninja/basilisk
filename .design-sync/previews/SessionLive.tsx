import { SessionLive, type SessionLiveProps } from "basilisk-portal";

/*
 * The live session: what it is doing, who is in it, and what confirmation
 * actually proved.
 *
 * **There is no "compare these words with your friend" state here, and there
 * must not be.** Key confirmation in this protocol is automatic: peers exchange
 * a `kc` frame carrying a transcript hash over the room id, both PGP
 * fingerprints, both ephemeral ECDH keys and both DTLS certificates. A mismatch
 * drops the frame and the peer stays unconfirmed. Nothing is ever shown to a
 * person to read aloud, so this panel reports that confirmation *happened* — or
 * says plainly that it has not.
 *
 * Every sentence below is `sessionReadout`'s or `confirmationReadout`'s, drawn
 * verbatim. Two opinions about whether a peer is confirmed would be considerably
 * worse than two about where a cell runs, and `PlanPanel` already refuses to be
 * a second opinion on the smaller question.
 *
 * The states are ordered as a session moves through them, and the interesting
 * ones are the middles: `waiting` and `partial` are where somebody still has to
 * be brought in or chased, which is why the invite card stays visible in both
 * and disappears once everyone is confirmed.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

const AUDIENCE = [ADA, GRACE, LIN].sort();
const ROOM = "KJ8X4M2Q7T9FQ2AB";
const URL = `https://basilisk.pages.dev/toolkit#j=${AUDIENCE.join(",")}`;

const noop = () => {};
const actions = {
  inviteUrl: URL,
  onCopyInvite: noop,
  onRestartIce: noop,
  onClose: noop,
} satisfies Partial<SessionLiveProps>;

const room = (patch: Record<string, unknown>) => ({
  phase: "connected" as const,
  role: "creator" as const,
  room: ROOM,
  status: "",
  audience: AUDIENCE,
  self: ADA,
  peers: [],
  ...patch,
});

/**
 * **Everybody confirmed — the state the whole flow exists to reach.**
 *
 * The sentence says what the confirmation covered, because "verified" alone is a
 * word a reader has to take on faith. Naming the room, both keys and both
 * transport certificates is what makes it checkable against the code, and it is
 * also the sentence that quietly explains why nobody was asked to compare
 * anything.
 *
 * The invite is gone. There is nobody left to send it to, and a share control
 * that never retires is one more thing to skim past in the states where it
 * matters.
 */
export const Confirmed = () => (
  <SessionLive
    {...actions}
    state={room({
      peers: [
        { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: true, via: "host" },
        { id: "@lin", fingerprint: LIN, state: "connected", authenticated: true, via: "srflx" },
      ],
    })}
  />
);

/**
 * **Waiting, with nobody there — and the transport fact that explains it.**
 *
 * Azure Web PubSub brokers to the connections in the group at the moment of the
 * send and keeps no backlog, and `NotebookSession.start()` publishes the signed
 * invite exactly once, the instant its own room is joined. So a joiner arriving
 * a second later is in the right room and will never see the introduction.
 *
 * That makes the remedy counter-intuitive — *start again*, not *wait longer* —
 * and it is the single most valuable sentence on this panel. A generic
 * "connecting…" spinner here would train people to wait out a state that never
 * resolves.
 */
export const NobodyYet = () => (
  <SessionLive {...actions} state={room({ phase: "waiting", peers: [] })} />
);

/**
 * Somebody arrived and the key exchange has not finished. Distinguished from the
 * state below on purpose: this normally clears in under a second on its own, and
 * badging an ordinary join as a security problem is how a real one stops being
 * read.
 */
export const JoinedNotYetConfirmed = () => (
  <SessionLive
    {...actions}
    state={room({
      phase: "waiting",
      peers: [
        { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: false },
      ],
    })}
  />
);

/**
 * **The dangerous middle: present and unproven.**
 *
 * A working DTLS channel that nothing has bound to a key. The session layer
 * already refuses to place a cell there and refuses to believe anything sent
 * over it — this is that refusal said out loud, at the moment it is true, rather
 * than discovered later as a run that will not start.
 *
 * `--error` rather than `--warn` is deliberate and is the one place this flow
 * spends it: a partially confirmed room is not a legitimate-but-risky action, it
 * is a claim that has failed to be established.
 */
export const HalfConfirmed = () => (
  <SessionLive
    {...actions}
    onRemove={noop}
    state={room({
      peers: [
        { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: true, via: "host" },
        { id: "@lin", fingerprint: LIN, state: "connected", authenticated: false, via: "relay" },
      ],
    })}
  />
);

/**
 * A peer left mid-session. The room stays `connected` — most of it is fine — and
 * the down link is the only thing on screen that says a ceremony needing
 * everybody cannot proceed. Per-row, because a session-level summary reads
 * identically whether every link is healthy or one died.
 */
export const PeerLeft = () => (
  <SessionLive
    {...actions}
    state={room({
      peers: [
        { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: true, via: "host" },
        { id: "@lin", fingerprint: LIN, state: "failed", authenticated: true },
      ],
    })}
  />
);

/**
 * **Removal, which is not eviction — and the note exists because "Remove" would
 * be read as though it were.**
 *
 * There is no eviction to be had: the signalling service exposes no membership
 * this application can enumerate and no connection it can close. What happens
 * instead is that the room *moves* — a new epoch, the remaining audience, and a
 * secret minted now and delivered sealed to the people who stay, so the name it
 * moves to is not a function of anything the removed key holds. Every pairwise
 * key is rebuilt over the new room, so the whole room is briefly unconfirmed
 * again, which is a consequence worth stating before the press rather than
 * watching happen.
 */
export const RemovingSomebody = () => (
  <SessionLive
    {...actions}
    onRemove={noop}
    state={room({
      peers: [
        { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: true, via: "host" },
        { id: "@lin", fingerprint: LIN, state: "connected", authenticated: true, via: "host" },
      ],
    })}
  />
);

/**
 * The transport gave up. The *why* is the session's own last status line rather
 * than a paraphrase — this module did not observe the failure, and inventing a
 * sentence for it is how a panel and a tile come to hold two opinions about one
 * cause.
 *
 * Restart is offered only here. It renegotiates ICE in place, so the room, the
 * audience and the roster survive; starting over would derive the same room from
 * the same audience anyway, which is the second sentence.
 */
export const Lost = () => (
  <SessionLive
    {...actions}
    state={room({
      phase: "failed",
      status: "Signalling dropped — reconnecting…",
      peers: [{ id: "@grace", fingerprint: GRACE, state: "failed", authenticated: true }],
    })}
  />
);

/**
 * Over. Muted, not hidden: this is the row somebody reads to confirm a ceremony
 * ended cleanly, and the closing sentence is the useful one — the room is a
 * digest of the audience, so the same people land in the same room next time.
 */
export const Closed = () => (
  <SessionLive {...actions} state={room({ phase: "closed", peers: [] })} />
);
