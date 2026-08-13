import { SessionSheet, startIssues } from "basilisk-portal";

/*
 * The shared session's own window — a `Sheet`, per the rule that a design
 * needing a window is a Sheet.
 *
 * Not a fourth row inside `ShareSheet`, because the two answer different
 * questions. `ShareSheet` is about *what leaves this machine* and each of its
 * rows is one transfer; a session is not a transfer at all. Nothing of the
 * notebook crosses it — both sides hold the same recipe text, arrived at
 * independently, which is what makes a shared run a reproducible build rather
 * than a screen share, and only offers, results and attestations move.
 *
 * Every cell renders `open`, because a closed sheet photographs as an empty
 * frame, and suppresses autofocus so the first control is not captured
 * mid-focus.
 *
 * The sheet holds one decision and nothing else: is there an exchange? Before
 * one there is a room to name; after one there is a room to watch. Closing the
 * session is what returns it to the first half, which is honest — a closed
 * exchange leaves nothing to observe, and the same audience derives the same
 * room again.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const AUDIENCE = [ADA, GRACE].sort();
const URL = `https://basilisk.pages.dev/toolkit#j=${AUDIENCE.join(",")}`;

const noop = () => {};

const START = {
  role: "offer" as const,
  onRole: noop,
  keys: [
    { fingerprint: ADA, uid: "Ada Lovelace <ada@example.org>" },
    { fingerprint: GRACE, uid: "Grace Hopper <grace@example.org>" },
  ],
  keyFingerprint: ADA,
  onKeyFingerprint: noop,
  audience: AUDIENCE,
  suggestions: [{ fingerprint: GRACE, uid: "Grace Hopper <grace@example.org>" }],
  onAudience: noop,
  onPaste: noop,
  issues: startIssues({ audience: AUDIENCE, keyFingerprint: ADA }),
  inviteUrl: URL,
  onCopyInvite: noop,
  recipe: [
    `agent.unlock ${ADA} | out $me`,
    "",
    `quorum.offer to="${AUDIENCE.join(",")}" key=$me | out $session`,
  ].join("\n"),
  onStart: noop,
};

/**
 * **The default and the primary story: no session yet.** This is what the Share
 * sheet's "Run it together" row opens onto, and what the Connections tab's Start
 * button reaches. The whole panel is about naming the room, because a room *is*
 * its audience.
 */
export const Naming = () => (
  <SessionSheet open onOpenChange={() => {}} live={null} start={START} />
);

/**
 * A session is open and confirmed. The naming half is gone — there is nothing
 * left to decide, and leaving an editable audience beside a room already derived
 * from one would suggest the room could be edited underneath itself.
 */
export const Live = () => (
  <SessionSheet
    open
    onOpenChange={() => {}}
    start={START}
    live={{
      state: {
        phase: "connected",
        role: "creator",
        room: "KJ8X4M2Q7T9FQ2AB",
        status: "",
        audience: AUDIENCE,
        self: ADA,
        peers: [
          { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: true, via: "host" },
        ],
      },
      inviteUrl: URL,
      onCopyInvite: noop,
      onRestartIce: noop,
      onClose: noop,
      onRemove: noop,
    }}
  />
);

/**
 * Open, and nobody has answered. Kept as its own cell because it is the state
 * that most needs the sheet's full width: the reason (nobody has arrived, or the
 * two audiences differ and each side derived a room of its own) and the remedy
 * (check the fingerprint list, not the order you pressed in) are two sentences a
 * strip could not have carried.
 *
 * It used to say "an invite published once, onto a relay with no history" and
 * "start again with the other side already waiting". The relay still keeps no
 * history; the protocol stopped depending on it — a joiner announces itself and
 * the creator republishes (`NotebookSession._onKnock`) — so restarting is no
 * longer a remedy for anything and naming it would hide the real cause.
 */
export const WaitingForSomebody = () => (
  <SessionSheet
    open
    onOpenChange={() => {}}
    start={START}
    live={{
      state: {
        phase: "waiting",
        role: "creator",
        room: "KJ8X4M2Q7T9FQ2AB",
        status: "",
        audience: AUDIENCE,
        self: ADA,
        peers: [],
      },
      inviteUrl: URL,
      onCopyInvite: noop,
      onClose: noop,
    }}
  />
);
