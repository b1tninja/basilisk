import { SessionStart, START_OPENS, startIssues } from "basilisk-portal";

/*
 * Naming the room, which is the only decision here.
 *
 * A room *is* its audience: `deriveRoomMaterial` hashes this site's hostname
 * with the sorted fingerprints, so choosing the list is choosing the room. There
 * is no code to allocate, no server to ask, and nothing else to configure — so
 * every control on this panel is about the list and about the key that proves
 * you belong in it.
 *
 * Two things this panel says that no other surface can:
 *
 * - **Start writes no cells.** It used to append `agent.unlock` and
 *   `quorum.offer` / `quorum.join` and run them, and this panel printed that
 *   recipe before writing it. There is no recipe any more, and silence would be
 *   the wrong replacement: `opens` carries `START_OPENS`' sentences, which say
 *   what opening a room actually does — chiefly that this key is held for as
 *   long as the session is open, which is true for far longer than any cell was.
 * - **Roles say what each end does, not who presses first.** Ordering stopped
 *   being a correctness question: a joiner announces itself on arrival and the
 *   creator republishes the signed invite to it, so arriving late costs nothing.
 *   The two roles remain because a room with two creators or two joiners is a
 *   room where nobody is introduced.
 *
 * `issues` is `startIssues`' own output rather than fixture prose, so these
 * cells cannot drift from the refusals a press would actually hit.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

const KEYS = [
  { fingerprint: ADA, uid: "Ada Lovelace <ada@example.org>" },
  { fingerprint: LIN, uid: "Lin Zhou <lin@example.org>" },
];

/**
 * `trusted`, not `suggestions`: keys this browser has already *met* and marked.
 * The list used to be this browser's own vault keys, which is the one group
 * that is mostly not the people you are meeting — your own key joins the room
 * the moment you choose it above, so every remaining row was a second identity
 * of yours. A `RecipientChoice` carries `label`, not `uid`.
 */
const TRUSTED = [
  { fingerprint: GRACE, label: "Grace Hopper <grace@example.org>" },
  { fingerprint: LIN, label: "Lin Zhou <lin@example.org>" },
];

const noop = () => {};

const base = {
  keys: KEYS,
  trusted: TRUSTED,
  /**
   * What Start does to your notebook, in `START_OPENS`' own sentences —
   * required, and the replacement for the `recipe` this panel used to print.
   * Real exported prose rather than fixture text, so a card can never show a
   * claim the product does not make.
   */
  opens: START_OPENS,
  onRole: noop,
  onKeyFingerprint: noop,
  onAudience: noop,
  onPaste: noop,
  onCopyInvite: noop,
  onStart: noop,
};

const linkFor = (audience: string[]) =>
  `https://basilisk.pages.dev/toolkit#j=${[...audience].sort().join(",")}`;

/**
 * **Nothing chosen yet — the state a reader arrives in.** Both refusals are
 * live: no key, and no room. They are sentences rather than a greyed button
 * because each names something different to do, and "Start (disabled)" names
 * neither.
 */
export const Empty = () => (
  <SessionStart
    {...base}
    role="offer"
    keyFingerprint=""
    audience={[]}
    issues={startIssues({ audience: [], keyFingerprint: "" })}
    inviteUrl={null}
  />
);

/**
 * Ready to start: a key chosen, two people in the room, no refusals left. The
 * invite card below already shows exactly what will be sent, before anything is
 * opened — the link is a function of the audience, so it exists the moment the
 * audience does.
 */
export const ReadyToStart = () => (
  <SessionStart
    {...base}
    role="offer"
    keyFingerprint={ADA}
    audience={[ADA, GRACE].sort()}
    issues={[]}
    inviteUrl={linkFor([ADA, GRACE])}
  />
);

/**
 * **The joiner's side, and the reason the roles are visible at all.**
 *
 * The copy inverts: a joiner waits for the creator's signed invite and meshes
 * only after verifying it. Arriving late costs nothing — a joiner announces
 * itself when it joins, and an invite already published is republished for it —
 * so the roles are about which end introduces the other, not about who presses
 * first. Collapsing them into one "Connect" would leave a room with two
 * creators or two joiners, where nobody is introduced at all.
 */
export const InvitedByLink = () => (
  <SessionStart
    {...base}
    role="join"
    keyFingerprint={GRACE}
    audience={[ADA, GRACE].sort()}
    issues={[]}
    inviteUrl={linkFor([ADA, GRACE])}
  />
);

/**
 * **A key outside the room.** The refusal that is easiest to hit and hardest to
 * diagnose without it: the room is derived from the audience, so opening it
 * under a key that is not in the list derives a *different* room, and both ends
 * wait forever in rooms neither can see. `startIssues` catches it before the
 * press; `NotebookSession` would refuse the same thing a moment later, with the
 * reader no longer looking at the list that caused it.
 */
export const KeyNotInTheRoom = () => (
  <SessionStart
    {...base}
    role="offer"
    keyFingerprint={LIN}
    audience={[ADA, GRACE].sort()}
    issues={startIssues({ audience: [ADA, GRACE], keyFingerprint: LIN })}
    inviteUrl={linkFor([ADA, GRACE])}
  />
);

/**
 * A session is already open. One exchange at a time is the transport's own rule
 * — `execQuorumOpen` throws on a second — so this is that refusal moved to where
 * it can be acted on rather than surfacing as a run error two cells later.
 */
export const AlreadyLive = () => (
  <SessionStart
    {...base}
    role="offer"
    keyFingerprint={ADA}
    audience={[ADA, GRACE].sort()}
    issues={startIssues({ audience: [ADA, GRACE], keyFingerprint: ADA, live: true })}
    inviteUrl={linkFor([ADA, GRACE])}
  />
);
