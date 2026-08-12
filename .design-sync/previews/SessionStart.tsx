import { SessionStart, startIssues } from "basilisk-portal";

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
 * - **Start writes cells.** It appends `agent.unlock` and `quorum.offer` /
 *   `quorum.join` to the notebook and runs them. A session started by a hidden
 *   code path would be the one thing in this app that happened without a recipe
 *   saying so, which is why the recipe is shown before it is written.
 * - **Order is correctness, not preference.** The relay brokers only to whoever
 *   is in the group at the instant of a send and stores nothing, and the
 *   creator's signed invite goes out exactly once, inside `start()`. A joiner
 *   arriving one second later is in the right room and will never see the
 *   introduction — which is why the role paragraph tells each side to let the
 *   other press first.
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

const SUGGESTIONS = [
  { fingerprint: GRACE, uid: "Grace Hopper <grace@example.org>" },
  { fingerprint: LIN, uid: "Lin Zhou <lin@example.org>" },
];

const noop = () => {};

const base = {
  keys: KEYS,
  suggestions: SUGGESTIONS,
  onRole: noop,
  onKeyFingerprint: noop,
  onAudience: noop,
  onPaste: noop,
  onCopyInvite: noop,
  onStart: noop,
};

const linkFor = (audience: string[]) =>
  `https://basilisk.pages.dev/toolkit#j=${[...audience].sort().join(",")}`;

const recipeFor = (audience: string[], key: string, role: "offer" | "join") =>
  [
    `agent.unlock ${key} | out $me`,
    "",
    `quorum.${role} to="${[...audience].sort().join(",")}" key=$me | out $session`,
  ].join("\n");

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
    recipe={recipeFor([], "", "offer")}
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
    recipe={recipeFor([ADA, GRACE], ADA, "offer")}
  />
);

/**
 * **The joiner's side, and the reason the roles are visible at all.**
 *
 * The copy inverts: a joiner waits for an invite that is broadcast once and
 * never stored, so pressing after the creator has already started means there is
 * nothing left on the wire to verify. Collapsing the two roles into one
 * "Connect" would make that failure indistinguishable from a network problem.
 */
export const InvitedByLink = () => (
  <SessionStart
    {...base}
    role="join"
    keyFingerprint={GRACE}
    audience={[ADA, GRACE].sort()}
    issues={[]}
    inviteUrl={linkFor([ADA, GRACE])}
    recipe={recipeFor([ADA, GRACE], GRACE, "join")}
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
    recipe={recipeFor([ADA, GRACE], LIN, "offer")}
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
    recipe={recipeFor([ADA, GRACE], ADA, "offer")}
  />
);
