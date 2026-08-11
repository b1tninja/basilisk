import { ConnectionsPanel } from "basilisk-portal";

/*
 * The session-wide view: who is in the room, which links are up, and which are
 * authenticated. `SessionStrip` cannot answer those — it assumes one session
 * with one peer — so this panel is what a multi-party notebook is managed from.
 *
 * Two kinds of connection appear here and they are not interchangeable. A
 * `quorum` link is the authenticated exchange the notebook session sits on top
 * of; a `peer` link is a raw managed connection whose far end is encrypted but
 * **not** identified. The panel keeps them apart, and the mesh roster is drawn
 * from `session.peers` while only `origin: "peer"` links get their own rows —
 * drawing both would show one connection twice.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

const frame = { maxWidth: 520 } as const;

/**
 * A healthy three-party room. Every peer authenticated, every link direct.
 *
 * `expected` is stated alongside `connected` because a threshold ceremony is
 * waiting for a *number*, and "3 connected" answers nothing on its own — the
 * question is always 3 of how many.
 */
export const Default = () => (
  <div style={frame}>
    <ConnectionsPanel
      session={{
        phase: "connected",
        room: "KJ8X4M2Q7T9FQ",
        role: "creator",
        connected: 3,
        expected: 3,
        peers: [
          { id: "@ada", fingerprint: ADA, state: "connected", authenticated: true, via: "host" },
          { id: "@grace", fingerprint: GRACE, state: "connected", authenticated: true, via: "srflx" },
          { id: "@lin", fingerprint: LIN, state: "connected", authenticated: true, via: "host" },
        ],
      }}
      onCloseLink={() => {}}
      onRestartLink={() => {}}
      onClose={() => {}}
    />
  </div>
);

/**
 * Nothing running. The panel is reachable at all times, so its idle state is a
 * real state rather than an absence — it says there is no session instead of
 * rendering an empty roster that could be mistaken for "everyone left".
 */
export const Idle = () => (
  <div style={frame}>
    <ConnectionsPanel session={{ phase: "idle" }} />
  </div>
);

/**
 * The room is open and the invite is unanswered. This is the state a person
 * sits in while they message the link to someone, which makes Copy invite the
 * only control that matters here — hence `onCopyInvite` and `onClose` and
 * nothing else.
 *
 * `connected: 0` against `expected: 3` is drawn rather than hidden: a ceremony
 * that will never reach its threshold should look unreached from the start.
 */
export const WaitingForPeers = () => (
  <div style={frame}>
    <ConnectionsPanel
      session={{
        phase: "waiting",
        room: "KJ8X4M2Q7T9FQ",
        role: "creator",
        invite: "https://basilisk.pages.dev/toolkit#s=KJ8X4M2Q7T9FQ&k=mDMEZHhhDBYJKwYBBAHaRw8",
        connected: 0,
        expected: 3,
        peers: [],
      }}
      onCopyInvite={() => {}}
      onClose={() => {}}
    />
  </div>
);

/**
 * The distinction the panel exists to draw: an authenticated room peer beside
 * one that is merely *connected*.
 *
 * `peer-4tq9` has a working encrypted channel and no proven identity — nobody
 * has checked a key against it. Treating that as equivalent to `@ada` is the
 * mistake this layout refuses to let a reader make, because a threshold
 * ceremony run against an unauthenticated participant proves nothing.
 */
export const MixedTrust = () => (
  <div style={frame}>
    <ConnectionsPanel
      session={{
        phase: "connected",
        room: "KJ8X4M2Q7T9FQ",
        role: "joiner",
        connected: 2,
        expected: 3,
        peers: [
          { id: "@ada", fingerprint: ADA, state: "connected", authenticated: true, via: "host" },
          { id: "peer-4tq9", state: "connected", authenticated: false, via: "srflx" },
          { id: "@lin", fingerprint: LIN, state: "connecting", authenticated: false },
        ],
      }}
      onCloseLink={() => {}}
      onRestartLink={() => {}}
      onClose={() => {}}
    />
  </div>
);

/**
 * Direct connections get their own section, and the relay state rides with
 * them.
 *
 * `relay.phase: "off"` is the shipped default and it is stated rather than
 * left blank — "no relay row" and "a relay that will never be contacted" look
 * identical otherwise, and only one of them is a promise. The escalating link
 * beneath it is the case where a direct path failed and the two-phase fallback
 * is reaching for a relay, which changes who can observe the connection's
 * existence and therefore deserves to be visible.
 */
export const DirectLinksAndRelay = () => (
  <div style={frame}>
    <ConnectionsPanel
      session={{
        phase: "connected",
        room: "KJ8X4M2Q7T9FQ",
        role: "creator",
        connected: 1,
        expected: 2,
        peers: [
          { id: "@ada", fingerprint: ADA, state: "connected", authenticated: true, via: "host" },
        ],
      }}
      links={[
        {
          id: "AABBCCDDEEFF0011",
          origin: "peer",
          role: "offerer",
          label: "laptop",
          connectionState: "connected",
          channelState: "open",
          authenticated: false,
          via: "host",
          relay: { phase: "off", configured: false },
        },
        {
          id: "1100FFEEDDCCBBAA",
          origin: "peer",
          role: "answerer",
          label: "phone",
          connectionState: "connecting",
          channelState: "connecting",
          authenticated: false,
          relay: { phase: "escalating", configured: true, reason: "no direct path after 4s" },
        },
      ]}
      onCloseLink={() => {}}
      onRestartLink={() => {}}
      onClose={() => {}}
    />
  </div>
);
