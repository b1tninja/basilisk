import { SessionStrip } from "basilisk-portal";

/*
 * The cell-level live-exchange region. A run that needs another party pauses
 * here, so this strip is the only thing on screen saying why nothing is
 * happening — which is why every cell below is a *waiting* state rather than a
 * gallery of happy paths.
 *
 * Room codes are truncated by the component itself (`KJ8X…9FQ`), so the
 * fixtures carry full codes and let it do the shortening. The invite line is a
 * real `#`-fragment share link: the fragment never leaves the browser, which is
 * the whole reason invites are shaped this way rather than as query strings.
 */

const INVITE =
  "https://basilisk.pages.dev/toolkit#s=KJ8X4M2Q7T9FQ&k=mDMEZHhhDBYJKwYBBAHaRw8BAQdAUcwl";

const wrap = { display: "grid", gap: 10, maxWidth: 560 } as const;
const label = {
  fontSize: 10.5,
  fontWeight: 700,
  textTransform: "uppercase" as const,
  letterSpacing: "0.06em",
  color: "var(--muted-foreground)",
  margin: "0 0 4px",
};

/**
 * The state a reader hits most: connected, two parties, nothing to do. The
 * strip stays visible after connecting rather than collapsing, because a
 * ceremony that silently lost its peer between cells is exactly the failure
 * this row exists to make visible.
 */
export const Default = () => (
  <SessionStrip state="connected" room="KJ8X4M2Q7T9FQ" connected={1} />
);

/**
 * Every state the strip can hold, in the order a session actually moves
 * through them. `offering` and `waiting` are distinct on purpose — the first
 * is this peer publishing a signed invite, the second is that invite sitting
 * unanswered — and collapsing them into one "connecting…" would hide which
 * side the ceremony is stuck on.
 *
 * `closed` and `failed` are also deliberately separate: a closed session ended
 * because someone ended it, a failed one lost its transport. Only the second
 * offers `onRestartIce`, and offering a retry on a session the user closed
 * themselves would misread the situation.
 */
export const States = () => (
  <div style={wrap}>
    {(
      [
        ["offering", { room: "KJ8X4M2Q7T9FQ", invite: INVITE }],
        ["waiting", { room: "KJ8X4M2Q7T9FQ", invite: INVITE }],
        ["connected", { room: "KJ8X4M2Q7T9FQ", connected: 1 }],
        ["closed", { room: "KJ8X4M2Q7T9FQ" }],
        ["failed", { room: "KJ8X4M2Q7T9FQ" }],
      ] as const
    ).map(([state, props]) => (
      <div key={state}>
        <p style={label}>{state}</p>
        <SessionStrip
          state={state}
          {...props}
          onCopyInvite={() => {}}
          onCancel={() => {}}
          onRestartIce={state === "failed" ? () => {} : undefined}
        />
      </div>
    ))}
  </div>
);

/**
 * Waiting, with the invite to hand. This is the share moment: the room code
 * identifies the session and Copy invite puts the full link on the clipboard.
 *
 * The code is shown *and* the link is copied, rather than only the link,
 * because the two are read out over different channels — someone reads four
 * characters aloud on a call to confirm they joined the same room as the link
 * they were sent. That comparison is the out-of-band check, and it needs
 * something short enough to say.
 */
export const WaitingForPeer = () => (
  <SessionStrip
    state="waiting"
    room="KJ8X4M2Q7T9FQ"
    invite={INVITE}
    onCopyInvite={() => {}}
    onCancel={() => {}}
  />
);

/**
 * Given a roster, the strip lists peers instead of counting them (p2p-dkg
 * DESIGN §6 — "per-peer, not per-session").
 *
 * "Connected · 3 peers" reads identically whether every link is healthy or one
 * of them died, and in a mesh ceremony that difference decides whether the run
 * can proceed. So the roster is per-row, and `authenticated` is drawn per-row
 * too: an unauthenticated peer is *connected* — the DTLS channel is up — but
 * nobody has proven who is on the other end of it, and a threshold ceremony
 * must not treat those two as the same thing.
 */
export const MeshRoster = () => (
  <SessionStrip
    state="connected"
    room="KJ8X4M2Q7T9FQ"
    connected={3}
    peers={[
      { id: "@ada", fingerprint: "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388", state: "connected", authenticated: true, via: "host" },
      { id: "@grace", fingerprint: "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43", state: "connected", authenticated: true, via: "srflx" },
      { id: "peer-4tq9", state: "connecting", authenticated: false },
    ]}
    onCancel={() => {}}
  />
);

/**
 * The mesh state worth designing for: one link down while the rest hold. The
 * session is still `connected` — most of the room is fine — but a ceremony
 * needing every participant cannot run, and the failed row is the only thing
 * on screen that says so.
 */
export const PeerLost = () => (
  <SessionStrip
    state="connected"
    room="KJ8X4M2Q7T9FQ"
    connected={2}
    peers={[
      { id: "@ada", fingerprint: "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388", state: "connected", authenticated: true, via: "host" },
      { id: "@grace", fingerprint: "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43", state: "connected", authenticated: true, via: "relay" },
      { id: "@lin", fingerprint: "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029", state: "failed", authenticated: true },
    ]}
    onRestartIce={() => {}}
    onCancel={() => {}}
  />
);
