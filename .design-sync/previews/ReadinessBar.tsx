import { ReadinessBar } from "basilisk-portal";

/*
 * What stands between the notebook and a run. Each blocker names the thing
 * that is missing and carries the control that fixes it, so the bar is a
 * worklist rather than an error message.
 *
 * The pairing is the whole design: a blocker without an action is a complaint,
 * and every entry here has an `action` label and an `onAction`. That is also
 * why the fixtures below never state a problem the reader cannot act on.
 */

const frame = { maxWidth: 560 };

/**
 * The common case — one thing missing. A session that needs a peer is the
 * blocker a shared notebook hits most, and the action is the invite.
 */
export const Default = () => (
  <div style={frame}>
    <ReadinessBar
      blockers={[
        {
          id: "no-peer",
          label: "No peer has joined this session",
          action: "Copy invite",
          onAction: () => {},
        },
      ]}
    />
  </div>
);

/**
 * Several at once, in the order they must be cleared.
 *
 * Locked vault first because nothing else can proceed through it; the
 * unassigned cell last because it is a choice rather than an obstruction.
 * Ordering matters here — a list that puts the cheapest fix first teaches
 * people to clear the cheap one and re-read the same bar.
 */
export const SeveralBlockers = () => (
  <div style={frame}>
    <ReadinessBar
      blockers={[
        {
          id: "vault-locked",
          label: "Vault is locked — $ada cannot be read",
          action: "Unlock",
          onAction: () => {},
        },
        {
          id: "peer-unverified",
          label: "@lin has not been verified against a published key",
          action: "Compare fingerprint",
          onAction: () => {},
        },
        {
          id: "cell-unassigned",
          label: "Cell 4 needs two owners' secrets and can run nowhere",
          action: "Assign",
          onAction: () => {},
        },
      ]}
    />
  </div>
);

/**
 * Nothing blocking. Kept as a cell because the empty state is reachable and
 * the component decides for itself what to draw — a design that assumes this
 * bar always has content will lay out around a row that is not there.
 */
export const Ready = () => (
  <div style={frame}>
    <ReadinessBar blockers={[]} />
  </div>
);
