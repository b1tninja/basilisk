import { Button, GateBanner, GateFact } from "basilisk-portal";

/*
 * The two real shapes, transcribed from the two components built on this shell:
 * `ApprovalBanner` (a key use, mid-run) and `ConsequenceBanner` (an outward
 * action, on a tile). Facts, digests, fingerprints and key ids below are real
 * values from this repo's own runs and fixtures.
 *
 * `facts` takes `<dt>`/`<dd>` pairs, and `GateFact` is how you make them — it
 * is a fragment rather than a wrapper, because the pairs have to stay direct
 * children of the banner's grid or the 68px term column stops meaning anything.
 */

/**
 * The approval moment: a running recipe reached a step that wants a key.
 *
 * Every line is data the engine held when the request was made — nothing
 * inferred, nothing decorative. That restraint is the design: this banner is
 * the only thing standing between "agent" and "rubber stamp", so anything on
 * it that a user learns to skim is a liability.
 *
 * The three outcomes are deliberately not three equal buttons. Deny is ghost
 * weight, "Approve once" is visually primary, and the session grant is a
 * *checkbox modifying it* — so the strong default stays the easy path. The
 * batch offer appears only here, after a real payload and the loop's true
 * count have been shown, so a recipe cannot pre-authorize itself.
 */
export const Approval = () => (
  <GateBanner
    label="ssh.sign wants to use a key"
    heading={
      <>
        <code>ssh.sign</code> wants to use a key
      </>
    }
    meta="request 2 of 7 this run"
    facts={
      <>
        <GateFact term="Step" detailClassName="break-all font-mono">
          cell 3 · ssh.sign key=@release namespace=git
        </GateFact>
        <GateFact term="Key">
          <span className="key-kind-badge" data-key-kind="ssh">
            SSH
          </span>
          <span>release signing</span>
          <span style={{ marginLeft: 6, color: "var(--muted-foreground)" }}>device-bound</span>
          <div className="break-all font-mono" style={{ fontSize: 10, color: "var(--muted-foreground)" }}>
            SHA256:BV9AB0OE5ffriBtNWFcPq6qLkdtnnn2LXlERMTNNuGc
          </div>
        </GateFact>
        <GateFact term="Payload">
          <span className="font-mono">
            1284 bytes · sha256 02f92eb042908 5e1…
          </span>
        </GateFact>
        <GateFact term="Namespace">
          <code>git</code>
          <span style={{ marginLeft: 6, color: "var(--muted-foreground)" }}>
            what a verifier must ask for — a <code>git</code> signature cannot be
            replayed under another namespace
          </span>
        </GateFact>
      </>
    }
    actions={
      <>
        <Button size="sm" variant="ghost">
          Deny
        </Button>
        <Button size="sm" variant="secondary">
          Approve once
        </Button>
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 10.5,
            color: "var(--muted-foreground)",
          }}
        >
          <input type="checkbox" readOnly />
          for this session (5 min)
        </label>
        <Button size="sm" variant="ghost">
          Approve the remaining 5
        </Button>
      </>
    }
  />
);

/**
 * The same banner once the session checkbox is ticked. The footnote is the
 * grant spelled out in the sentence a user would have to write themselves to
 * understand what they just agreed to — and it appears only after the choice
 * widens the consequence, never as standing advice.
 */
export const ApprovalWithSessionGrant = () => (
  <GateBanner
    label="agent.decrypt wants to use a key"
    heading={
      <>
        <code>agent.decrypt</code> wants to use a key
      </>
    }
    meta="request 1 this run"
    facts={
      <>
        <GateFact term="Step" detailClassName="break-all font-mono">
          cell 1 · agent.decrypt key=@ada
        </GateFact>
        <GateFact term="Key">
          <span className="key-kind-badge" data-key-kind="pgp">
            PGP
          </span>
          <span>Ada Lovelace</span>
          <span style={{ marginLeft: 6, color: "var(--muted-foreground)" }}>passphrase</span>
          <div className="break-all font-mono" style={{ fontSize: 10, color: "var(--muted-foreground)" }}>
            EF15 CD3F 7594 7843 71E8 2C0A 9049 08A0 F0EC F0AB
          </div>
        </GateFact>
        <GateFact term="Ciphertext">
          <span className="font-mono">597 bytes · sha256 c9073d1d04486…</span>
          <span style={{ marginLeft: 6, color: "var(--muted-foreground)" }}>
            ciphertext — digest only
          </span>
        </GateFact>
      </>
    }
    actions={
      <>
        <Button size="sm" variant="ghost">
          Deny
        </Button>
        <Button size="sm" variant="secondary">
          Approve once
        </Button>
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 10.5,
            color: "var(--muted-foreground)",
          }}
        >
          <input type="checkbox" defaultChecked readOnly />
          for this session (5 min)
        </label>
      </>
    }
    footnote={
      <p style={{ marginTop: 6, fontSize: 10, color: "var(--warn)" }}>
        While this lasts, recipes in this notebook can decrypt with this key
        without asking. It expires in 5 minutes, and the Keyring row counts every
        use.
      </p>
    }
  />
);

/**
 * The consequence confirmation, on a tile, under the action the user just
 * clicked. Same shell, and the sameness carries the argument.
 *
 * Three things are visibly absent compared with the approval above, and the
 * absences *are* the design: no session grant, no batch offer, no request
 * counter. There is no defensible "don't ask again" for publishing — each
 * publish is its own irreversible act, and a five-minute window in which a tile
 * publishes without asking is a bug wearing a checkbox. Because everything else
 * is identical, the eye lands where the checkbox was and finds nothing there.
 *
 * Neither button is `--warn`. Amber marks the decision point: on a tile that is
 * the outward button, and here it is the banner itself — the buttons are its
 * answer. `onEscape` is wired, which the approval banner deliberately does not
 * do; this one appeared because the user clicked, so cancelling with a key is
 * fair. It is opt-in for exactly that reason.
 */
export const Consequence = () => (
  <GateBanner
    label="Publish this key to the keyserver"
    heading="Publish this key to the keyserver"
    onEscape={() => {}}
    facts={
      <>
        <GateFact term="Key">
          <span>Ada Lovelace &lt;ada.lovelace@example.org&gt;</span>
          <div className="break-all font-mono" style={{ fontSize: 10, color: "var(--muted-foreground)" }}>
            EF15 CD3F 7594 7843 71E8 2C0A 9049 08A0 F0EC F0AB
          </div>
        </GateFact>
        <GateFact term="Server" detailClassName="break-all font-mono">
          keys.openpgp.org
        </GateFact>
        <GateFact term="Effect">
          <span>Public and permanent</span>
          <div style={{ fontSize: 10, color: "var(--muted-foreground)" }}>
            a keyserver has no delete — a published key can be revoked, never
            withdrawn
          </div>
        </GateFact>
      </>
    }
    actions={
      <>
        <Button size="sm" variant="ghost">
          Cancel
        </Button>
        <Button size="sm" variant="secondary">
          Publish
        </Button>
      </>
    }
  />
);

/**
 * The failure state. §33f: the thrown message verbatim, never "something went
 * wrong" — and the action stays live, because a failed publish is retryable and
 * swallowing the message is the one outcome worse than the failure itself.
 */
export const ConsequenceFailed = () => (
  <GateBanner
    label="Replace the key in this keyring slot"
    heading="Replace the key in this keyring slot"
    onEscape={() => {}}
    facts={
      <>
        <GateFact term="Slot" detailClassName="font-mono">
          @release
        </GateFact>
        <GateFact term="Replacing">
          <span>release signing (ed25519)</span>
          <div className="break-all font-mono" style={{ fontSize: 10, color: "var(--muted-foreground)" }}>
            SHA256:BV9AB0OE5ffriBtNWFcPq6qLkdtnnn2LXlERMTNNuGc
          </div>
        </GateFact>
        <GateFact term="Effect">
          <span>The old key is not kept</span>
        </GateFact>
      </>
    }
    actions={
      <>
        <Button size="sm" variant="ghost">
          Cancel
        </Button>
        <Button size="sm" variant="secondary">
          Replace
        </Button>
      </>
    }
    footnote={
      <p style={{ marginTop: 6, fontSize: 10, color: "var(--error)" }}>
        Keyring is locked — unlock it in My Keys before replacing a slot.
      </p>
    }
  />
);
