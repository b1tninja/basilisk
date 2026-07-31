# Handoff: Agent boundary + SSH

Design pass for the capability family in [BRIEF.md](./BRIEF.md): boundary
ops that use My Keys without exporting them (`agent.sign` /
`agent.decrypt`), the per-use approval moment, a multi-kind vault
(PGP + SSH + raw), the `ssh.*` encoding/signing family, and the agent
status story including the CLI socket agent. **Design only** — nothing
under `web/` was touched; implementation happens from these documents.

## Reading order

1. **[BRIEF.md](./BRIEF.md)** — feasibility ground truth. Binding on facts
   (what can be an agent, which primitives exist); the design doc answers
   its five questions.
2. **[AGENT-SSH-DESIGN.md](./AGENT-SSH-DESIGN.md)** — the decisions, §26–§31:
   - **§26** the boundary made visible: Boundary/Vault shelf split, the
     `data-key-exposed` underline that traces key material through a
     pipeline, `exposure: "exports-secret"` on tool cards, glyphs, and
     normative registry entries for `agent.sign` / `agent.decrypt`.
   - **§27** the approval moment: inline gate at the requesting cell,
     RunBar `waiting-approval` state, exact banner contents (step, key,
     payload digest + preview, namespace), once / per-run batch / session
     grant semantics, the foreach abuse analysis, passkey sequencing, and
     the CLI's `--approve` / `ssh-add -c`-style headless behavior.
   - **§28** multi-kind My Keys: kind-shaped ids (`SHA256:` base64 vs hex),
     one mixed list with kind badges, the public-line copy affordance,
     protection caveats (no passphrase mode for SSH at launch, stated),
     `agent.list` rendering.
   - **§29** the `ssh.*` family: five ops with full registry-style specs
     and doc strings, a new top-level `ssh` toolbox (order 6, `#39c5cf`,
     CAST rides the `webcrypto` suite), refined text types, glyph
     metaphors, deliberate omissions (bcrypt_pbkdf, md5, allowed_signers,
     certs) and the unencrypted-export warning copy.
   - **§30** status surface: Keyring tray header line (browser agent);
     the browser claims *nothing* about the CLI agent until the mesh
     phase, whose status channel is the quorum roster (`role: "agent"`).
   - **§31** DSL touches: serialization of `fpr=`, no recipe syntax for
     pre-granting approval (deliberate), run/pause semantics, exact error
     strings, no migration entries.
3. **[IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md)** — the build
   plan in dependency order with per-unit acceptance criteria. Everything
   is *not started*.
4. **[agent-ssh-reference.html](./agent-ssh-reference.html)** — static
   visual reference (open in a browser): approval banner states, the
   multi-kind key list, and the shelf presentation. It is a document, not
   app code — inline CSS there is fine and nothing in it is exempt from
   the design doc where the two disagree (the .md binds).

## Decided vs. open

**Decided** (forks argued in the doc): inline cell gate over a modal
(§27a); session grant as a checkbox with visible/revocable/counting state
over silent caching (§27c); per-run batch approval only after the first
real payload of a loop is shown (§27d); top-level `ssh` toolbox over
splitting the family across `encoding`/`webcrypto` (§29b); Keyring tray
over TopBar for status (§30a); CLI `run` consents via explicit
`--approve` flag rather than interactive replay or silent trust (§27f).

**Open / deferred**: `bcrypt_pbkdf` (encrypted openssh-key-v1, and with it
passphrase-mode vault protection for SSH keys); mesh forwarding of
approvals (§30d — designed, explicitly not scheduled); `allowed_signers`
principal matching; a richer `agent.list` widget beyond the row rendering
in §28c.

## Conventions

Sections are cited as `§26`–`§31` (this handoff's series). Citations of
the form "design v2 §21a" refer to the existing toolkit design document
series that code comments already use — the two series are distinct.
