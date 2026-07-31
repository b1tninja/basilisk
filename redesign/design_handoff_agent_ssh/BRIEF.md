# Agent + SSH capability brief

The vault already borrows gpg-agent's *name* (`agent.unlock`, `agent.pub`,
`agent.list`, `agent.save` in `web/src/lib/toolkit/agent-ops.js`). This brief
is about making it earn the name, and about SSH — encoding, signing, and an
actual agent socket. It is the feasibility ground truth for the UX design
pass; every claim below was checked against the repo on 2026-07-31.

## Feasibility, answered honestly

**Can Basilisk actually serve as a gpg-agent?** Not on gpg's wire. gpg talks
Assuan over a Unix socket at a path gpg controls, and a browser cannot bind a
socket at all. The CLI (`web/cli/`, Node, same engine) *could* bind one, but
Assuan is a large, picky protocol (PKSIGN/PKDECRYPT/KEYINFO plus the whole
pinentry dance), and gpg versions disagree about it. The recommendation is to
adopt gpg-agent's *architecture* rather than its protocol: a boundary that
keys never cross, where clients submit operations and receive results. That
is what the current ops fail to do — `agent.unlock` hands the private key
*into* the pipeline, which is precisely the thing an agent exists to prevent.

**Can Basilisk serve as an ssh-agent?** Yes, genuinely. The ssh-agent
protocol (draft-miller-ssh-agent) is small — a dozen message types over a
Unix socket (`$SSH_AUTH_SOCK`) or, on Windows, the named pipe
`\\.\pipe\openssh-ssh-agent`. Node can bind both. `ssh`, `git`, `scp` would
talk to `basilisk agent` exactly as they talk to OpenSSH's agent. Notably,
gpg-agent itself ships `enable-ssh-support` — being an ssh-agent *is* the
established way a PGP keystore serves SSH clients, so this is the lineage,
not a detour.

**Do we have the SSH primitives?** All of them. `genkey` already generates
`ed25519`, `ec/p256|p384|p521`, `rsa/2048..4096` — exactly the algorithm set
of `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-256/512`.
`keypair`/`export` move PKCS#8/SPKI/JWK. `@noble/curves` is already a
dependency. What is missing is pure encoding: the RFC 4253 wire blob, the
`openssh-key-v1` private container, `SHA256:` fingerprints, and the `sshsig`
signature format (`ssh-keygen -Y` — which is also how git signs commits with
SSH keys, a headline interop win).

One scoping note: encrypted `openssh-key-v1` private files use `bcrypt_pbkdf`,
which no Web API provides. Phase it: unencrypted export (with a visible
warning), vault-side protection as the story for keys at rest, `bcrypt_pbkdf`
later if demanded.

## The proposed capability set

**1. The agent boundary (the conceptual centerpiece).** New ops where the
private key never enters the pipeline:

- `agent.sign fpr=… [format=ssh|gpg|raw]` — payload in, signature out. The
  unlock happens inside the op, against the vault, with per-use approval.
- `agent.decrypt fpr=…` — ciphertext in, plaintext out, same boundary.
- `agent.unlock` remains for recipes that legitimately need key material
  (export, transformation), but the docs and UX should steer toward the
  boundary ops, and the sensitive-value treatment should make exporting feel
  like the exception it is.

**2. SSH encodings** (new `ssh` shelf, likely on the `encoding`/`webcrypto`
toolboxes — design decides placement):

- `ssh.encode` / `ssh.decode` — keypair/public ↔ OpenSSH public line
  (`ssh-ed25519 AAAA… comment`) and `openssh-key-v1` private PEM.
- `ssh.fingerprint` — `SHA256:…` base64, matching `ssh-keygen -lf`.
- `ssh.sign` / `ssh.verify` — `sshsig` format, `namespace=` param
  (`file`, `git`), interop-testable against `ssh-keygen -Y`.

**3. Vault becomes multi-kind.** Records gain `kind: "pgp" | "ssh" | "raw"`.
`agent.save` accepts `keypair` input, not just `openpgp-key`; id for non-PGP
keys is the SSH SHA256 fingerprint. `agent.list` reports kind. All existing
protection modes (device/passphrase/passkey) apply unchanged — the wrap layer
never cared what it wrapped.

**4. The socket server (CLI only).** `basilisk agent --ssh` binds the socket/
pipe and answers the protocol, backed by keys loaded from a recipe run or an
`agent.save`-style store. The browser cannot bind sockets; its role is
*approver* — a later phase can forward sign requests from the CLI agent to
the browser over the existing quorum mesh (the gpg-agent-forwarding
analogue), where the passkey-protected vault approves each use.

## What the design pass needs to answer

1. **The approval moment.** `agent.sign` is a pinentry moment: something
   asked to use your key. What does the per-use approval surface look like in
   the toolkit (and how does it degrade headlessly in the CLI)? This is the
   highest-stakes UX in the feature — it is the only thing standing between
   "agent" and "rubber stamp".
2. **My Keys with multiple kinds.** The vault UI is PGP-shaped today
   (fingerprints, UIDs, armor). How do SSH keys sit beside PGP keys —
   listing, badges, the public-line copy affordance, fingerprint display?
3. **Boundary legibility in the recipe language.** `agent.sign` vs
   `agent.unlock | gpg.sign` produce similar results with opposite security
   properties. How do the shelf, the tool cards, and the pipeline view make
   the boundary visible — glyphs, framing, the sensitive-value treatment?
4. **Agent status.** When the CLI agent is running (or the mesh-forwarding
   phase lands), where does "agent: 3 keys loaded, last used 2m ago" live —
   TopBar, a drawer header, the session panel?
5. **Op ergonomics.** Names, params, defaults for the `ssh.*` family;
   where the shelf puts them; glyphs (`ssh` key shape, terminal, knot?).

## Constraints the designs must respect

- Strict CSP: no inline styles, closed vocabularies as data attributes,
  continuous values through `lib/css-vars.js`. See `docs/THREAT-MODEL.md`.
- The registry (`web/src/lib/toolkit/registry.js` STEPS) is the single
  source of truth; ops get `doc` strings with examples, types via
  `input`/`output`/`overloads`, and CAST applies (`webcrypto` suite covers
  the SSH math; the encodings should get verb-smoke coverage).
- CLI and browser run the same engine — every op that can be pure JS should
  be, so recipes run headlessly (`docs/CLI.md`; browser-only ops exit 4).
- Design-doc conventions: sections numbered like the existing §18–§25 so code
  comments can cite them.
