# Basilisk CLI

Run toolkit recipes headlessly:

```
node web/cli/basilisk.js run recipe.txt
```

From inside `web/`, `npm run cli -- run recipe.txt` and (after `npm link`)
`basilisk run recipe.txt` are the same thing. Paths below are written from the
repo root.

Basilisk is a browser notebook, and this does not change that. The registry,
recipe language and engine (`web/src/lib/toolkit/`) are pure JS and Node ships
WebCrypto, so the CLI is **packaging, not a second engine** — it drives
`compileRecipe`, `createKernel` and `listSteps`, the same modules the toolkit
page drives. A recipe that runs here runs there, and vice versa, minus the ops
that genuinely need a browser (see [Browser-only ops](#browser-only-ops)).

Recipe syntax is unchanged: see [RECIPE.md](./RECIPE.md).

## Commands

| Command | Does |
|---------|------|
| `run <recipe>` | Compile, validate, execute; print artifacts |
| `check <recipe>` | Compile and validate only; non-zero exit if invalid |
| `list-ops` | Dump the op registry (generated from `listSteps()`) |

Exit codes: `0` ok · `1` usage · `2` invalid recipe · `3` runtime error ·
`4` browser-only op.

## `check`

Compile and validate without running anything — safe on a recipe full of ops
this host cannot execute, and the right thing to put in CI.

```bash
node web/cli/basilisk.js check recipe.txt
node web/cli/basilisk.js check recipe.txt --json
```

A valid recipe reports its cell count, any compile warnings, and the runtime
inputs a `run` would ask for:

```
ok — 2 cells
  runtime inputs needed: shares
```

An invalid one prints the same messages the toolkit's per-cell banner shows —
the validator's own strings, with the offending op named — and exits `2`:

```
recipe.txt: 1 error
  Unknown step "frobnicate". See the Reference panel for available steps.
```

`--json` emits `{ ok, errors, warnings, cells, inputNeeds }`.

## `run`

Each blank-line **chain** is a cell, and one kernel spans the whole file — so
`out @slot` in cell 1 is live in cell 3, exactly as in the notebook. Cells run
top to bottom.

```bash
node web/cli/basilisk.js run split-recover.txt --out-dir ./artifacts
```

with `split-recover.txt`:

```text
random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share

shares | blip39.decode | sss.combine | base64 | out @secret
```

The recover cell has no paste panel here and does not need one: it falls back
to the indexed share slots the split cell's `foreach` just registered — the
same cross-cell wiring the notebook uses.

Output is one block per artifact:

```
── 1. share (share 1)  (share-1.txt)  [sensitive role=share]
away manual carpet fitness aluminum garden stick ajar subject …
── 4. secret  (secret.txt)  [sensitive role=secret]
0G0HcNCpIAZHhoTKso2Ul+3RymgpbhqvutGsBIHVfEU=
```

| Option | Effect |
|--------|--------|
| `--out-dir <dir>` | Write each artifact to `<dir>/<filename>`, byte-exact |
| `--json` | Emit artifacts as JSON (label, filename, role, sensitive, mime, stepName, content) |
| `--quiet` | Print artifact headers only, not contents |

**Secrets go to stdout.** The notebook masks sensitive tiles until you ask to
reveal them; a CLI that refused to print what you asked for would be useless,
so `run` prints everything and tags it `[sensitive]`. Redirect to a file, or
use `--out-dir`, rather than leaving key material in your scrollback.

`--out-dir` writes contents byte-exact — no trailing newline is added, because
some artifacts are exact-byte crypto material.

## Input bindings

The notebook feeds `input` / `shares` / `gpg.decrypt` from paste panels. The
CLI assembles the same `RuntimeBindings` from flags and files.

| Flag | Feeds |
|------|-------|
| `--input <text>` | the `input` op |
| `--input-file <file>` | the `input` op, from a file |
| `--stdin` | the `input` op, from piped stdin |
| `--shares <file>` | the `shares` op — **one mnemonic per line** |
| `--ciphertext <file>` | `gpg.decrypt` and envelope ops |
| `--private-key <file>` | armored OpenPGP private key (the key panel's job) |
| `--passphrase-env <VAR>` | passphrase, read from an environment variable |

```bash
echo -n "hello world" | node web/cli/basilisk.js run hash.txt --stdin
node web/cli/basilisk.js run hash.txt --input "hello world"
```

where `hash.txt` is `input | utf8 | digest | encode hex | out @hash`. Both
print `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9`.

Recovering from shares held outside this session:

```bash
node web/cli/basilisk.js run recover.txt --shares ./shares.txt
```

`shares.txt` is one mnemonic per line; blank lines and `#` comments are
ignored. There is no cleverness about wrapped lines — a 33-word mnemonic
soft-wrapped by your terminal looks exactly like two shares to any heuristic,
and guessing wrong reports "Invalid share checksum", which sends you looking
at your crypto instead of your text file.

Decrypting an OpenPGP message:

```bash
BASILISK_PW=… node web/cli/basilisk.js run decrypt.txt \
  --ciphertext ./message.asc \
  --private-key ./secret.asc \
  --passphrase-env BASILISK_PW
```

with `decrypt.txt` being `gpg.decrypt | out @plain`.

### Why there is no `--passphrase`

A passphrase passed as a bare flag ends up in `~/.bash_history`, in `ps` output
readable by every user on the host, and in CI job logs. `--passphrase-env
<VAR>` reads it from the environment instead, where it is at least scoped to
the process:

```bash
read -rs BASILISK_PW
export BASILISK_PW
node web/cli/basilisk.js run decrypt.txt --ciphertext m.asc \
  --private-key k.asc --passphrase-env BASILISK_PW
```

Passing `--passphrase` is a usage error, not an undocumented alias.

`--passphrase-env` covers private-key unlock and the SSS envelope. It does
**not** feed `gpg.symencrypt` / `gpg.symdecrypt` `mode=passphrase`, whose
passphrase is a *recipe* parameter (`passphrase=@slot`) rather than a runtime
input — see RECIPE.md.

## Browser-only ops

Some ops need a browser surface Node does not have. They fail by name:

```
$ node web/cli/basilisk.js run rtc.txt
browser-only op: "rtc.certificate" (cell 2, step 1) needs WebRTC
(RTCPeerConnection), which this Node process does not provide. Run this recipe
in the Basilisk toolkit page instead.
```

Exit code `4`, and nothing else in the recipe runs.

Detection is derived from the code rather than a hand-maintained list of op
names, in two layers:

1. **Pre-flight, registry-derived.** A toolbox → capability map read off
   `getStep().toolbox`. `webrtc` and `agent` qualify because every op in them is
   browser-bound (main-thread WebRTC; the IndexedDB vault). An op added to
   either toolbox later is covered with no edit to the CLI. This runs before
   any crypto work, so a browser-only op in cell 4 does not leave cells 1–3
   half-executed.
2. **Dispatch interception.** Everything else is caught by running it and
   classifying the failure against a vocabulary of browser globals —
   `RTCPeerConnection`, `navigator`, `indexedDB`, `PublicKeyCredential` and
   friends. The set of *ops* this covers is never enumerated, so it cannot go
   stale. It is how `clipboard.write` and `webauthn.create` are caught.

The `webauthn` toolbox is deliberately **not** blanket-blocked: it also holds
pure parsers — `webauthn.attest` decodes pasted attestation bytes and works
fine headlessly — and refusing the whole toolbox would be a lie in the other
direction. Its ceremony ops are caught by layer 2, which is exact.

Probes are evaluated live, not cached, so a host that *does* provide a surface
(jsdom, Electron, a polyfill) is believed rather than second-guessed.

## `list-ops`

Generated from the registry — an op that stops existing stops being listed.

```bash
node web/cli/basilisk.js list-ops
node web/cli/basilisk.js list-ops --toolbox webrtc
node web/cli/basilisk.js list-ops --json
```

The column view shows `name`, `toolbox` and the first sentence of the registry
doc. `--json` carries the whole doc plus `input` / `output` types.

## Implementation notes

- `cli/basilisk.js` is the executable wrapper; `cli/main.js` holds the commands
  and exports `main(argv, io)`, which writes through the `CliIO` it is handed
  and *returns* an exit code instead of calling `process.exit` — that is what
  makes it testable in-process.
- `cli/raw-loader.js` registers Node ESM loader hooks for Vite's `?raw` text
  imports. Two library modules read wordlists that way (SLIP-0039, needed by
  the core `blip39` op, and the EFF list). Both ship verbatim so they can be
  checked against their publishers' SHA-256; converting them to `.js` string
  modules to appease Node would destroy that, so the CLI teaches Node to read a
  text file as a module instead.
- The CLI is not bundled: `vite.config.js` lists HTML entry points explicitly
  and `web/cli/` is not among them.
- Tests: `web/src/test/cli.test.js` and `web/src/test/cli-docs.test.js`. The
  examples on this page are executed by the latter, so doc drift fails the
  suite.
