# Basilisk toolkit recipe language

Normative syntax for Crypto Toolkit pipelines. The parser is a hand-rolled
recursive descent matching the EBNF below (PEG-style ordered choice).

Implementation: `web/src/lib/toolkit/recipe-parse.js` (parse),
`recipe.js` (validate / serialize / presets), `engine.js` (run).

## Quick examples

```text
# Linear stem
genkey ec/p256 | export pkcs8 | pem | out @private

# Mid-stem fork (tee): branches run on a clone; stem continues
genkey ec/p256 | tee
  - .private | inspect
  - .public | export spki | pem | out @public
| export pkcs8 | pem | out @private

# Multi-chain: blank line starts a new pipeline; in loads a prior out slot
genkey ec/p256 | out @kp

in @kp | .public | export spki | pem | out @public
in @kp | export pkcs8 | pem | out @private

# Shares collection → foreach body
random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share

# Dict view + per-item projection
… | blip39 | foreach .items
  - .value | out @share

# One share (1-based index)
… | blip39 | [1] | out @share-1
```

## Design rules

- A recipe is one or more **chains** separated by blank lines.
- Within a chain: flat `|` stem; a newline between stem lines is the same as `|`.
- Blocks: `tee` / `foreach` take a **body** (braces `{ … }` or indented `-` lines).
- Member / dict projection uses **selectors** (`.private`, `.items`, …).
- Slots: `out @label` registers a live pipeline value; `in @label` / `in 1` loads it.
- Named slot args pass live values into ops: `aes-gcm key=@cek` (stem stays the payload).
- Namespaced product ops use dots (`gpg.encrypt`, `sss.combine`, `webauthn.prf`); cipher ops use hyphens (`aes-gcm`). OpenSSL-sized (`aes-256-gcm`), JCE (`AES/GCM/NoPadding`), and sugar `encrypt`/`decrypt` + transform parse to the same canonical hyphen name.
- Bare `out kp` / `in kp` / `key=cek` is shorthand for `@` form (canonical always uses `@`).
- Prefer **positional** args: `out @public`, `export pkcs8`, `genkey ec/p256`.
- Casts: `as master` / `as scalar` / `as opaque` retag bytes only (not import).
- Empty `tee` is invalid; use `peek` for a side inspect snapshot.
- List marker is only `-`. Leading tabs are errors.
- File paths (`./x.pem`, quoted paths, `file:…`) are reserved — not supported yet.
- Comments: full-line `# …` (kept inside the current chain).
- Ops-drawer **shelves** and **conjugate rows** (encode | `-d`, sign | verify) are UI only — they do not change recipe tokens or grammar.

## Chains

| Rule | Behavior |
|------|----------|
| Separator | One or more blank lines |
| Order | Chains run top-to-bottom |
| Slots | Shared registry across the whole recipe |
| First chain | Also exposed as `ast.steps` for older callers |

Use **tee** when you need a mid-stem projection fork (public beside private export).
Use **blank-line chains + `in`** when a later pipeline should reuse an earlier `out`.

## Arguments

Each apply stage is `name` then zero or more args:

| Form | Example | Notes |
|------|---------|-------|
| Positional | `genkey ec/p256`, `out @public` | Binds the step’s `positional` param |
| Named | `sss.split threshold=2 shares=3` | `ident=value` |
| Flag | `blip39 -d`, `pem -d` | Sets the param with `flag: "-d"` to `true` |

Canonical serialize omits redundant `name=` for the primary positional when the
value is not the registry default (slot names always serialize as `@label`).

Aliases resolve at parse time (`paste` → `input`, `from` → `in`, …). Basilisk-legacy step tokens (`encrypt`, `aesgcm`, `wa-prf`, `recover`, …) do **not** parse — use `migrateRecipe()` / **Upgrade recipe**.

## Slots (`@label`)

`out` emits a result tile **and** registers a cloned live pipeline value.
`in` / `from` sources that value (typed keypair / bytes / shares / …) — not
re-parsed artifact text.

| Form | Meaning |
|------|---------|
| `out @kp` | Emit + register memory slot `kp` (+ next 1-based index) |
| `out kp` | Same (rewrites to `out @kp`) |
| `in @kp` / `from @kp` | Load slot `kp` |
| `in 1` | Load first registered slot by registration order |
| `./x.pem`, `"…"`, `file:…` | Reserved for future file I/O — rejected today |

Rules:

- Duplicate `@label` in one recipe → error.
- Forward / missing refs → error.
- Only explicit `out` registers slots (dangling auto-emit does not).
- Default stem when omitted: `@output`.

## Named slot args

Secondary live values (keys, peers) are passed as **slot-typed named args**,
not on the stem. The stem stays the payload.

```text
genkey aes/256 | out @cek

input | utf8 | aes-gcm key=@cek | out @ct

in @ct | aes-gcm -d key=@cek | utf8 | out @plain
```

| Op | Slot args |
|----|-----------|
| `aes-gcm` / `aes-cbc` / `aes-ctr` / `rsa-oaep` / `rsa-pkcs1` / `sign` / `unwrap` | `key=@…` |
| `verify` | `key=@…` `signature=@…` (or bare base64url for `signature=`) |
| `gpg.verify` | `signature=@…` (detached; cleartext uses stem) |
| `ecdh` | `private=@…` `peer=@…` |
| `wrap` | `key=@…` (wrapping) `target=@…` (CEK) |

Rules:

- Refs use the same `@label` sugar as `out` / `in` (bare `key=cek` → `key=@cek`).
- Forward / missing refs error at validate (same as `in`).
- When required slot args are present, the key/peer/wrap/signature panels are not required.
- Panels remain as fallback when slot args are omitted.
- Do not embed JWK JSON secrets in the recipe — only `@` refs (or panels).

```text
input | utf8 | out @msg
genkey ed25519 | out @kp

in @msg | sign key=@kp | base64url | out @sig
in @msg | verify key=@kp signature=@sig | out @ok
```

### Namespaces and cipher spellings

| Kind | Canonical | Also parses | Serialize |
|------|-----------|-------------|-----------|
| OpenPGP | `gpg.genkey` / `gpg.inspect` / `gpg.encrypt` / `gpg.decrypt` / `gpg.sign` / `gpg.verify` / `gpg.symencrypt` / `gpg.symdecrypt` | `gpg.encrypt -s` sign+encrypt | dotted |
| WebCrypto AEAD/cipher/RSA | `aes-gcm`, `aes-cbc`, `aes-ctr`, `rsa-oaep`, `rsa-pkcs1` | `aes-256-gcm`, `AES/GCM/NoPadding`, `encrypt AES/GCM/NoPadding`, `decrypt …` | hyphen |
| SSS | `sss.split` / `sss.combine` | — | dotted |
| WebAuthn | `webauthn.caps` … `webauthn.mds` | — | dotted |
| WebCrypto sign | `sign` / `verify` | `hmac`, `hmac.verify` | bare (SubtleCrypto) |
| Key wrap | `wrap` / `unwrap` | `mode=aes-kw` (default), `aes-gcm`, `aes-cbc`, `aes-ctr`, `rsa-oaep` | hyphen modes |

Bare `encrypt` / `decrypt` are **WebCrypto sugar** (not OpenPGP): they require a cipher transform and rewrite to the concrete op on parse.

```text
input | utf8 | encrypt AES/GCM/NoPadding key=@cek | out @ct
in @ct | decrypt aes-gcm key=@cek | utf8 | out @plain
# serialize → aes-gcm / aes-gcm -d
```

**Builder UX:** the ops drawer’s **Pick a cipher** strip (Encrypt | Decrypt) is a meta entry — it opens a subset of AEAD/cipher/RSA ops and inserts a **concrete** card (`aes-gcm`, …) with decode pre-filled for Decrypt. There is never a builder block named `encrypt` / `decrypt`. Recipe-text sugar and the picker land on the same AST.

OpenPGP signatures are **`gpg.sign` / `gpg.verify` only** — never bare `sign`/`verify`. OpenPGP encrypt stays **`gpg.encrypt`** (`-s` / `sign=true` = sign-then-encrypt with the vault private key). `gpg.genkey` emits Curve25519 keys; `gpg.inspect` summarizes armor without decrypting.

```text
input | utf8 | gpg.sign | out @signed
in @signed | gpg.verify | out @ok

input | utf8 | out @msg
in @msg | gpg.sign format=detached | out @sig
in @msg | gpg.verify signature=@sig | out @ok

input | gpg.encrypt -s
gpg.genkey email="you@example.com" | out @priv
input | gpg.inspect format=packets | out @report
passphrase mode=char length=20 | out @pass
random 10 | base32 | out @id
```

WebCrypto `verify` is fail-loud by default; `verify -q` / `soft=true` emits text `verified` or `invalid` (setup errors still throw). Same soft mode on `gpg.verify`. Prefer fail-loud for auth decisions. `aes-cbc` / `aes-ctr` are **unauthenticated** — prefer `aes-gcm` for new work.

RSA sign keys: `genkey rsa/2048 padding=pss` (default) or `padding=pkcs1` (discouraged RSASSA-PKCS1-v1_5); optional `hash=sha-256|384|512`. Content encrypt stays `rsa-oaep` (optional `label=`); key wrap uses `wrap mode=rsa-oaep`. SubtleCrypto knobs: `aes-gcm tagLength=`, `aes-ctr length=` (counter bits; IV packing stays 16 bytes), `sign`/`verify` `saltLength=` (RSA-PSS) and `hash=` (ECDSA override; `auto` = curve default). Symmetric sizes include `aes/192` and `hmac/sha384`.

`ecdh` defaults `bits=0` (curve-aware: P-256/X25519 → 256, P-384 → 384, P-521 → 528) and accepts `as=aes/256` etc. like `hkdf`.

### Discouraged algorithms

Supported for interop, but compile warns and result tiles are tagged `legacy` / `discouraged`:

| Op | Prefer instead |
|----|----------------|
| `digest sha-1` | `digest` / `sha-256` |
| `rsa-pkcs1` (RSAES-PKCS1-v1_5; pure-JS) | `rsa-oaep` |
| `genkey`/`import` `padding=pkcs1` (RSASSA-PKCS1-v1_5) | `padding=pss` |

On `genkey`/`import` for ed25519, x25519, aes/*, hmac/*: non-`auto` `usage=` is ignored and emits a compile warning.

## Casts (`as`)

`as` **retags** refined type only — no crypto conversion. Not an import.

```text
random 16 | digest | as master | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share
```

| Form | Meaning |
|------|---------|
| `as master` | Tag as `bytes/master` (must be 16 or 32 bytes) |
| `as scalar` | Tag as `bytes/scalar` |
| `as opaque` | Tag as `bytes/opaque` |

Never: `as keypair` / `as jwk` — use `import` / `export`.

Homonym: the stage `as master` is distinct from KDF/ECDH params `hkdf … as=aes/256` / `pbkdf2 … as=aes/256` / `ecdh … as=aes/256` (`deriveKey` → keypair when not `bytes`).

## Selectors

Bare selector stages become `select` under the hood; under `tee` / `foreach`
they also appear as branch prefixes (`- .public | …`).

| Selector | Meaning |
|----------|---------|
| `.private` / `.public` | Keypair half (`.priv` / `.pub` / `.secret` accepted) |
| `.keys` / `.values` / `.items` | Dict views of a shares map |
| `.key` / `.value` | Fields of one `{ key, value }` item |
| `[n]` / `[n:m]` | Share index / slice (same as `at`) |

## Blocks

### `tee`

Side pipelines on a **clone** (or projected member). Stem value is unchanged.

```text
genkey ec/p256 | tee
  - .public | export spki | pem | out @public
| export pkcs8 | pem | out @private
```

Brace form is equivalent: `tee { - .public | … }`.

### `foreach`

Map a body over a shares collection. Optional selector before the body:

```text
… | blip39 | foreach
  - gpg.encrypt

… | blip39 | foreach .items
  - .value | out @share
```

Nested `tee` / `foreach` inside a body is rejected in v1.

### `peek`

Side inspect snapshot; stem unchanged. Prefer this over an empty `tee`.

```text
genkey ec/p256 | peek keypair | export pkcs8 | pem | out @private
```

## Keywords

| Keyword | Role |
|---------|------|
| `tee` | Side pipelines on clone/projection; stem unchanged. **Requires** a body. |
| `foreach` | Map body over a sequence. Optional `.items` / `.values` / `.keys`. |
| `peek` | Side inspect snapshot; stem unchanged. |
| `at` | Same as `[n]` / `[n:m]` — share index or slice. |
| `in` / `from` | Source: load a prior `out` slot by `@label` or 1-based index. |
| `out` | Emit a tile, register a slot, pass the value through. |
| `as` | Retag refined bytes kind (`master` / `scalar` / `opaque`). |
| `input` | Free-form text at run time (not a slot). Aliases: `paste`, `cat`. |
| `select` | Internal name for a bare selector stage (usually written as `.public`). |

## EBNF

```ebnf
(* Lexical *)
letter       = "A" … "Z" | "a" … "z" ;
digit        = "0" … "9" ;
ident        = letter , { letter | digit | "_" | "-" } ;
number       = digit , { digit } ;
string       = '"' , { char - '"' } , '"' | "'" , { char - "'" } , "'" ;
ws           = " " ;
nl           = "\n" ;
comment      = "#" , { char - "\n" } ;
space        = { ws } ;

(* Recipe = chains separated by blank lines *)
recipe       = chain , { blank_line , { blank_line } , chain } ;
blank_line   = space , nl ;
chain        = { comment_line | pipeline_line } ;
comment_line = space , comment , nl ;
pipeline_line = space , [ "|" ] , space , pipeline , space , nl ;

pipeline     = stage , { space , "|" , space , stage } ;
stage        = block | apply | selector ;

apply        = name , { space , arg } ;
name         = ident | dotted_name | hyphen_name | jce_name ;
dotted_name  = ident , "." , ident , { "." , ident } ;
hyphen_name  = ident , "-" , ident , { "-" , ident } ;
jce_name     = letter , { letter | digit | "/" | "-" } ; (* allowlisted JCE transforms only *)
arg          = flag | binding | positional ;
flag         = "-" , ident ;
binding      = ident , "=" , value ;
positional   = value | slot_ref ;
value        = string | number | bare_value | slot_ref | "true" | "false" ;
bare_value   = letter , { letter | digit | "_" | "-" | "/" | "." } ;

slot_ref     = "@" , ident | ident | number ;
(* bare ident ≡ @ident for out/in names and type=slot params; number = 1-based index for in *)

selector     = "." , ident
             | "[" , number , [ ":" , number ] , "]" ;

block        = tee_block | foreach_block ;
tee_block    = "tee" , space , body ;
foreach_block = "foreach" , [ space , selector ] , space , body ;

body         = brace_body | indent_body ;
brace_body   = "{" , space , [ nl ] , { branch_line | blank_line | comment_line } , space , "}" ;
indent_body  = nl , { branch_line | blank_line | comment_line } ;

branch_line  = indent , "-" , space , branch , space , nl ;
indent       = "  " , { "  " } ;
branch       = [ selector , space , "|" , space ] , pipeline ;
```

Parser alternatives are **ordered** (first match wins).

## Semantics

```text
chains       blank-line separated; run in order; share a slot registry
pipeline     left-to-right within a chain
out @x       emit tile + register cloned pipeline value as slot x
in @x / in N load cloned slot (typed); must refer to an earlier out
key=@x       named slot arg — resolve live value into the op (not the stem)
as kind      retag bytes refined type (allowlisted)
tee body     side branches on projection/clone; stem unchanged
foreach      over values (default) or .items / .keys / .values
peek         side inspect; stem unchanged
```

Runtime input panels (`shares`, `input`, GPG recipients, envelopes, bound JWKs)
are never stored in the recipe text.

## Serialization

Paste / blur canonicalize via `canonicalizeRecipe`:

- lowercases step names and expands aliases
- rewrites bare slot idents to `@label`
- `from` → `in`
- joins chains with a blank line
- formats `tee` / `foreach` bodies with indented `-` lines

## Migration notes

| Old habit | Current form |
|-----------|--------------|
| Flat `foreach \| out` | `foreach` with a body: `- out @share` |
| Trailing `merge` / `collect` | Omit — body closes by dedent or `}` |
| Side-export / mid-stem fork | `tee` with `- .public \| …` (or multi-chain `out @kp` + `in @kp`) |
| Side inspect without a body | `peek @label` |
| `encrypt gpg` / `gpg` / `decrypt gpg` | `gpg.encrypt` / `gpg.decrypt` (bare `encrypt`/`decrypt` are WebCrypto sugar now) |
| `symencrypt` / `symdecrypt` | `gpg.symencrypt` / `gpg.symdecrypt` |
| `aesgcm` / `aescbc` / `aesctr` | `aes-gcm` / `aes-cbc` / `aes-ctr` |
| `rsaoaep` / `rsapkcs1` | `rsa-oaep` / `rsa-pkcs1` |
| `sss` / `recover` | `sss.split` / `sss.combine` |
| `wa-*` | `webauthn.*` |

Use `migrateRecipe(text)` (or the toolkit **Upgrade recipe** button) for a one-shot rewrite. The parser does not accept legacy tokens.

## See also

- [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) — algorithms, toolbox inventory, example recipes
- `web/src/lib/toolkit/registry.js` — step docs / params (Reference panel)
- `web/src/lib/toolkit/recipe.js` — validate / serialize / presets
