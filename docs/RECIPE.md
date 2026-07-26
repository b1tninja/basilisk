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
random 32 | sss threshold=2 shares=3 | blip39 | foreach
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
- Bare `out kp` / `in kp` is shorthand for `@kp` (canonical form always uses `@`).
- Prefer **positional** args: `out @public`, `export pkcs8`, `genkey ec/p256`.
- Empty `tee` is invalid; use `peek` for a side inspect snapshot.
- List marker is only `-`. Leading tabs are errors.
- File paths (`./x.pem`, quoted paths, `file:…`) are reserved — not supported yet.
- Comments: full-line `# …` (kept inside the current chain).

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
| Named | `sss threshold=2 shares=3` | `ident=value` |
| Flag | `blip39 -d`, `pem -d` | Sets the param with `flag: "-d"` to `true` |

Canonical serialize omits redundant `name=` for the primary positional when the
value is not the registry default (slot names always serialize as `@label`).

Aliases resolve at parse time (`paste` → `input`, `gpg` → `encrypt`, `from` → `in`, …).

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
  - encrypt gpg

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
name         = ident ;
arg          = flag | binding | positional ;
flag         = "-" , ident ;
binding      = ident , "=" , value ;
positional   = value | slot_ref ;
value        = string | number | bare_value | "true" | "false" ;
bare_value   = letter , { letter | digit | "_" | "-" | "/" | "." } ;

slot_ref     = "@" , ident | ident | number ;
(* bare ident ≡ @ident for out/in slot names; number = 1-based slot index for in *)

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

## See also

- [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) — algorithms, toolbox inventory, example recipes
- `web/src/lib/toolkit/registry.js` — step docs / params (Reference panel)
- `web/src/lib/toolkit/recipe.js` — validate / serialize / presets
